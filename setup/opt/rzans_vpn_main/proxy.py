#!/usr/bin/env -S python3 -u
# -*- coding: utf-8 -*-

from __future__ import print_function
import socket, struct, subprocess, sys, time, argparse, threading, pathlib, shutil, json, signal
import yaml
from collections import deque
from ipaddress import IPv4Network, AddressValueError, NetmaskValueError
from dnslib import DNSRecord, RCODE, QTYPE, A
from dnslib.server import DNSServer, DNSHandler, BaseResolver, DNSLogger

SETTINGS_YAML = pathlib.Path("/opt/rzans_vpn_main/settings.yaml")
SETTINGS_BIN = "/opt/rzans_vpn_main/settings/settings.sh"
DEFAULT_FAKE_RANGE = "10.30.0.0/15"
CHAIN = "RZANS_VPN_MAIN-MAPPING"

def _read_yaml(path: pathlib.Path = SETTINGS_YAML) -> dict:
    """Прочитать settings.yaml (возвращает dict либо {})."""
    if not path.exists():
        return {}
    try:
        with path.open("r", encoding="utf-8") as fh:
            return yaml.safe_load(fh) or {}
    except yaml.YAMLError as e:
        print(f"ERROR: bad YAML in {path}: {e}", file=sys.stderr)
        return {}

def _as_bool(v):
    """Мягкое приведение YAML-скаляров к bool."""
    if isinstance(v, bool):
        return v
    if isinstance(v, int):
        return v != 0
    if isinstance(v, str):
        return v.strip().lower() in ("1", "true", "yes", "on", "enabled")
    return False

class PassthroughDNSHandler(DNSHandler):
    """
        Modify DNSHandler logic (get_reply method) to send directly to
        upstream DNS server rather then decoding/encoding packet and
        passing to Resolver (The request/response packets are still
        parsed and logged but this is not inline)
    """
    def get_reply(self,data):
        # Защитимся от битых запросов: если не распарсилось — молча дропаем
        try:
            request = DNSRecord.parse(data)
        except Exception:
            return b""
        self.log_request(request)
        # Берём первый upstream — DNSServer вызывает handler отдельно для TCP/UDP
        host,port = self.server.resolver.upstreams[0]
        t = getattr(self.server.resolver, "timeout", 5.0)
        try:
            if self.protocol == "tcp":
                data = struct.pack("!H",len(data)) + data
                response = send_tcp(data,host,port,timeout=t)
                response = response[2:]
            else:
                response = send_udp(data,host,port,timeout=t)
            reply = DNSRecord.parse(response)
            self.log_reply(reply)
            return response
        except (socket.timeout, OSError, socket.gaierror, Exception):
            r = request.reply()
            r.header.rcode = getattr(RCODE, "SERVFAIL")
            self.log_reply(r)
            return r.pack()

class ProxyResolver(BaseResolver):
    """
        Proxy resolver - passes all requests to upstream DNS server and
        returns response

        Note that the request/response will be each be decoded/re-encoded
        twice:

        a) Request packet received by DNSHandler and parsed into DNSRecord
        b) DNSRecord passed to ProxyResolver, serialised back into packet
           and sent to upstream DNS server
        c) Upstream DNS server returns response packet which is parsed into
           DNSRecord
        d) ProxyResolver returns DNSRecord to DNSHandler which re-serialises
           this into packet and returns to client

        In practice this is actually fairly useful for testing but for a
        'real' transparent proxy option the DNSHandler logic needs to be
        modified (see PassthroughDNSHandler)
    """
    def __init__(self, upstream_list, timeout, ip_range, cleanup_interval, cleanup_expiry, map_log=False, ttl_cap=300):
        # iptables бинарь (на случай альтернативных путей)
        self.iptables = shutil.which("iptables") or "iptables"
        self.iptables_save = shutil.which("iptables-save") or "iptables-save"
        # список upstream-ов вида [(host,port), ...] для простого fail-over
        self.upstreams = list(upstream_list)
        if not self.upstreams:
            raise SystemExit("ERROR: no upstreams provided (expecting kresd@2 from settings.sh)")
        # Preflight: убедимся, что цепочка для мэппинга уже создана (up.sh запускается раньше proxy)
        try:
            subprocess.run(
                [self.iptables, "-w", "-t", "nat", "-S", CHAIN],
                check=True, capture_output=True, text=True
            )
        except (subprocess.CalledProcessError, OSError):
            print(f"ERROR: iptables chain '{CHAIN}' not found. "
                  f"Run firewall first (e.g. up.sh --fw-mapping).", file=sys.stderr)
            sys.exit(2)
        self.map_log = bool(map_log)
        self.ttl_cap = int(ttl_cap) if ttl_cap is not None else 300
        self.timeout = float(timeout)

        # Пул фейковых IP
        try:
            self.ip_pool = deque([str(x) for x in IPv4Network(ip_range).hosts()])
        except (AddressValueError, NetmaskValueError, ValueError):
            print(f"ERROR: Bad ip-range '{ip_range}', fallback to {DEFAULT_FAKE_RANGE}", file=sys.stderr)
            self.ip_pool = deque([str(x) for x in IPv4Network(DEFAULT_FAKE_RANGE).hosts()])

        self.ip_map = {}
        # Восстановить существующие DNAT-маппинги из iptables-save -t nat
        current_time = time.time()
        try:
            saved = subprocess.run(
                [self.iptables_save, "-t", "nat"], check=True, capture_output=True, text=True
            ).stdout
        except (subprocess.CalledProcessError, OSError):
            saved = ""
        for line in saved.splitlines():
            # ищем строки вида: -A RZANS_VPN_MAIN-MAPPING -d <fake> ... -j DNAT --to-destination <real[:port]>
            if not line.startswith(f"-A {CHAIN} "):
                continue
            tokens = line.split()
            fake_ip, real_ip = None, None
            for i, tok in enumerate(tokens):
                if tok == "-d" and i + 1 < len(tokens):
                    fake_ip = tokens[i + 1].split("/")[0]
                if tok == "--to-destination" and i + 1 < len(tokens):
                    real_ip = tokens[i + 1].split(":")[0]
            if fake_ip and real_ip:
                ok = self.mapping_ip(real_ip, fake_ip, current_time, log_restore=self.map_log)
                if not ok:
                    # если мусор — лучше подчистить цепочку и уйти
                    subprocess.run([self.iptables, "-w", "-t", "nat", "-F", CHAIN], check=False)
                    sys.exit(1)
        self.cleanup_interval = cleanup_interval
        self.cleanup_expiry = cleanup_expiry
        self.lock = threading.Lock()
        # Start thread for cleanup fake IPs
        threading.Thread(target=self.cleanup_fake_ips_worker,daemon=True).start()

    def get_fake_ip(self,real_ip):
        with self.lock:
            entry = self.ip_map.get(real_ip)
            if entry:
                entry["last_access"] = time.time()
                return entry["fake_ip"]
            else:
                try:
                    fake_ip = self.ip_pool.popleft()
                except IndexError:
                    print("ERROR: no fake IP left", file=sys.stderr)
                    return None
                self.ip_map[real_ip] = {"fake_ip": fake_ip, "last_access": time.time()}
                # цепь создастся заранее up.sh, но вставка безопасна даже если она уже есть
                subprocess.run([
                    self.iptables, "-w", "-t", "nat",
                    "-A", CHAIN, "-d", fake_ip,
                    "-m", "comment", "--comment", f"map:{real_ip}",
                    "-j", "DNAT", "--to-destination", real_ip
                ], check=True)
                if self.map_log:
                    print(f"Mapping: {fake_ip} -> {real_ip}", file=sys.stderr)
                return fake_ip

    def mapping_ip(self,real_ip,fake_ip,last_access, log_restore=False):
        if self.ip_map.get(real_ip):
            print(f"ERROR: mapped: {real_ip}", file=sys.stderr)
            return False
        try:
            self.ip_pool.remove(fake_ip)
            self.ip_map[real_ip] = {"fake_ip": fake_ip, "last_access": last_access}
            if log_restore and self.map_log:
                print(f"Restore mapping: {fake_ip} -> {real_ip}", file=sys.stderr)
        except ValueError:
            print(f"ERROR: fake not in pool: {fake_ip}", file=sys.stderr)
            return False
        return True

    def cleanup_fake_ips_worker(self):
        while True:
            time.sleep(self.cleanup_interval)
            self.cleanup_fake_ips()

    def cleanup_fake_ips(self):
        with self.lock:
            current_time = time.time()
            cleanup_ips = []
            for key, entry in self.ip_map.items():
                if current_time - entry["last_access"] > self.cleanup_expiry:
                    cleanup_ips.append((key, entry["fake_ip"]))
            for real_ip,fake_ip in cleanup_ips:
                self.ip_pool.appendleft(fake_ip)
                del self.ip_map[real_ip]
                try:
                    subprocess.run([
                        self.iptables, "-w", "-t", "nat",
                        "-D", CHAIN,
                        "-d", fake_ip,
                        "-m", "comment", "--comment", f"map:{real_ip}",
                        "-j", "DNAT", "--to-destination", real_ip,
                    ], check=True)
                except subprocess.CalledProcessError:
                    pass
            if self.map_log:
                print(f"Cleanup: {len(cleanup_ips)} expired fake IPs", file=sys.stderr)

    def resolve(self,request,handler):
        try:
            proxy_r = None
            last_err = None
            for host,port in self.upstreams:
                try:
                    if handler.protocol == "udp":
                        proxy_r = request.send(host,port,timeout=self.timeout)
                    else:
                        proxy_r = request.send(host,port,tcp=True,timeout=self.timeout)
                    if proxy_r:
                        break
                except (socket.timeout, OSError, socket.gaierror) as e:
                    last_err = e
                    continue
            if proxy_r is None:
                raise last_err or socket.timeout()
            reply = DNSRecord.parse(proxy_r)
            # 1) ВСЕГДА переписываем A-записи в Answer: скрываем реальные IP
            for rr in reply.rr:
                if rr.rtype != QTYPE.A:
                    continue
                real_ip = str(rr.rdata)
                fake_ip = self.get_fake_ip(real_ip)
                if not fake_ip:
                    r = request.reply()
                    r.header.rcode = getattr(RCODE, "SERVFAIL")
                    return r
                rr.rdata = A(fake_ip)
                if self.ttl_cap and self.ttl_cap > 0:
                    try:
                        rr.ttl = min(int(getattr(rr, "ttl", self.ttl_cap)), self.ttl_cap)
                    except Exception:
                        rr.ttl = self.ttl_cap
            # В v4-only режиме избегаем утечек IPv6: удаляем AAAA из Answer всегда
            reply.rr = [rr for rr in reply.rr if rr.rtype != QTYPE.AAAA]

            # 2) Только для qtype=A — чистим Answer до {A,CNAME} и выравниваем имя
            if request.q.qtype == QTYPE.A:
                keep = []
                for rr in reply.rr:
                    if rr.rtype in (QTYPE.A, QTYPE.CNAME):
                        if rr.rtype == QTYPE.A:
                            rr.rname = request.q.qname
                        keep.append(rr)
                reply.rr = keep
            # Переписываем/зачищаем Additional ВСЕГДА: скрываем реальные A, сохраняем CNAME
            keep_ar = []
            for rr in list(getattr(reply, "ar", [])):
                if rr.rtype == QTYPE.A:
                    real_ip = str(rr.rdata)
                    fake_ip = self.get_fake_ip(real_ip)
                    if not fake_ip:
                        continue
                    rr.rdata = A(fake_ip)
                    if self.ttl_cap and self.ttl_cap > 0:
                        try:
                            rr.ttl = min(int(getattr(rr, "ttl", self.ttl_cap)), self.ttl_cap)
                        except Exception:
                            rr.ttl = self.ttl_cap
                    keep_ar.append(rr)
                elif rr.rtype == QTYPE.CNAME:
                    keep_ar.append(rr)
                elif rr.rtype == QTYPE.OPT:  # EDNS(0) — сохраняем
                    keep_ar.append(rr)
                # остальные типы в AR — отбрасываем, чтобы не утекали реальные IP (NS glue и пр.)
            reply.ar = keep_ar
            return reply
            #print(reply)
        except (socket.timeout, OSError, socket.gaierror, Exception):
            reply = request.reply()
            reply.header.rcode = getattr(RCODE,"SERVFAIL")
        return reply

def _open_sock(host, port, proto, timeout=None):
    # Принудительно IPv4 к апстримам (proxy используется в v4-only SPLIT-цепочке)
    infos = socket.getaddrinfo(host, port, socket.AF_INET, proto)
    af, st, pr, _, sa = infos[0]
    s = socket.socket(af, st, pr)
    if timeout is not None:
        s.settimeout(float(timeout))
    return s, sa

def send_tcp(data,host,port,timeout=None):
    """TCP DNS запрос (длина-префикс в начале)."""
    sock, sa = _open_sock(host, port, socket.SOCK_STREAM, timeout)
    sock.connect(sa)
    sock.sendall(data)
    # сначала гарантированно читаем 2-байтовый префикс длины
    header = b""
    while len(header) < 2:
        chunk = sock.recv(2 - len(header))
        if not chunk:
            break
        header += chunk
    if len(header) < 2:
        sock.close()
        return b""
    length = struct.unpack("!H", header)[0]
    # затем читаем payload указанной длины
    payload = b""
    while len(payload) < length:
        chunk = sock.recv(min(8192, length - len(payload)))
        if not chunk:
            break
        payload += chunk
    sock.close()
    return header + payload

def send_udp(data,host,port,timeout=None):
    """UDP DNS запрос."""
    sock, sa = _open_sock(host, port, socket.SOCK_DGRAM, timeout)
    sock.sendto(data, sa)
    response, _ = sock.recvfrom(8192)
    sock.close()
    return response

if __name__ == "__main__":
    p = argparse.ArgumentParser(description="DNS Proxy")
    p.add_argument("--port","-p",type=int,default=53,
                    metavar="<port>",
                    help="Local proxy port (default:53)")
    p.add_argument("--address","-a",default="127.0.0.5",
                    metavar="<address>",
                    help="Local proxy listen address (default:127.0.0.5)")
    # TCP по умолчанию включён; --no-tcp отключает
    p.add_argument("--no-tcp", dest="tcp", action="store_false",
                    help="Disable TCP listener (default: UDP+TCP)")
    p.set_defaults(tcp=True)
    p.add_argument("--timeout","-o",type=float,default=5,
                    metavar="<timeout>",
                    help="Upstream timeout (default: 5s)")
    p.add_argument("--passthrough",action="store_true",default=False,
                    help="Dont decode/re-encode request/response (default: off)")
    p.add_argument("--log",default="request,reply,truncated,error",
                    help="Log hooks to enable (default: +request,+reply,+truncated,+error,-recv,-send,-data)")
    p.add_argument("--log-prefix",action="store_true",default=False,
                    help="Log prefix (timestamp/handler/resolver) (default: False)")
    p.add_argument("--ip-range", default=None,
                   metavar="<ip/mask>",
                   help="Fake IP range (overrides vpn.map_dns from settings.yaml)")
    p.add_argument("--cleanup-interval","-c",type=int,default=3600,
                    metavar="<seconds>",
                    help="Seconds between fake IP cleanup runs (default: 3600)")
    p.add_argument("--cleanup-expiry","-e",type=int,default=7200,
                    metavar="<seconds>",
                    help="Seconds of inactivity before fake IP is removed (default: 7200)")
    p.add_argument("--map-log", action="store_true", default=False,
                   help="Verbose mapping logs to stderr (default: off)")
    p.add_argument("--ttl-cap", type=int, default=None,
                   help="Cap TTL for rewritten A-records (0 = leave as-is). If omitted, derive from settings.yaml (adguard_home.enable).")
    args = p.parse_args()
    # --- helpers: читать env из settings.sh (read-only JSON)
    def _read_env():
        try:
            out = subprocess.check_output([SETTINGS_BIN, "--print-env-proxy"], text=True, timeout=3)
            j = json.loads(out.strip() or "{}")
            # валидация порт/адресов минимальная
            host = str(j.get("PROXY_IP") or "127.0.0.5").strip()
            k2   = str(j.get("KRESD2_IP") or "127.0.0.2").strip()
            port = int(j.get("DNS_PORT") or 53)
            if port <= 0 or port > 65535: port = 53
            return host, k2, port
        except Exception:
            return "127.0.0.5", "127.0.0.2", 53

    # --- читаем settings.yaml (vpn.map_dns + adguard_home.enable)
    y = _read_yaml()
    # upstream: строго kresd@2 из settings.sh
    upstreams = []
    _proxy_ip, _kresd2, _dns_port = _read_env()
    if not _kresd2:
        sys.exit("ERROR: KRESD2_IP is not provided by settings.sh --print-env-proxy")
    upstreams = [(_kresd2, _dns_port)]

    # ip-range: vpn.map_dns из YAML либо дефолт
    if args.ip_range is None:
        vpn = (y.get("vpn") or {})
        args.ip_range = (vpn.get("map_dns") or DEFAULT_FAKE_RANGE)
    else:
        # Если задано через CLI, проверим согласованность с settings.yaml
        try:
            vpn = (y.get("vpn") or {})
            cfg_range = vpn.get("map_dns")
        except Exception:
            cfg_range = None
        if cfg_range and cfg_range != args.ip_range:
            print(f"WARNING: --ip-range {args.ip_range} != vpn.map_dns {cfg_range} "
                  f"(PREROUTING hook may not match)", file=sys.stderr)

    # Если адрес/порт не задан через CLI — берём из settings.sh
    _proxy_ip, _kresd2, _dns_port = _read_env()
    if args.address == p.get_default("address"):
        args.address = _proxy_ip
    if args.port == p.get_default("port"):
        args.port = _dns_port

    # TTL из settings.yaml (если CLI не переопределил)
    ttl_cli_override = (args.ttl_cap is not None)
    if not ttl_cli_override:
        agh_cfg = (y.get("adguard_home") or {})
        agh_on = _as_bool(agh_cfg.get("enable"))
        args.ttl_cap = 180 if agh_on else 300
    print(f"TTL cap: {args.ttl_cap} (source={'CLI' if ttl_cli_override else 'settings.yaml'})", file=sys.stderr)

    pretty_up = ",".join([f"{h}:{port}" for (h,port) in upstreams])
    print("Starting Proxy Resolver (%s:%d -> %s) [%s]" % (
          args.address or "*", args.port, pretty_up,
          "UDP/TCP" if args.tcp else "UDP"))

    resolver = ProxyResolver(
        upstreams,
        args.timeout, args.ip_range,
        args.cleanup_interval, args.cleanup_expiry,
        map_log=args.map_log, ttl_cap=args.ttl_cap)
    handler = PassthroughDNSHandler if args.passthrough else DNSHandler
    logger = DNSLogger(args.log,args.log_prefix)
    udp_server = DNSServer(resolver,
                           port=args.port,
                           address=args.address,
                           logger=logger,
                           handler=handler)
    udp_server.start_thread()
    if args.tcp:
        tcp_server = DNSServer(resolver,
                               port=args.port,
                               address=args.address,
                               tcp=True,
                               logger=logger,
                               handler=handler)
        tcp_server.start_thread()

    # лёгкий hot-reload по SIGHUP: перечитать settings.yaml и обновить TTL (если CLI не задавал)
    def _reload_env(signum, frame):
        nonlocal args, upstreams, y, ttl_cli_override, resolver
        # upstreams/addr/port не меняем на лету
        print("SIGHUP: env refreshed", file=sys.stderr)
        y = _read_yaml()
        if not ttl_cli_override:
            agh_cfg = (y.get("adguard_home") or {})
            agh_on = _as_bool(agh_cfg.get("enable"))
            args.ttl_cap = 180 if agh_on else 300
            resolver.ttl_cap = int(args.ttl_cap)  # применяем новое значение на лету
            print(f"SIGHUP: TTL cap -> {resolver.ttl_cap} (source=settings.yaml)", file=sys.stderr)
    try: signal.signal(signal.SIGHUP, _reload_env)
    except Exception: pass
    while True:
        alive = udp_server.isAlive()
        if args.tcp:
            try:
                alive = alive or tcp_server.isAlive()
            except NameError:
                pass
        if not alive:
            break
        time.sleep(1)
