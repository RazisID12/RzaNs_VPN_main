#!/usr/bin/env -S python3 -u
# -*- coding: utf-8 -*-

from __future__ import print_function
import socket, struct, subprocess, sys, time, argparse, threading, re, pathlib, shutil
from collections import deque
from ipaddress import IPv4Network, AddressValueError, NetmaskValueError
from dnslib import DNSRecord, RCODE, QTYPE, A
from dnslib.server import DNSServer, DNSHandler, BaseResolver, DNSLogger

SETTINGS_PATH = pathlib.Path("/opt/rzans_vpn_main/settings.map")
DEFAULT_FAKE_RANGE = "10.30.0.0/15"
CHAIN = "RZANS_VPN_MAIN-MAPPING"

def read_settings_map(path: pathlib.Path = SETTINGS_PATH) -> dict:
    """
    Быстрый парсер settings.map: TAG <space> VALUE, строки с # игнорируем.
    Возвращает dict {'TAG': 'VALUE'}.
    """
    result = {}
    if not path.exists():
        return result
    pat = re.compile(r"^\s*([A-Z0-9_]+)\s+(.+?)\s*(#.*)?$")
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        if line.lstrip().startswith("#") or not line.strip():
            continue
        m = pat.match(line)
        if not m:
            continue
        tag, val = m.group(1), m.group(2).strip()
        result[tag] = val
    return result

def choose_upstream_from_settings(cfg: dict) -> str:
    """
    Выбрать публичный DNS на основе тега UPSTREAM_DNS (1|2|3).
    1 = Cloudflare, 2 = Quad9, 3 = Google. Возвращает 'IP:port'.
    """
    sel = (cfg.get("UPSTREAM_DNS", "1") or "1").strip()
    mapping = {
        "1": "1.1.1.1:53",         # Cloudflare
        "2": "9.9.9.10:53",        # Quad9
        "3": "8.8.8.8:53",         # Google
    }
    if sel not in mapping:
        print(f"WARNING: Unexpected UPSTREAM_DNS='{sel}', fallback to {mapping['1']}", file=sys.stderr)
    return mapping.get(sel, mapping["1"])

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
    def __init__(self, address, port, timeout, ip_range, cleanup_interval, cleanup_expiry):
        # iptables бинарь (на случай альтернативных путей)
        self.iptables = shutil.which("iptables") or "iptables"

        # Пул фейковых IP
        try:
            self.ip_pool = deque([str(x) for x in IPv4Network(ip_range).hosts()])
        except (AddressValueError, NetmaskValueError, ValueError):
            print(f"ERROR: Bad ip-range '{ip_range}', fallback to {DEFAULT_FAKE_RANGE}")
            self.ip_pool = deque([str(x) for x in IPv4Network(DEFAULT_FAKE_RANGE).hosts()])

        self.ip_map = {}
        # Load existing mapping
        rule = f"{self.iptables} -w -t nat -nL {CHAIN} | awk '{{if (NR<3) {{next}}; print $5, substr($6, 4)}}'"
        try:
            mappings = subprocess.run(rule, shell=True, check=True,
                                      capture_output=True, text=True).stdout
        except subprocess.CalledProcessError:
            # Цепочки ещё нет — просто считаем, что маппингов нет
            mappings = ""
        current_time = time.time()
        for line in mappings.splitlines():
            line = line.strip()
            if line:
                parts = line.split()   # безопаснее, чем split(" ")
                if len(parts) != 2:
                    continue
                fake_ip, real_ip = parts
                if not self.mapping_ip(real_ip, fake_ip, current_time):
                    rule = f"{self.iptables} -w -t nat -F {CHAIN}"
                    subprocess.run(rule, shell=True, check=True)
                    sys.exit(1)
        self.address = address
        self.port = port
        self.timeout = timeout
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
                    print("ERROR: No fake IP left")
                    return None
                self.ip_map[real_ip] = {"fake_ip": fake_ip, "last_access": time.time()}
                rule = f"{self.iptables} -w -t nat -A {CHAIN} -d {fake_ip} -j DNAT --to-destination {real_ip}"
                subprocess.run(rule, shell=True, check=True)
                print(f"Mapping: {fake_ip} to {real_ip}")
                return fake_ip

    def mapping_ip(self,real_ip,fake_ip,last_access):
        if self.ip_map.get(real_ip):
            print(f"ERROR: Real IP {real_ip} is already mapped")
            return False
        try:
            self.ip_pool.remove(fake_ip)
            self.ip_map[real_ip] = {"fake_ip": fake_ip, "last_access": last_access}
            print(f"Mapping: {fake_ip} to {real_ip}")
        except ValueError:
            print(f"ERROR: Fake IP {fake_ip} not in fake IP pool")
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
                rule = f"{self.iptables} -w -t nat -D {CHAIN} -d {fake_ip} -j DNAT --to-destination {real_ip}"
                subprocess.run(rule, shell=True, check=True)
                #print(f"Unmapped: {fake_ip} to {real_ip}")
            print(f"Cleanup: {len(cleanup_ips)} expired fake IPs")

    def resolve(self,request,handler):
        try:
            if handler.protocol == "udp":
                proxy_r = request.send(self.address,self.port,timeout=self.timeout)
            else:
                proxy_r = request.send(self.address,self.port,tcp=True,timeout=self.timeout)
            reply = DNSRecord.parse(proxy_r)
            if request.q.qtype == QTYPE.A:
                #print("GOT A")
                newrr = []
                for record in reply.rr:
                    if record.rtype != QTYPE.A:
                        continue
                    newrr.append(record)
                reply.rr = newrr
                for record in reply.rr:
                    #print(dir(record))
                    #print(type(record.rdata))
                    real_ip = str(record.rdata)
                    fake_ip = self.get_fake_ip(real_ip)
                    if not fake_ip:
                        reply = request.reply()
                        reply.header.rcode = getattr(RCODE,"SERVFAIL")
                        return reply
                    record.rdata = A(fake_ip)
                    record.rname = request.q.qname
                    record.ttl = 300
                    #print(a.rdata)
                return reply
            #print(reply)
        except socket.timeout:
            reply = request.reply()
            reply.header.rcode = getattr(RCODE,"SERVFAIL")
        return reply

class PassthroughDNSHandler(DNSHandler):
    """
        Modify DNSHandler logic (get_reply method) to send directly to
        upstream DNS server rather then decoding/encoding packet and
        passing to Resolver (The request/response packets are still
        parsed and logged but this is not inline)
    """
    def get_reply(self,data):
        host,port = self.server.resolver.address,self.server.resolver.port
        request = DNSRecord.parse(data)
        self.log_request(request)
        if self.protocol == "tcp":
            data = struct.pack("!H",len(data)) + data
            response = send_tcp(data,host,port)
            response = response[2:]
        else:
            response = send_udp(data,host,port)
        reply = DNSRecord.parse(response)
        self.log_reply(reply)
        return response

def send_tcp(data,host,port):
    """
        Helper function to send/receive DNS TCP request
        (in/out packets will have prepended TCP length header)
    """
    sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    sock.connect((host,port))
    sock.sendall(data)
    response = sock.recv(8192)
    length = struct.unpack("!H",bytes(response[:2]))[0]
    while len(response) - 2 < length:
        response += sock.recv(8192)
    sock.close()
    return response

def send_udp(data,host,port):
    """
        Helper function to send/receive DNS UDP request
    """
    sock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
    sock.sendto(data,(host,port))
    response,server = sock.recvfrom(8192)
    sock.close()
    return response

if __name__ == "__main__":
    p = argparse.ArgumentParser(description="DNS Proxy")
    p.add_argument("--port","-p",type=int,default=53,
                    metavar="<port>",
                    help="Local proxy port (default:53)")
    p.add_argument("--address","-a",default="127.0.0.2",
                    metavar="<address>",
                    help="Local proxy listen address (default:127.0.0.2)")
    p.add_argument("--upstream","-u",default=None,
                    metavar="<dns server:port>",
                    help="Upstream DNS server:port (default: from settings.map UPSTREAM_DNS)")
    p.add_argument("--tcp",action="store_true",default=False,
                    help="TCP proxy (default: UDP only)")
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
                   help="Fake IP range (overrides settings.map VPN_MAP_DST4)")
    p.add_argument("--cleanup-interval","-c",type=int,default=3600,
                    metavar="<seconds>",
                    help="Seconds between fake IP cleanup runs (default: 3600)")
    p.add_argument("--cleanup-expiry","-e",type=int,default=7200,
                    metavar="<seconds>",
                    help="Seconds of inactivity before fake IP is removed (default: 7200)")
    args = p.parse_args()
    # --- settings.map заранее (используем и для ip-range, и для upstream)
    cfg = read_settings_map()

    # --- upstream: если не задан ключом, берём из settings.map (UPSTREAM_DNS)
    if args.upstream in (None, "", "auto"):
        args.upstream = choose_upstream_from_settings(cfg)
    args.dns, _, args.dns_port = args.upstream.partition(":")
    args.dns_port = int(args.dns_port or 53)

    # --- settings.map: если --ip-range не задан
    if args.ip_range is None:
        ip_from_cfg = cfg.get("VPN_MAP_DST4", "").strip()
        args.ip_range = ip_from_cfg or DEFAULT_FAKE_RANGE

    print("Starting Proxy Resolver (%s:%d -> %s:%d) [%s]" % (
          args.address or "*", args.port,
          args.dns, args.dns_port,
          "UDP/TCP" if args.tcp else "UDP"))

    resolver = ProxyResolver(
        args.dns, args.dns_port,
        args.timeout, args.ip_range,
        args.cleanup_interval, args.cleanup_expiry)
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
    while udp_server.isAlive():
        time.sleep(1)