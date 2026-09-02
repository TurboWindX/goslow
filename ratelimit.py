"""HARD global HTTP request-rate cap for in-scope hosts (one shared token bucket).

Scope entries (one per line, '#'=comment) may be hostnames, IPs, or CIDRs; pasted
URLs are accepted (scheme/port/path stripped). Hostnames match themselves + subdomains;
CIDRs/IPs match the connection's real destination IP, so load-balancer / DNS IP
rotation cannot dodge the cap.
"""
import asyncio, fnmatch, ipaddress, logging, os, time
from mitmproxy import http

RATE = float(os.getenv("RATE", "20"))
BURST = float(os.getenv("BURST", str(RATE)))
SCOPE_FILE = os.getenv("SCOPE", "/etc/mitmproxy/scope.txt")
log = logging.getLogger("ratelimit")

class RateLimiter:
    def __init__(self):
        self.rate, self.capacity, self.tokens = RATE, BURST, BURST
        self.updated = time.monotonic()
        self.lock = asyncio.Lock()
        self.hosts, self.nets = self._load()
    def _load(self):
        hosts, nets = [], []
        try:
            f = open(SCOPE_FILE)
        except FileNotFoundError:
            log.warning("scope %s missing -> throttling ALL hosts", SCOPE_FILE)
            return hosts, nets
        with f:
            for ln in f:
                ln = ln.split("#", 1)[0].strip().lower()
                if not ln:
                    continue
                if "://" in ln:                       # pasted URL -> drop scheme
                    ln = ln.split("://", 1)[1]
                try:                                  # IP or CIDR?
                    nets.append(ipaddress.ip_network(ln, strict=False))
                    continue
                except ValueError:
                    pass
                h = ln.split("/", 1)[0].split(":", 1)[0].rstrip(".")   # host: drop path/port/dot
                if h:
                    hosts.append(h)
        return hosts, nets
    def in_scope(self, host, ip=None):
        if not self.hosts and not self.nets:
            return True
        host = (host or "").lower().rstrip(".")
        for p in self.hosts:
            if host == p or host.endswith("." + p) or fnmatch.fnmatch(host, p):
                return True
        for cand in (ip, host):                       # CIDR/IP match on dest IP (LB-proof)
            if not cand:
                continue
            try:
                addr = ipaddress.ip_address(cand)
            except ValueError:
                continue
            if any(addr in n for n in self.nets):
                return True
        return False
    async def acquire(self):
        async with self.lock:
            while True:
                now = time.monotonic()
                self.tokens = min(self.capacity, self.tokens + (now - self.updated) * self.rate)
                self.updated = now
                if self.tokens >= 1:
                    self.tokens -= 1
                    return
                await asyncio.sleep((1 - self.tokens) / self.rate)

limiter = RateLimiter()

async def request(flow: http.HTTPFlow):
    h = flow.request.pretty_host
    ip = None
    try:
        ip = flow.server_conn.peername[0]
    except Exception:
        pass
    if limiter.in_scope(h, ip):
        await limiter.acquire()

def load(loader):
    log.info("[ratelimit] cap=%s req/s burst=%s scope=%s (%d hosts, %d nets)",
             RATE, BURST, SCOPE_FILE, len(limiter.hosts), len(limiter.nets))
