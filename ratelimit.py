"""HARD global HTTP request-rate cap for in-scope hosts (one shared token bucket).

Scope entries (one per line, '#'=comment) may be hostnames, IPs, or CIDRs; pasted
URLs are accepted (scheme/port/path stripped). Hostnames match themselves + subdomains;
CIDRs/IPs match the connection's real destination IP, so load-balancer / DNS IP
rotation cannot dodge the cap.
"""
import asyncio, fnmatch, ipaddress, json, logging, os, time
from mitmproxy import http

RATE = float(os.getenv("RATE", "20"))
BURST = float(os.getenv("BURST", str(RATE)))
SCOPE_FILE = os.getenv("SCOPE", "/etc/mitmproxy/scope.txt")
# Live-stats snapshot read by `goslow top` / `goslow status` (separate process). Written
# atomically every STATS_EVERY seconds; absent/stale => the reader reports "not running".
STATS_FILE = os.getenv("STATS_HTTP", "/tmp/goslow-http-stats.json")
STATS_EVERY = 1.0
log = logging.getLogger("ratelimit")

class RateLimiter:
    def __init__(self):
        self.rate, self.capacity, self.tokens = RATE, BURST, BURST
        self.updated = time.monotonic()
        self.lock = asyncio.Lock()
        # observability counters (asyncio is single-threaded -> plain ints are race-free)
        self.allowed = 0        # requests granted a token (cumulative)
        self.waiting = 0        # requests currently blocked in acquire() = queue depth
        self.host_counts = {}   # per-target grant counts, for the "top targets" view
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

    def tokens_now(self):
        # non-mutating view of the bucket for display (refills lazily only inside acquire())
        return min(self.capacity, self.tokens + (time.monotonic() - self.updated) * self.rate)

    async def snapshot_loop(self):
        # Emit a fresh stats snapshot every STATS_EVERY seconds. reqps is measured over the
        # interval (allowed delta / dt), so the reader sees an effective, not cumulative, rate.
        last_allowed, last_t = self.allowed, time.monotonic()
        tmp = STATS_FILE + ".tmp"
        while True:
            await asyncio.sleep(STATS_EVERY)
            now = time.monotonic()
            dt = (now - last_t) or 1e-9
            reqps = (self.allowed - last_allowed) / dt
            last_allowed, last_t = self.allowed, now
            top = dict(sorted(self.host_counts.items(), key=lambda kv: kv[1], reverse=True)[:8])
            snap = {"ts": time.time(), "cap": self.rate, "burst": self.capacity,
                    "tokens": round(self.tokens_now(), 2), "allowed": self.allowed,
                    "waiting": self.waiting, "reqps": round(reqps, 2),
                    "scoped": bool(self.hosts or self.nets), "hosts": top}
            try:
                with open(tmp, "w") as f:
                    json.dump(snap, f)
                os.replace(tmp, STATS_FILE)  # atomic swap; readers never see a partial file
            except OSError as e:
                log.warning("[ratelimit] stats write failed: %s", e)

limiter = RateLimiter()

async def request(flow: http.HTTPFlow):
    h = flow.request.pretty_host
    ip = None
    try:
        ip = flow.server_conn.peername[0]
    except Exception:
        pass
    if limiter.in_scope(h, ip):
        limiter.waiting += 1
        try:
            await limiter.acquire()
        finally:
            limiter.waiting -= 1
        limiter.allowed += 1
        key = h or ip or "?"
        limiter.host_counts[key] = limiter.host_counts.get(key, 0) + 1

def load(loader):
    log.info("[ratelimit] cap=%s req/s burst=%s scope=%s (%d hosts, %d nets)",
             RATE, BURST, SCOPE_FILE, len(limiter.hosts), len(limiter.nets))

def running():
    # Event loop is up now -> start the background stats writer.
    try:
        asyncio.ensure_future(limiter.snapshot_loop())
    except RuntimeError as e:
        log.warning("[ratelimit] could not start stats loop: %s", e)
