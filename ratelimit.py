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

# --- Adaptive back-off (ON BY DEFAULT; disable with --fixed / ADAPT=0) ----------------------
# A safety governor, not a throughput optimizer: the configured rate is a CEILING the effective
# rate can only drop BELOW, never exceed. By default it STARTS AT the ceiling (you asked for N
# req/s, you get N) and only pulls below it if the target actually struggles, then recovers back
# up. It watches the target the way TCP congestion control watches a link — by DELAY and LOSS,
# not status codes (a struggling server rarely sends a clean 429/503; it just gets slow, then
# stops answering). Signals, strongest first: connection loss/timeout, a request stalled with no
# answer, and per-host latency rising vs its own healthy baseline (windowed low-percentile RTT).
# On distress: multiplicative decrease (AIMD); when quiet: slow additive recovery toward the
# ceiling. SLOW_START (--slow-start) instead begins at the floor and ramps UP for an unknown,
# possibly fragile target. --fixed disables the governor entirely (exact, reproducible N req/s).
# Everything is surfaced in `goslow top`.
ADAPT = os.getenv("ADAPT", "1") == "1"
SLOW_START = os.getenv("SLOW_START", "0") == "1"
ADAPT_MIN = float(os.getenv("ADAPT_MIN", str(max(1.0, RATE * 0.1))))  # floor: never throttle below this
WARMUP = float(os.getenv("ADAPT_WARMUP", "3"))       # observe-only seconds to learn a baseline
WINDOW = float(os.getenv("ADAPT_WINDOW", "10"))      # rolling seconds for the min-RTT baseline
MIN_SAMPLES = int(os.getenv("ADAPT_SAMPLES", "5"))   # per-host samples before a ratio is trusted
STALL_S = float(os.getenv("ADAPT_STALL", "8"))       # an in-flight request older than this = distress
SOFT_RATIO = float(os.getenv("ADAPT_SOFT", "2.0"))   # latency this x baseline -> gentle ease
HARD_RATIO = float(os.getenv("ADAPT_HARD", "4.0"))   # latency this x baseline -> hard back-off
RECOVER_RATIO = float(os.getenv("ADAPT_RECOVER", "1.3"))  # below this + no loss -> recover
DECREASE = float(os.getenv("ADAPT_DECREASE", "0.5")) # multiplicative decrease on distress
GENTLE = float(os.getenv("ADAPT_GENTLE", "0.9"))     # softer decrease on rising latency
BASE_FLOOR = float(os.getenv("ADAPT_BASE_FLOOR", "0.005"))  # ratio baseline can't dip below this (anti-poison)
MIN_LAT_SAMPLE = 0.002   # ignore sub-2ms "responses" (resets/cached errors) as healthy-RTT samples
EWMA_ALPHA = 0.3
log = logging.getLogger("ratelimit")

class RateLimiter:
    def __init__(self):
        # rate = current EFFECTIVE rate (adapts down); ceiling = the hard cap it never exceeds.
        self.ceiling = RATE
        self.floor = min(ADAPT_MIN, RATE)
        # Start point: by default (adaptive or fixed) begin AT the ceiling with a full burst, so a
        # user who asked for N req/s gets N and the governor only pulls BELOW on measured distress.
        # --slow-start instead begins at the floor with a floor-sized burst so the first wave can't
        # slam an unknown target before the controller's first tick, then ramps UP while healthy
        # (additive, not exponential — exponential overshoots a fragile target's safe point then
        # has to slam the brakes).
        if ADAPT and SLOW_START:
            self.rate = self.capacity = self.tokens = self.floor
            self.slow_start = True
        else:
            self.rate, self.capacity = RATE, BURST
            self.slow_start = False
            if ADAPT:
                # Adaptive default: run AT the ceiling, but do NOT hand out a full second's worth of
                # tokens at t=0. A full burst would admit RATE requests simultaneously and could tip
                # a fragile target past its concurrency cliff before the controller's first tick (a
                # stall cascade the governor then can't undo — easing the admission rate doesn't
                # drain requests already hung on the server). Start the bucket near-empty; it refills
                # at RATE/s, so throughput still reaches RATE within ~1s but the opening is smooth.
                self.tokens = self.floor
            else:
                self.tokens = BURST  # fixed mode keeps the full burst (exact, reproducible)
        self.step = max(1.0, RATE * 0.05)   # additive-increase step on recovery
        self.updated = time.monotonic()
        self.lock = asyncio.Lock()
        # observability counters (asyncio is single-threaded -> plain ints are race-free)
        self.allowed = 0        # requests granted a token (cumulative)
        self.waiting = 0        # requests currently blocked in acquire() = queue depth
        self.host_counts = {}   # per-target grant counts, for the "top targets" view
        # adaptive state
        self.adapt = ADAPT
        self.start_ts = time.monotonic()
        self.hoststats = {}     # host -> {"win": [(ts, latency_s)...], "ewma": s}
        self.inflight = {}      # flow.id -> monotonic start (for stall detection)
        self.losses = 0         # cumulative connection errors/timeouts (no answer)
        self._last_losses = 0
        self.adapt_reason = "off" if not ADAPT else "warmup"
        self.worst_ratio, self.worst_base, self.worst_lat = 0.0, None, None
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

    def record_latency(self, host, lat, status):
        # feed one completed in-scope request into that host's rolling baseline + EWMA.
        hs = self.hoststats.get(host)
        if hs is None:
            hs = self.hoststats[host] = {"win": [], "ewma": lat}
        now = time.monotonic()
        hs["ewma"] = EWMA_ALPHA * lat + (1 - EWMA_ALPHA) * hs["ewma"]  # tracks CURRENT latency
        # Only a healthy serve defines the min-RTT baseline. A 5xx (or an instant reset that still
        # counts as a "response") is NOT the server's healthy floor -- folding one in poisons the
        # baseline and makes every real response look like a huge latency multiple in `goslow top`.
        if (status is not None and status >= 500) or lat < MIN_LAT_SAMPLE:
            return
        hs["win"].append((now, lat))
        cutoff = now - WINDOW
        if hs["win"][0][0] < cutoff:  # trim expired samples
            hs["win"] = [(t, l) for (t, l) in hs["win"] if t >= cutoff]

    def _adapt_tick(self):
        # Runs once per STATS_EVERY. No awaits -> executes atomically in the single asyncio
        # thread, so mutating rate/capacity/tokens here can't tear an acquire() in progress.
        now = time.monotonic()
        if now - self.start_ts < WARMUP:
            self.adapt_reason = "warmup"
            return
        # worst per-host latency ratio (current EWMA vs that host's windowed min-RTT baseline)
        worst_ratio, worst_base, worst_lat = 0.0, None, None
        for hs in self.hoststats.values():
            win = hs["win"]
            if len(win) < MIN_SAMPLES:
                continue
            # Baseline = a LOW PERCENTILE (~p20) of the window, not the absolute min. A jittery but
            # healthy server's fastest sample is unrepresentatively quick; comparing EWMA against
            # that raw min makes normal variance look like distress. p20 ignores the lucky-fast
            # tail while still tracking a rate-induced latency climb. Floor guards a poisoned base.
            lats = sorted(l for _, l in win)
            base = max(lats[len(lats) // 5], BASE_FLOOR)
            ratio = hs["ewma"] / base
            if ratio > worst_ratio:
                worst_ratio, worst_base, worst_lat = ratio, base, hs["ewma"]
        self.worst_ratio, self.worst_base, self.worst_lat = worst_ratio, worst_base, worst_lat

        loss = self.losses - self._last_losses
        self._last_losses = self.losses
        stall = any((now - t) > STALL_S for t in self.inflight.values())
        reap = now - max(STALL_S * 3, 60)  # drop abandoned entries so inflight can't leak
        for fid in [f for f, t in self.inflight.items() if t < reap]:
            del self.inflight[fid]

        if loss > 0 or stall or worst_ratio >= HARD_RATIO:
            self.slow_start = False        # first distress ends the ramp -> AIMD from here on
            self.rate = max(self.floor, self.rate * DECREASE)
            why = "no-answer/loss" if loss > 0 else ("stall (no reply)" if stall else "latency %.1fx" % worst_ratio)
            self.adapt_reason = "backoff: " + why
        elif worst_ratio >= SOFT_RATIO:
            self.slow_start = False
            self.rate = max(self.floor, self.rate * GENTLE)
            self.adapt_reason = "ease: latency %.1fx" % worst_ratio
        elif worst_ratio and worst_ratio <= RECOVER_RATIO and self.rate < self.ceiling:
            # healthy + proven (>=MIN_SAMPLES): ramp toward the ceiling ADDITIVELY (+step/tick),
            # whether ramping up from the floor for the first time or recovering after a back-off.
            # Deliberately NOT exponential: a governor probing an unknown limit must not overshoot
            # the safe point (an exponential ramp jumps past it into distress, then has to slam the
            # brakes). Additive means the worst overshoot is one step, so the latency rise is caught
            # near the safe rate. burst grows with rate (below), so no sudden admission spike either.
            self.rate = min(self.ceiling, self.rate + self.step)
            self.adapt_reason = ("ramping %g/s" % self.rate) if self.slow_start else "recovering"
        else:
            # no trusted samples yet, or holding steady. Don't ramp blind.
            if self.rate >= self.ceiling:
                self.adapt_reason = "steady"
            elif worst_ratio == 0:
                self.adapt_reason = "probing" if self.slow_start else "hold"
            else:
                self.adapt_reason = "hold"
        # burst shrinks with the effective rate (a governor shouldn't let a big bucket punch
        # through the back-off), and never carry more tokens than the current capacity.
        self.capacity = self.rate
        if self.tokens > self.capacity:
            self.tokens = self.capacity

    async def snapshot_loop(self):
        # Emit a fresh stats snapshot every STATS_EVERY seconds. reqps is measured over the
        # interval (allowed delta / dt), so the reader sees an effective, not cumulative, rate.
        last_allowed, last_t = self.allowed, time.monotonic()
        tmp = STATS_FILE + ".tmp"
        while True:
            await asyncio.sleep(STATS_EVERY)
            if self.adapt:
                self._adapt_tick()
            now = time.monotonic()
            dt = (now - last_t) or 1e-9
            reqps = (self.allowed - last_allowed) / dt
            last_allowed, last_t = self.allowed, now
            top = dict(sorted(self.host_counts.items(), key=lambda kv: kv[1], reverse=True)[:8])
            snap = {"ts": time.time(), "cap": self.ceiling, "rate": round(self.rate, 2),
                    "burst": self.capacity, "tokens": round(self.tokens_now(), 2),
                    "allowed": self.allowed, "waiting": self.waiting, "reqps": round(reqps, 2),
                    "scoped": bool(self.hosts or self.nets), "hosts": top,
                    "adapt": self.adapt, "reason": self.adapt_reason, "losses": self.losses,
                    "base_ms": round((self.worst_base or 0) * 1000, 1),
                    "lat_ms": round((self.worst_lat or 0) * 1000, 1),
                    "ratio": round(self.worst_ratio, 2)}
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
        if limiter.adapt:
            limiter.inflight[flow.id] = time.monotonic()  # for stall / latency tracking

def response(flow: http.HTTPFlow):
    # Completed round-trip for an in-scope request -> feed its latency into the baseline.
    if not limiter.adapt:
        return
    start = limiter.inflight.pop(flow.id, None)
    if start is None:
        return  # wasn't tracked (out of scope)
    # Measure the SERVER round-trip: from admission (post-acquire, recorded in the request hook)
    # to the response. NOT from request receipt -- that would include the time the request sat in
    # goslow's OWN token-bucket queue, so throttling would look like server latency and the
    # governor would back off in response to its own delay (a feedback loop). We cap what we send;
    # we must judge the target only by how fast IT answers once we let the request through.
    lat = time.monotonic() - start
    if lat > 0:
        limiter.record_latency(flow.request.pretty_host, lat, flow.response.status_code)

def error(flow: http.HTTPFlow):
    # Connection error / timeout / no answer on an in-scope request = a loss (hard distress).
    if limiter.adapt and limiter.inflight.pop(flow.id, None) is not None:
        limiter.losses += 1

def load(loader):
    if not ADAPT:
        mode = "fixed (hard cap, no back-off)"
    elif SLOW_START:
        mode = "adaptive slow-start: floor %g/s -> ceiling %g/s, backs off on latency/loss" % (limiter.floor, limiter.ceiling)
    else:
        mode = "adaptive: start %g/s (ceiling), floor %g/s, backs off on latency/loss" % (limiter.ceiling, limiter.floor)
    log.info("[ratelimit] cap=%s req/s burst=%s scope=%s (%d hosts, %d nets) [%s]",
             RATE, BURST, SCOPE_FILE, len(limiter.hosts), len(limiter.nets), mode)

def running():
    # Event loop is up now -> start the background stats writer.
    try:
        asyncio.ensure_future(limiter.snapshot_loop())
    except RuntimeError as e:
        log.warning("[ratelimit] could not start stats loop: %s", e)
