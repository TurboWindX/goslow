# goslow

Rate-limit **every** offensive tool on the box (Burp, sqlmap, ffuf, nuclei, curl, Metasploit,
hydra…), scoped to your targets — one command, whole scope.

Default is **hybrid** and covers the entire scope, not just web:

- **HTTP ports** (`--ports`, default 80,443) → transparent mitmproxy token-bucket → **hard
  per-request** req/s cap. Over-cap requests are **queued**, then completed — nothing fails.
- **every other tcp port** (FTP, SSH, SMB, RDP, anything) → a built-in transparent **TCP
  pacer**. Two things are paced against one shared bucket: **new connections** (conn/s) *and*
  the **client's outbound data** (one token per chunk you send). Over-cap traffic is **queued**
  (delayed) then forwarded — lossless, no dropped packets, no failed attempts. Server replies /
  downloads are **not** gated: it caps what you *send*, not what the target sends back.

So if your scope is `www.example.com` **and** `1.2.3.4` (all external services), a hydra brute
against `1.2.3.4:21` is throttled too — and because it paces your outbound data, not just new
connections, it throttles the **attempt rate** even though hydra pipelines many attempts over a
few reused connections. You don't have to know what's listening on the IP, and the brute keeps
working (just slower) instead of seeing connection errors.

Single static binary. No interpreter, no sibling files — the mitmproxy addon is embedded and
written at runtime. Auto-installs its deps (`iptables`, `ipset`, `mitmproxy`) on Kali via apt.

## Install (per box)

Grab the binary — no wiki copy-paste:

```bash
curl -fsSL http://<your-host>/goslow -o goslow && chmod +x goslow && sudo mv goslow /usr/local/bin/
```

## Use

```bash
sudo goslow scope.txt              # hybrid: HTTP req/s + non-HTTP conn/s; Ctrl-C reverts
sudo goslow scope.txt 50           # 50/s
sudo goslow --ports 80,443,8443 scope.txt   # treat 8443 as HTTP too (proxy it)
sudo goslow --http-only scope.txt  # proxy only; leave non-HTTP ports unthrottled
sudo goslow --coarse scope.txt 20  # iptables-only conn/s cap on ALL ports (no proxy/CA)
goslow top                         # live dashboard (in another shell) — no sudo
goslow status                      # one-shot snapshot, then exit — no sudo
sudo goslow down                   # revert everything
```

### scope file

One entry per line, `#` = comment. Just paste what you're testing:

```
target.com                       # hostname — matches subdomains, auto-re-resolved (LB-proof)
https://api.target.com:8443/v1   # full URL — scheme/port/path stripped
10.0.0.5                         # IP
10.0.0.0/24                      # CIDR — matched on the real destination IP
```

**Load balancers / CDNs:** list the **hostname**. It's re-resolved every `--refresh` seconds
(default 30), so the cap holds even as the LB/DNS rotates backend IPs. For a big CDN with many
frontends, listing its **CIDR** is most airtight.

### flags / env

| flag | env | default | meaning |
|------|-----|---------|---------|
| `--rate N` (or positional) | `RATE` | 20 | req/s (HTTP) **and** conn/s (non-HTTP) cap; both queue over-cap traffic |
| `--ports LIST` | `PORTS` | `80,443` | tcp ports treated as HTTP → mitmproxy; rest → TCP pacer (queued conn cap) |
| `--refresh SEC` | `REFRESH` | 30 | re-resolve hostnames every SEC (0=off) |
| `--http-only` | | off | proxy HTTP ports only; leave other ports unthrottled |
| `--coarse` | | off | iptables-only conn cap on ALL ports (no proxy/CA) |
| `--no-install` | `NO_INSTALL=1` | off | don't apt-get missing deps |

**Which mode?** Default (hybrid) is the right call for almost every engagement — it's the only
one that covers a whole scope safely and losslessly (nothing dropped; over-cap traffic is queued
and completed). `--http-only` if you specifically don't want to touch non-web ports. `--coarse`
only when the proxies can't run (mitmproxy won't install, a tool breaks on the MITM'd TLS) — it
DROPs over-rate connections (lossy) and caps *connections* not *requests*, so keepalive/HTTP2
web tools slip past.

## Watch it work

While goslow runs, open another shell (**no sudo** — these only read the live stats) and:

```bash
goslow top       # self-refreshing dashboard, Ctrl-C to exit
goslow status    # print one frame and exit (scriptable)
```

```
 goslow live  ·  cap 20/s  ·  14:39:21
 ──────────────────────────────────────────────────────────────
 HTTP  mitmproxy    20.0 req/s  [████████████████████████]  of 20
   tokens 0.4/20   queue 20 waiting   served 1,284
 TCP   pacer        11.0 conn/s [█████████████░░░░░░░░░░░]  of 20
   tokens 0.5/20   active 10   queue 7   conns 59   paced 1.4 KB
 ──────────────────────────────────────────────────────────────
 top targets
   10.0.0.5           [████████████████████████] 1,284
   10.0.0.5:21        [█████████████████████░░░]   59
```

- **queue** = requests/connections blocked waiting for a token right now (how much you're backed up).
- **req/s** (HTTP) / **conn/s** (TCP) = *effective* rate over the last second, so you can see the cap biting.
- **paced** = client→target bytes forwarded through the TCP pacer; **served** = HTTP requests granted.
- **top targets** = where the throttled traffic is going (mitmproxy hosts + pacer destinations, merged).

Both engines flush a snapshot to `/tmp/goslow-{http,tcp}-stats.json` once a second; `top`/`status`
just read those. Absent or >4s stale ⇒ they report *not running*. `--coarse` has no proxy, so it
has no live stats (it's pure iptables); use it when you don't need the visibility.

## Build

```bash
make build        # static linux/amd64 -> ./goslow
```

Requires Go ≥ 1.21. Stdlib only, no module downloads.

## How it works

1. Load scope into an `ipset` (hostnames resolved to A records; CIDRs kept as nets).
2. Write + launch the embedded mitmproxy addon (`ratelimit.py`) as a dedicated `mitmproxy` user.
3. Trust mitmproxy's CA system-wide so TLS tools don't error. The proxy does **not**
   verify the target's own cert (`--ssl-insecure`) — pentest targets routinely self-sign
   or run expired certs, and this only affects the proxy→target leg you're already attacking.
4. `iptables` nat REDIRECT: in-scope tcp/`$PORTS` → the proxy (the proxy user's own upstream
   traffic is excluded to avoid a loop).
5. One shared token bucket delays over-cap requests — a true global req/s ceiling.
6. **Hybrid** also adds a second nat REDIRECT: in-scope tcp on every port *not* in `$PORTS`
   (i.e. non-HTTP) is redirected to a built-in **TCP pacer** — a protocol-blind transparent
   proxy that recovers each connection's real destination (`SO_ORIGINAL_DST`), holds it on a
   shared token bucket until a slot frees (**queued, not dropped**), then splices it to the
   target. As it splices, the **client→target** direction is *also* gated on the same bucket
   (one token per chunk written), so a tool that reuses a few connections to pipeline many
   attempts (`hydra -t 16`, DB brutes) is capped on **attempt rate**, not just connection rate.
   The **target→client** direction is ungated (we cap what you send, not the target's replies /
   downloads). Its own upstream dials carry an `SO_MARK` that this rule excludes, so it never
   loops. Redirected HTTP packets were already rewritten to the mitmproxy by then, so they don't
   hit this rule — no double-count.
7. A background refresher keeps the ipset fresh as the target's IPs rotate.
8. `down` (or Ctrl-C) removes all rules (it strips every rule referencing the ipset, so both
   redirects go), kills the proxy + refresher (the TCP pacer is a goroutine of the proxy, so it
   dies with it), restores sysctl, drops the ipset. CA left trusted (removal command printed).

`--http-only` skips step 6. `--coarse` skips the proxies entirely: a single `hashlimit` rule
**DROPs** in-scope new connections over the rate on **all** ports (lossy — relies on TCP retransmit).
Cheap, but caps *connections* not *requests*, so keepalive/HTTP2 web tools slip past. Use the
default for a real per-request cap on web plus lossless conn pacing everywhere else.
