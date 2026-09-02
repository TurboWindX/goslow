// goslow — rate-limit every offensive tool on this box, scoped to your targets.
//
// Default is HYBRID and covers the whole scope: in-scope HTTP ports get a HARD per-request
// cap via a transparent mitmproxy token-bucket; every other in-scope tcp port gets a
// built-in transparent TCP pacer that QUEUES over-cap connections AND paces the client's
// outbound data (one token per chunk sent), so FTP/SSH/etc. brute is throttled per-attempt —
// even tools that reuse a few connections to pipeline attempts (hydra -t N) — and keeps working.
// Lossless: nothing dropped, everything queued. Server->client replies are not gated.
// --http-only proxies HTTP only; --coarse is iptables-only DROP on all ports (no proxy/CA).
// Single static binary; embeds the mitmproxy addon and writes it at runtime. Auto-installs
// its deps (iptables/ipset/mitmproxy) on Kali via apt unless --no-install.
//
// USAGE
//   sudo goslow <scope-file> [rate]      hybrid: HTTP req/s cap + non-HTTP conn/s cap
//   sudo goslow --http-only <scope>      proxy only; non-HTTP ports left unthrottled
//   sudo goslow --coarse <scope> [rate]  iptables-only conn/s cap, all ports (no proxy/CA)
//   goslow top                           live dashboard (rate/queue/top targets)
//   goslow status                        one stats snapshot, then exit
//   sudo goslow down                     revert everything
package main

import (
	_ "embed"
	"fmt"
	"os"
	"strconv"
	"strings"
)

//go:embed ratelimit.py
var addonPy string

const (
	defRate    = 20
	defPorts   = "80,443"
	defRefresh = 30
)

// Config holds everything the run needs; defaults come from env, then flags/positionals.
type Config struct {
	SetName   string
	ProxyUser string
	ProxyPort string
	TCPPort   string
	Ports     string
	Rate      string
	Refresh   int
	ConfDir   string
	CASrc     string
	CADst     string
	RLNState  string
	HLName    string
	Tag       string // refresher process marker (for fallback pattern-kill)
	Coarse    bool
	HTTPOnly  bool
	Fixed     bool // disable the adaptive governor (exact, reproducible hard cap)
	SlowStart bool // adaptive + ramp up from the floor instead of starting at the ceiling
	NoInstall bool
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func envInt(k string, def int) int {
	if v := os.Getenv(k); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func defaultConfig() *Config {
	confdir := envOr("CONFDIR", "/etc/mitmproxy")
	return &Config{
		SetName:   envOr("SET_NAME", "pentest_scope"),
		ProxyUser: envOr("PROXY_USER", "mitmproxy"),
		ProxyPort: envOr("PROXY_PORT", "42069"), // off Burp's default 8080 to avoid listener clash
		TCPPort:   envOr("TCP_PORT", "42070"),   // non-HTTP pacer listener (mitmproxy uses 42069)
		Ports:     envOr("PORTS", defPorts),
		Rate:      envOr("RATE", strconv.Itoa(defRate)),
		Refresh:   envInt("REFRESH", defRefresh),
		ConfDir:   confdir,
		CASrc:     confdir + "/mitmproxy-ca-cert.pem",
		CADst:     "/usr/local/share/ca-certificates/mitmproxy.crt",
		RLNState:  confdir + "/.route_localnet.old",
		HLName:    "pentest",
		Tag:       "pentest_scope_refresher",
		NoInstall: os.Getenv("NO_INSTALL") == "1",
	}
}

func die(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "!! "+format+"\n", a...)
	os.Exit(1)
}

func mustRoot() {
	if os.Geteuid() != 0 {
		die("run as root (sudo)")
	}
}

func main() {
	// Make iptables/ipset (usually in /usr/sbin) reachable even under a bare sudo PATH.
	augmentPATH()

	cfg := defaultConfig()
	args := os.Args[1:]

	// Internal detached refresher re-exec: __refresh <tag> <interval> <setName> <confDir>
	if len(args) >= 1 && args[0] == "__refresh" {
		runRefresher(args)
		return
	}

	if len(args) >= 1 && args[0] == "down" {
		mustRoot()
		teardown(cfg)
		return
	}

	// Live observability — read-only, no root needed (just reads the /tmp stats snapshots).
	if len(args) >= 1 && args[0] == "top" {
		runTop(cfg)
		return
	}
	if len(args) >= 1 && args[0] == "status" {
		runStatus(cfg)
		return
	}

	scope := parseArgs(cfg, args)
	if scope == "" {
		usage()
		os.Exit(1)
	}
	if _, err := os.Stat(scope); err != nil {
		die("scope file not readable: %s", scope)
	}

	mustRoot()
	if cfg.Coarse {
		runCoarse(cfg, scope)
	} else {
		runProxy(cfg, scope)
	}
}

// parseArgs accepts flags in any position plus up to two positionals (scope, rate),
// mirroring the original script (`goslow scope.txt 50`).
func parseArgs(cfg *Config, args []string) (scope string) {
	var pos []string
	takeVal := func(i *int, flag string) string {
		*i++
		if *i >= len(args) {
			die("flag %s needs a value", flag)
		}
		return args[*i]
	}
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--coarse":
			cfg.Coarse = true
		case a == "--http-only":
			cfg.HTTPOnly = true
		case a == "--fixed":
			cfg.Fixed = true
		case a == "--slow-start":
			cfg.SlowStart = true
		case a == "--adapt":
			// adaptive is the default now; keep --adapt as an accepted no-op so old muscle
			// memory / scripts don't break.
		case a == "--no-install":
			cfg.NoInstall = true
		case a == "-h" || a == "--help":
			usage()
			os.Exit(0)
		case a == "--rate":
			cfg.Rate = takeVal(&i, a)
		case strings.HasPrefix(a, "--rate="):
			cfg.Rate = a[len("--rate="):]
		case a == "--ports":
			cfg.Ports = takeVal(&i, a)
		case strings.HasPrefix(a, "--ports="):
			cfg.Ports = a[len("--ports="):]
		case a == "--refresh":
			cfg.Refresh = atoi(takeVal(&i, a))
		case strings.HasPrefix(a, "--refresh="):
			cfg.Refresh = atoi(a[len("--refresh="):])
		default:
			if strings.HasPrefix(a, "-") {
				die("unknown flag %q (see --help)", a)
			}
			pos = append(pos, a)
		}
	}
	if len(pos) >= 1 {
		scope = pos[0]
	}
	if len(pos) >= 2 {
		cfg.Rate = pos[1] // positional rate, like the original script
	}
	if cfg.Fixed && cfg.SlowStart {
		die("--fixed and --slow-start are mutually exclusive")
	}
	return scope
}

func atoi(s string) int {
	n, err := strconv.Atoi(s)
	if err != nil {
		die("not a number: %q", s)
	}
	return n
}

func augmentPATH() {
	path := os.Getenv("PATH")
	for _, d := range []string{"/usr/local/sbin", "/usr/sbin", "/sbin", "/usr/local/bin"} {
		if !strings.Contains(":"+path+":", ":"+d+":") {
			path = d + ":" + path
		}
	}
	os.Setenv("PATH", path)
}

func usage() {
	fmt.Fprint(os.Stderr, `goslow — rate-limit every offensive tool on this box, scoped to your targets.

USAGE
  sudo goslow <scope-file> [rate]      DEFAULT hybrid: HTTP req/s cap + non-HTTP conn/s cap
  sudo goslow --http-only <scope>      proxy only; leave non-HTTP ports unthrottled
  sudo goslow --coarse <scope> [rate]  iptables-only conn/s cap, all ports (no proxy/CA)
  goslow top                           live dashboard (rate/queue/top targets); reads a running goslow
  goslow status                        print one stats snapshot and exit
  sudo goslow down                     revert everything

DEFAULT (hybrid) covers the WHOLE scope: in-scope HTTP ports (--ports) get a HARD per-request
cap via a transparent mitmproxy; every OTHER in-scope tcp port (FTP/SSH/SMB/RDP/...) goes through
a built-in TCP pacer that QUEUES over-cap connections AND paces the client's outbound data (one
token per chunk), all lossless. So a hydra brute against a scoped IP is throttled per-attempt —
even over its handful of reused connections — and keeps working (just slower). You don't have to
know which services are behind it. (Server replies/downloads are not gated; only what you send.)

By DEFAULT the HTTP rate is ADAPTIVE: --rate is the starting rate AND a ceiling — you get your
N req/s, and goslow only pulls BELOW N if the target actually slows down or drops connections
(delay+loss driven, AIMD, never exceeds N), then recovers back to N. Watch it in 'goslow top'.
Use --fixed for an exact, reproducible cap; --slow-start to ramp up from a floor on an unknown target.

FLAGS
  --rate N        starting rate AND ceiling: req/s (HTTP) and conn/s (non-HTTP); over-cap queued; also positional or $RATE
  --ports LIST    tcp ports treated as HTTP -> mitmproxy (default 80,443); rest -> TCP pacer; or $PORTS
  --refresh SEC   re-resolve hostnames every SEC to track LB/DNS rotation (default 30, 0=off); or $REFRESH
  --fixed         disable the adaptive governor: hold exactly --rate, never back off (reproducible)
  --slow-start    adaptive, but START at a floor and ramp UP toward --rate (extra-cautious for unknown/fragile targets)
  --http-only     proxy the HTTP ports only; do NOT pace/cap other ports
  --coarse        DROP over-rate conns on ALL in-scope tcp ports, no proxy/CA (cheapest, lossy, no per-request cap)
  --no-install    do not apt-get missing deps (iptables/ipset/mitmproxy)

SCOPE FILE: one entry per line, '#'=comment. hostnames, full URLs (scheme/port/path stripped),
  IPs, CIDRs. Hostnames match subdomains and are auto-re-resolved (LB-proof); CIDR/IP match
  the real destination IP. For a big CDN, list its CIDR.
`)
}
