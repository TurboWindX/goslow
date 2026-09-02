package main

import (
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"syscall"
	"time"
)

func writeAddon(cfg *Config) {
	_ = os.MkdirAll(cfg.ConfDir, 0755)
	if err := os.WriteFile(cfg.ConfDir+"/ratelimit.py", []byte(addonPy), 0644); err != nil {
		die("write addon: %v", err)
	}
}

// runProxy is the default transparent-proxy mode: mitmproxy enforces a hard global
// req/s cap for in-scope hosts. Runs foreground; Ctrl-C (or `goslow down`) reverts.
func runProxy(cfg *Config, scopeFile string) {
	needCmd(cfg, "mitmdump", "mitmproxy")
	if err := ensureUser(cfg.ProxyUser, cfg.ConfDir); err != nil {
		die("useradd %s: %v", cfg.ProxyUser, err)
	}
	writeAddon(cfg)

	domains, err := loadScope(cfg, scopeFile) // also writes cleaned scope.txt
	if err != nil {
		die("scope: %v", err)
	}
	// mitmdump runs as ProxyUser and must own confdir (writes its CA there).
	_ = runQ("chown", "-R", cfg.ProxyUser+":", cfg.ConfDir)

	old := sysctlGet("net.ipv4.conf.all.route_localnet")
	if old == "" {
		old = "0"
	}
	_ = os.WriteFile(cfg.RLNState, []byte(old), 0644)

	uid, gid, err := lookupUIDGID(cfg.ProxyUser)
	if err != nil {
		die("lookup %s: %v", cfg.ProxyUser, err)
	}

	logf, err := os.Create("/tmp/mitmdump.log")
	if err != nil {
		die("open log: %v", err)
	}
	mitm := exec.Command("mitmdump",
		"-s", cfg.ConfDir+"/ratelimit.py",
		"--set", "confdir="+cfg.ConfDir,
		"--mode", "transparent",
		"--listen-host", "0.0.0.0",
		"--listen-port", cfg.ProxyPort,
		"--ssl-insecure", // don't verify the TARGET's cert; pentest targets often self-sign/expire
		"--showhost")
	mitm.Env = append(os.Environ(),
		"RATE="+cfg.Rate, "BURST="+cfg.Rate, "SCOPE="+cfg.ConfDir+"/scope.txt")
	mitm.Stdout, mitm.Stderr = logf, logf
	mitm.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uid, Gid: gid}}

	fmt.Printf("[*] starting mitmproxy (transparent, %s req/s) as '%s'\n", cfg.Rate, cfg.ProxyUser)
	if err := mitm.Start(); err != nil {
		die("start mitmdump: %v", err)
	}
	_ = os.WriteFile(cfg.ConfDir+"/.mitm.pid", []byte(strconv.Itoa(mitm.Process.Pid)), 0644)

	// Revert on Ctrl-C / SIGTERM.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	fmt.Print("[*] waiting for CA")
	ready := false
	for i := 0; i < 30; i++ {
		if fileExists(cfg.CASrc) {
			ready = true
			break
		}
		if !processAlive(mitm.Process.Pid) {
			fmt.Println()
			dumpLog()
			teardown(cfg)
			die("mitmproxy died on startup")
		}
		fmt.Print(".")
		time.Sleep(500 * time.Millisecond)
	}
	fmt.Println()
	if !ready {
		teardown(cfg)
		die("CA not generated — see /tmp/mitmdump.log")
	}
	if err := copyFile(cfg.CASrc, cfg.CADst); err != nil {
		die("install CA: %v", err)
	}
	_ = runQ("update-ca-certificates")
	fmt.Printf("[*] CA installed system-wide -> %s\n", cfg.CADst)

	sysctlSet("net.ipv4.conf.all.route_localnet", "1")
	_ = iptablesRedirect(cfg, "-D") // clear any stale rule
	if err := iptablesRedirect(cfg, "-A"); err != nil {
		teardown(cfg)
		die("iptables redirect: %v", err)
	}
	// Hybrid: queue (not drop) every NON-HTTP in-scope port through our own transparent TCP
	// pacer, so brute against FTP/SSH/etc. on a scoped IP is throttled losslessly. Bind the
	// pacer first (so the redirect only goes live once it's listening); its upstream dials are
	// SO_MARK'd and excluded from the redirect below. --http-only opts out.
	if !cfg.HTTPOnly {
		if err := startTCPPacer(cfg); err != nil {
			teardown(cfg)
			die("start tcp pacer on :%s: %v", cfg.TCPPort, err)
		}
		fmt.Printf("[*] non-HTTP TCP pacer on :%s (queues conns at %s/s — lossless)\n", cfg.TCPPort, cfg.Rate)
		_ = iptablesNonHTTPRedirect(cfg, "-D")
		if err := iptablesNonHTTPRedirect(cfg, "-A"); err != nil {
			teardown(cfg)
			die("iptables non-http redirect: %v", err)
		}
	}
	startRefresher(cfg, domains)

	printBanner(cfg, scopeFile)

	// Block until a signal arrives or mitmdump exits, then revert.
	waitCh := make(chan struct{}, 1)
	go func() { _ = mitm.Wait(); waitCh <- struct{}{} }()
	select {
	case <-sig:
	case <-waitCh:
	}
	teardown(cfg)
}

func dumpLog() {
	if b, err := os.ReadFile("/tmp/mitmdump.log"); err == nil {
		fmt.Fprint(os.Stderr, string(b))
	}
}

func printBanner(cfg *Config, scopeFile string) {
	nonHTTP := fmt.Sprintf("   other tcp ports   -> %s conn/s   (TCP pacer, QUEUED/lossless: FTP/SSH/SMB/RDP/...)\n", cfg.Rate)
	if cfg.HTTPOnly {
		nonHTTP = "   other tcp ports   -> NOT throttled (--http-only)\n"
	}
	fmt.Printf(`
==================================================================
 GOSLOW ACTIVE -> every tool, scoped
   HTTP (tcp/%s)  -> %s req/s   (mitmproxy, HARD per-request)
%s   scope     : %s  (%d entries)
   proxy log : tail -f /tmp/mitmdump.log
 Cert-verifying tool still errors (rare; most pentest tools skip verify)?
   export REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt   # python requests
   export NODE_EXTRA_CA_CERTS=%s                                  # node
 Ctrl-C to stop and revert everything (or: sudo goslow down).
==================================================================
`, cfg.Ports, cfg.Rate, nonHTTP, scopeFile, ipsetCount(cfg), cfg.CASrc)
}
