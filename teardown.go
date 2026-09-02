package main

import (
	"fmt"
	"os"
	"strings"
)

// teardown reverts everything, regardless of which flags set it up. Idempotent.
func teardown(cfg *Config) {
	fmt.Println("\n[*] tearing down...")

	// Remove OUTPUT rules referencing our set (transparent nat + coarse filter).
	removeRules(cfg, true)  // nat table
	removeRules(cfg, false) // filter table

	// Stop the auto-refresher (pidfile, then a cmdline-tag sweep for any orphan).
	killPidfile(cfg.ConfDir+"/.refresh.pid", false)
	pkillTag(cfg.Tag)

	// Stop the proxy: SIGTERM, wait out mitmdump's ~1s async shutdown, SIGKILL fallback,
	// so `down` returns only once port is free. (The non-HTTP TCP pacer is an in-process
	// goroutine of that proxy, so it dies with it — nothing extra to kill.)
	killPidfile(cfg.ConfDir+"/.mitm.pid", true)

	// Restore route_localnet to its pre-run value.
	old := "0"
	if b, err := os.ReadFile(cfg.RLNState); err == nil {
		if v := strings.TrimSpace(string(b)); v != "" {
			old = v
		}
	}
	sysctlSet("net.ipv4.conf.all.route_localnet", old)

	// Drop the ipset.
	_ = runQ("ipset", "destroy", cfg.SetName)

	fmt.Printf("[*] reverted. CA left trusted (remove: sudo rm %s && sudo update-ca-certificates --fresh)\n", cfg.CADst)
}
