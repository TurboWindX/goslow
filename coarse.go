package main

import "fmt"

// runCoarse applies a lightweight iptables-only new-connection-rate cap and exits.
// No proxy, no CA. Caps conns/s (≈ req/s only without keepalive); use proxy mode for
// a true per-request cap. Persists until `goslow down`.
func runCoarse(cfg *Config, scopeFile string) {
	domains, err := loadScope(cfg, scopeFile)
	if err != nil {
		die("scope: %v", err)
	}
	_ = iptablesCoarse(cfg, "-D") // clear any stale rule
	if err := iptablesCoarse(cfg, "-A"); err != nil {
		die("iptables coarse: %v", err)
	}
	startRefresher(cfg, domains)
	fmt.Printf("== COARSE: in-scope new TCP conns capped at %s/s (DROP over limit). Revert: sudo goslow down ==\n", cfg.Rate)
	fmt.Println("   note: ~req/s only if keepalive OFF; HTTP/2 & keepalive tools not truly capped (use proxy mode).")
}
