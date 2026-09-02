package main

// Live observability for a running goslow: `goslow top` is a self-refreshing terminal
// dashboard (bars, queue depth, effective rate, top targets); `goslow status` prints one
// frame and exits. Both are READ-ONLY and run as a SEPARATE process from the goslow that's
// enforcing the cap, so they can't share memory — they read the per-second JSON snapshots the
// two engines flush (mitmproxy addon -> goslow-http-stats.json, TCP pacer -> goslow-tcp-stats.json).
// Hand-rolled ANSI, stdlib only, so the shipped binary stays static and dependency-free.

import (
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"time"
)

const (
	httpStatsFile = "/tmp/goslow-http-stats.json"
	tcpStatsPath  = tcpStatsFile // defined in tcpproxy.go
	staleAfter    = 4 * time.Second
	barW          = 24
)

// ANSI
const (
	aReset = "\033[0m"
	aDim   = "\033[2m"
	aBold  = "\033[1m"
	aGreen = "\033[32m"
	aYell  = "\033[33m"
	aRed   = "\033[31m"
	aCyan  = "\033[36m"
	aHome  = "\033[H"
	aClrEL = "\033[K"  // erase to end of line
	aClrBD = "\033[0J" // erase from cursor to end of screen
	aHide  = "\033[?25l"
	aShow  = "\033[?25h"
)

type httpSnap struct {
	Ts      float64          `json:"ts"`
	Cap     float64          `json:"cap"`
	Burst   float64          `json:"burst"`
	Tokens  float64          `json:"tokens"`
	Allowed int64            `json:"allowed"`
	Waiting int64            `json:"waiting"`
	Reqps   float64          `json:"reqps"`
	Scoped  bool             `json:"scoped"`
	Hosts   map[string]int64 `json:"hosts"`
}

type tcpSnap struct {
	Ts         float64          `json:"ts"`
	Cap        float64          `json:"cap"`
	Tokens     float64          `json:"tokens"`
	Active     int64            `json:"active"`
	Waiting    int64            `json:"waiting"`
	TotalConns int64            `json:"total_conns"`
	BytesPaced int64            `json:"bytes_paced"`
	Connps     float64          `json:"connps"`
	Dsts       map[string]int64 `json:"dsts"`
}

// readSnap loads a JSON snapshot and reports whether it's FRESH (exists + ts within staleAfter).
func readSnap[T any](path string, out *T, ts func(*T) float64) bool {
	b, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	if json.Unmarshal(b, out) != nil {
		return false
	}
	age := time.Since(time.Unix(0, int64(ts(out)*1e9)))
	return age >= 0 && age < staleAfter
}

// runStatus prints one frame and exits (for checking from any shell / scripting).
func runStatus(_ *Config) {
	var h httpSnap
	var t tcpSnap
	hf := readSnap(httpStatsFile, &h, func(s *httpSnap) float64 { return s.Ts })
	tf := readSnap(tcpStatsPath, &t, func(s *tcpSnap) float64 { return s.Ts })
	if !hf && !tf {
		fmt.Println("goslow: not running (no live stats at " + httpStatsFile + " / " + tcpStatsPath + ")")
		os.Exit(1)
	}
	fmt.Println(strings.Join(render(&h, hf, &t, tf, false), "\n"))
}

// runTop is the live dashboard: refresh once a second until Ctrl-C. Safe to launch before goslow
// (shows a waiting frame, then picks it up). Restores the cursor on exit.
func runTop(_ *Config) {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	fmt.Print(aHide + "\033[2J") // hide cursor, clear once
	defer fmt.Print(aShow + aReset)
	go func() {
		<-sig
		fmt.Print(aShow + aReset + "\n")
		os.Exit(0)
	}()
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		var h httpSnap
		var t tcpSnap
		hf := readSnap(httpStatsFile, &h, func(s *httpSnap) float64 { return s.Ts })
		tf := readSnap(tcpStatsPath, &t, func(s *tcpSnap) float64 { return s.Ts })
		lines := render(&h, hf, &t, tf, true)
		// home + per-line erase avoids full-screen-clear flicker; erase-below wipes leftovers.
		fmt.Print(aHome + strings.Join(lines, aClrEL+"\n") + aClrEL + "\n" + aClrBD)
		<-tick.C
	}
}

func render(h *httpSnap, hf bool, t *tcpSnap, tf bool, live bool) []string {
	cap := 0.0
	if hf {
		cap = h.Cap
	} else if tf {
		cap = t.Cap
	}
	capStr := "—"
	if cap > 0 {
		capStr = fmt.Sprintf("%g/s", cap)
	}
	rule := strings.Repeat("─", 62)
	L := []string{
		fmt.Sprintf(" %sgoslow live%s  ·  cap %s  ·  %s", aBold+aCyan, aReset, capStr, time.Now().Format("15:04:05")),
		" " + aDim + rule + aReset,
	}

	// HTTP section
	if hf {
		L = append(L, fmt.Sprintf(" %-6s%-11s%s  %s  %sof %g%s", "HTTP", "mitmproxy",
			fmt.Sprintf("%6.1f req/s", h.Reqps), bar(h.Reqps, h.Cap, h.Waiting), aDim, h.Cap, aReset))
		L = append(L, fmt.Sprintf("   %stokens %.1f/%g   queue %d waiting   served %s%s",
			aDim, h.Tokens, h.Cap, h.Waiting, comma(h.Allowed), aReset))
	} else {
		L = append(L, fmt.Sprintf(" %-6s%-11s%s(not running)%s", "HTTP", "mitmproxy", aDim, aReset))
	}

	// TCP section
	if tf {
		L = append(L, fmt.Sprintf(" %-6s%-11s%s  %s  %sof %g%s", "TCP", "pacer",
			fmt.Sprintf("%5.1f conn/s", t.Connps), bar(t.Connps, t.Cap, t.Waiting), aDim, t.Cap, aReset))
		L = append(L, fmt.Sprintf("   %stokens %.1f/%g   active %d   queue %d   conns %s   paced %s%s",
			aDim, t.Tokens, t.Cap, t.Active, t.Waiting, comma(t.TotalConns), humanBytes(t.BytesPaced), aReset))
	} else {
		L = append(L, fmt.Sprintf(" %-6s%-11s%s(off — --http-only, --coarse, or not running)%s", "TCP", "pacer", aDim, aReset))
	}

	// Merged top targets (HTTP hosts + TCP destinations)
	L = append(L, " "+aDim+rule+aReset)
	tops := mergeTops(h, hf, t, tf)
	if len(tops) == 0 {
		L = append(L, " "+aDim+"top targets   (none yet)"+aReset)
	} else {
		L = append(L, " "+aBold+"top targets"+aReset)
		maxv := tops[0].v
		for _, kv := range tops {
			L = append(L, fmt.Sprintf("   %-20s %s %s%s%s", trunc(kv.k, 20), bar(float64(kv.v), float64(maxv), 0), aDim, comma(kv.v), aReset))
		}
	}

	if live {
		L = append(L, " "+aDim+rule+aReset)
		L = append(L, " "+aDim+"refresh 1s · Ctrl-C to exit"+aReset)
	}
	return L
}

type kv struct {
	k string
	v int64
}

func mergeTops(h *httpSnap, hf bool, t *tcpSnap, tf bool) []kv {
	m := map[string]int64{}
	if hf {
		for k, v := range h.Hosts {
			m[k] += v
		}
	}
	if tf {
		for k, v := range t.Dsts {
			m[k] += v
		}
	}
	out := make([]kv, 0, len(m))
	for k, v := range m {
		out = append(out, kv{k, v})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].v > out[j].v })
	if len(out) > 8 {
		out = out[:8]
	}
	return out
}

// bar renders a fixed-width fill bar, colored by load: green under 70%, yellow up to the cap,
// red once at/over the cap or whenever the queue is non-empty (throttling is actively biting).
func bar(v, max float64, queue int64) string {
	if max <= 0 {
		max = 1
	}
	f := v / max
	if f < 0 {
		f = 0
	}
	if f > 1 {
		f = 1
	}
	n := int(f*float64(barW) + 0.5)
	color := aGreen
	switch {
	case queue > 0 || v >= max:
		color = aRed
	case f >= 0.7:
		color = aYell
	}
	return "[" + color + strings.Repeat("█", n) + aDim + strings.Repeat("░", barW-n) + aReset + "]"
}

func humanBytes(n int64) string {
	if n < 1024 {
		return fmt.Sprintf("%d B", n)
	}
	f := float64(n)
	units := []string{"KB", "MB", "GB", "TB"}
	i := -1
	for f >= 1024 && i < len(units)-1 {
		f /= 1024
		i++
	}
	return fmt.Sprintf("%.1f %s", f, units[i])
}

func comma(n int64) string {
	s := fmt.Sprintf("%d", n)
	if n < 0 {
		return s
	}
	var b strings.Builder
	pre := len(s) % 3
	if pre == 0 {
		pre = 3
	}
	b.WriteString(s[:pre])
	for i := pre; i < len(s); i += 3 {
		b.WriteString(",")
		b.WriteString(s[i : i+3])
	}
	return b.String()
}

func trunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n <= 1 {
		return s[:n]
	}
	return s[:n-1] + "…"
}
