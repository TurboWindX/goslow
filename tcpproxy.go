package main

import (
	"encoding/json"
	"io"
	"log"
	"net"
	"os"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// plog is the pacer's diagnostic log (/tmp/goslow-tcpproxy.log); nil until startTCPPacer runs.
// It records only startup + failures (a busy brute would make per-connection logging useless).
var plog *log.Logger

// tcpStatsFile is the live snapshot the pacer flushes every second; `goslow top` / `goslow status`
// read it (they run as a separate process, so shared memory is not an option — a file is).
const tcpStatsFile = "/tmp/goslow-tcp-stats.json"

// pstats are live pacer counters (atomics for the scalars; dsts under its own mutex). Read by the
// per-second statsWriter, never by the hot path except to increment. Global so handleTCP/pacedCopy
// can bump them without threading a pointer through every call.
var pstats = struct {
	active     int64 // connections currently spliced
	waiting    int64 // connections blocked on the bucket = queue depth
	totalConns int64 // cumulative connections accepted
	bytesPaced int64 // cumulative client->server bytes forwarded (paced)
	mu         sync.Mutex
	dsts       map[string]int64 // per-destination connection counts (for "top targets")
}{dsts: map[string]int64{}}

func noteDst(dst string) {
	pstats.mu.Lock()
	pstats.dsts[dst]++
	pstats.mu.Unlock()
}

// SO_ORIGINAL_DST recovers the pre-REDIRECT destination of a connection nat'd to us.
const soOriginalDst = 80

// pacerMark tags the pacer's OWN upstream sockets (SO_MARK) so the non-HTTP transparent
// redirect can exclude them (iptables -m mark ! --mark) and never loop back into us. Using a
// mark instead of a uid lets the pacer run in-process as root — no re-exec, no dependence on
// the binary living somewhere the proxy user can traverse.
const pacerMark = 0x2a

// markDialer dials upstream with pacerMark set on the socket, so those packets skip the redirect.
var markDialer = &net.Dialer{
	Timeout: 10 * time.Second,
	Control: func(_, _ string, c syscall.RawConn) error {
		var serr error
		if err := c.Control(func(fd uintptr) {
			serr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, pacerMark)
		}); err != nil {
			return err
		}
		return serr
	},
}

// startTCPPacer binds the protocol-blind TCP pacer for NON-HTTP in-scope ports, then serves it
// in a background goroutine. Binding synchronously means the redirect is only installed once the
// listener is up. Every redirected connection is accepted, its real destination recovered
// (SO_ORIGINAL_DST), then QUEUED on a shared token bucket before we dial upstream — pacing new
// connections to the rate without dropping one (contrast --coarse, which DROPs SYNs). The pacer
// lives in the (root) proxy process, so it dies with it on teardown.
func startTCPPacer(cfg *Config) error {
	rate, _ := strconv.Atoi(cfg.Rate)
	if rate <= 0 {
		rate = defRate
	}
	if lf, e := os.OpenFile("/tmp/goslow-tcpproxy.log", os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644); e == nil {
		plog = log.New(lf, "", log.Ltime|log.Lmicroseconds)
	}
	b := &bucket{tokens: float64(rate), max: float64(rate), rate: float64(rate), last: time.Now()}
	ln, err := net.Listen("tcp", "0.0.0.0:"+cfg.TCPPort)
	if err != nil {
		return err
	}
	if plog != nil {
		plog.Printf("pacer listening :%s rate=%d/s burst=%d", cfg.TCPPort, rate, rate)
	}
	go statsWriter(b)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				continue
			}
			tc, ok := c.(*net.TCPConn)
			if !ok {
				c.Close()
				continue
			}
			go handleTCP(tc, b)
		}
	}()
	return nil
}

func handleTCP(client *net.TCPConn, b *bucket) {
	defer client.Close()
	dst, err := originalDst(client)
	if err != nil || dst == "" {
		if plog != nil {
			plog.Printf("originalDst FAIL from %v: dst=%q err=%v", client.RemoteAddr(), dst, err)
		}
		return
	}
	atomic.AddInt64(&pstats.totalConns, 1)
	noteDst(dst)
	// pace the new CONNECTION: block until a token frees up (lossless). Count the wait so the
	// live view shows real queue depth (this conn-level acquire, not the per-chunk data pacing).
	atomic.AddInt64(&pstats.waiting, 1)
	b.acquire()
	atomic.AddInt64(&pstats.waiting, -1)
	up, err := markDialer.Dial("tcp", dst)
	if err != nil {
		if plog != nil {
			plog.Printf("dial FAIL -> %s: %v", dst, err)
		}
		return
	}
	atomic.AddInt64(&pstats.active, 1)
	defer atomic.AddInt64(&pstats.active, -1)
	splice(client, up.(*net.TCPConn), b)
}

// splice pumps bytes both ways until either side closes, propagating half-close. The
// client->server direction is PACED on the shared bucket (one token per write), so tools that
// reuse a connection to pipeline many requests/attempts (hydra -t N, DB brutes) are throttled
// per-request too — not just per-connection. server->client is not gated: we cap what the
// attacker SENDS, not what the target replies.
func splice(client, up *net.TCPConn, b *bucket) {
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(client, up); _ = client.CloseWrite(); done <- struct{}{} }()
	go func() { pacedCopy(up, client, b); _ = up.CloseWrite(); done <- struct{}{} }()
	<-done
	<-done
	client.Close()
	up.Close()
}

// pacedCopy copies src->dst, spending one token per chunk forwarded so the client's request
// rate is capped at ~rate/s. Reads are not gated (idle connections cost nothing); a token is
// taken only when there's data to forward, and backpressure holds the client until it's granted.
func pacedCopy(dst, src *net.TCPConn, b *bucket) {
	buf := make([]byte, 16384)
	for {
		n, rerr := src.Read(buf)
		if n > 0 {
			b.acquire()
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return
			}
			atomic.AddInt64(&pstats.bytesPaced, int64(n))
		}
		if rerr != nil {
			return
		}
	}
}

// originalDst returns the connection's pre-REDIRECT destination (getsockopt SO_ORIGINAL_DST).
func originalDst(c *net.TCPConn) (string, error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return "", err
	}
	var addr string
	var operr error
	if err := raw.Control(func(fd uintptr) {
		mreq, e := syscall.GetsockoptIPv6Mreq(int(fd), syscall.IPPROTO_IP, soOriginalDst)
		if e != nil {
			operr = e
			return
		}
		// mreq.Multiaddr holds a struct sockaddr_in: family(2) port(2,BE) addr(4).
		ip := net.IPv4(mreq.Multiaddr[4], mreq.Multiaddr[5], mreq.Multiaddr[6], mreq.Multiaddr[7])
		port := int(mreq.Multiaddr[2])<<8 | int(mreq.Multiaddr[3])
		addr = net.JoinHostPort(ip.String(), strconv.Itoa(port))
	}); err != nil {
		return "", err
	}
	return addr, operr
}

// bucket is a token bucket: acquire() blocks (queues) until a token is available, pacing to
// `rate` tokens/sec with a burst of `max`. Nothing is dropped — callers wait their turn.
type bucket struct {
	mu     sync.Mutex
	tokens float64
	max    float64
	rate   float64
	last   time.Time
}

func (b *bucket) acquire() {
	for {
		b.mu.Lock()
		now := time.Now()
		b.tokens += now.Sub(b.last).Seconds() * b.rate
		b.last = now
		if b.tokens > b.max {
			b.tokens = b.max
		}
		if b.tokens >= 1 {
			b.tokens--
			b.mu.Unlock()
			return
		}
		wait := time.Duration((1 - b.tokens) / b.rate * float64(time.Second))
		b.mu.Unlock()
		if wait < time.Millisecond {
			wait = time.Millisecond
		}
		time.Sleep(wait)
	}
}

// snapshot returns a non-mutating view of the bucket (current tokens + capacity) for display.
func (b *bucket) snapshot() (tokens, max float64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	t := b.tokens + time.Since(b.last).Seconds()*b.rate
	if t > b.max {
		t = b.max
	}
	return t, b.max
}

// statsWriter flushes /tmp/goslow-tcp-stats.json once a second: current queue depth, active
// splices, effective conn/s (delta over the interval), paced bytes, and top destinations. The
// file is swapped atomically so `goslow top` never reads a half-written frame. Absent/stale =>
// the reader treats the pacer as not running.
func statsWriter(b *bucket) {
	lastConns := atomic.LoadInt64(&pstats.totalConns)
	lastT := time.Now()
	tmp := tcpStatsFile + ".tmp"
	for range time.Tick(time.Second) {
		now := time.Now()
		dt := now.Sub(lastT).Seconds()
		if dt <= 0 {
			dt = 1
		}
		conns := atomic.LoadInt64(&pstats.totalConns)
		connps := float64(conns-lastConns) / dt
		lastConns, lastT = conns, now

		// copy the top-N destinations out from under the lock
		pstats.mu.Lock()
		type kv struct {
			k string
			v int64
		}
		all := make([]kv, 0, len(pstats.dsts))
		for k, v := range pstats.dsts {
			all = append(all, kv{k, v})
		}
		pstats.mu.Unlock()
		sort.Slice(all, func(i, j int) bool { return all[i].v > all[j].v })
		top := map[string]int64{}
		for i := 0; i < len(all) && i < 8; i++ {
			top[all[i].k] = all[i].v
		}

		tokens, max := b.snapshot()
		snap := map[string]any{
			"ts":          float64(now.UnixNano()) / 1e9,
			"cap":         max,
			"tokens":      round2(tokens),
			"active":      atomic.LoadInt64(&pstats.active),
			"waiting":     atomic.LoadInt64(&pstats.waiting),
			"total_conns": conns,
			"bytes_paced": atomic.LoadInt64(&pstats.bytesPaced),
			"connps":      round2(connps),
			"dsts":        top,
		}
		data, err := json.Marshal(snap)
		if err != nil {
			continue
		}
		if err := os.WriteFile(tmp, data, 0644); err != nil {
			if plog != nil {
				plog.Printf("stats write FAIL: %v", err)
			}
			continue
		}
		_ = os.Rename(tmp, tcpStatsFile)
	}
}

func round2(f float64) float64 { return float64(int64(f*100+0.5)) / 100 }
