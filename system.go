package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// run returns combined output + error. runQ discards output.
func run(name string, args ...string) (string, error) {
	out, err := exec.Command(name, args...).CombinedOutput()
	return string(out), err
}

func runQ(name string, args ...string) error {
	return exec.Command(name, args...).Run()
}

func have(cmd string) bool {
	_, err := exec.LookPath(cmd)
	return err == nil
}

// ---- dependency auto-install (Kali-native) -----------------------------

func aptInstall(cfg *Config, pkgs ...string) error {
	if cfg.NoInstall {
		return errors.New("auto-install disabled (--no-install)")
	}
	if !have("apt-get") {
		return errors.New("no apt-get on PATH")
	}
	fmt.Printf("[*] installing missing dependency: %s (use --no-install to skip)\n", strings.Join(pkgs, " "))
	env := append(os.Environ(), "DEBIAN_FRONTEND=noninteractive")
	up := exec.Command("apt-get", "update", "-qq")
	up.Env = env
	_ = up.Run()
	ins := exec.Command("apt-get", append([]string{"install", "-y", "-qq"}, pkgs...)...)
	ins.Env = env
	return ins.Run()
}

// needCmd ensures cmd is present, apt-installing pkg if missing, else dies.
func needCmd(cfg *Config, cmd, pkg string) {
	if have(cmd) {
		return
	}
	_ = aptInstall(cfg, pkg)
	if !have(cmd) {
		die("missing '%s' — install package '%s' manually (apt/pipx)", cmd, pkg)
	}
}

// ---- iptables / ipset --------------------------------------------------

func ipsetCount(cfg *Config) int {
	out, _ := run("ipset", "list", cfg.SetName)
	n := 0
	for _, ln := range strings.Split(out, "\n") {
		if ln != "" && ln[0] >= '0' && ln[0] <= '9' {
			n++
		}
	}
	return n
}

// transparent nat REDIRECT for in-scope dst on the configured ports (action = -A|-D).
func iptablesRedirect(cfg *Config, action string) error {
	return runQ("iptables", "-t", "nat", action, "OUTPUT",
		"-m", "set", "--match-set", cfg.SetName, "dst",
		"-p", "tcp", "-m", "multiport", "--dports", cfg.Ports,
		"-m", "owner", "!", "--uid-owner", cfg.ProxyUser,
		"-j", "REDIRECT", "--to-ports", cfg.ProxyPort)
}

// coarse new-connection-rate DROP for in-scope dst, ALL tcp ports (action = -A|-D).
func iptablesCoarse(cfg *Config, action string) error {
	return runQ("iptables", action, "OUTPUT",
		"-m", "set", "--match-set", cfg.SetName, "dst",
		"-p", "tcp", "--syn",
		"-m", "hashlimit", "--hashlimit-name", cfg.HLName, "--hashlimit-mode", "dstip",
		"--hashlimit-above", cfg.Rate+"/second", "--hashlimit-burst", cfg.Rate,
		"-j", "DROP")
}

// hybrid companion to the proxy: transparent nat REDIRECT for in-scope dst on every NON-HTTP
// port (i.e. tcp ports NOT in --ports, which mitmproxy handles) to our protocol-blind TCP
// pacer, which QUEUES (delays) connections instead of dropping — lossless conn/s cap for
// FTP/SSH/SMB/RDP/... brute against a scoped IP. The pacer's own upstream dials carry SO_MARK
// pacerMark, excluded here (mark match) so they go direct and never loop. action = -A|-D.
func iptablesNonHTTPRedirect(cfg *Config, action string) error {
	return runQ("iptables", "-t", "nat", action, "OUTPUT",
		"-m", "set", "--match-set", cfg.SetName, "dst",
		"-p", "tcp", "-m", "multiport", "!", "--dports", cfg.Ports,
		"-m", "mark", "!", "--mark", strconv.Itoa(pacerMark),
		"-j", "REDIRECT", "--to-ports", cfg.TCPPort)
}

// removeRules deletes every OUTPUT rule referencing our set, whatever ports/rate/uid
// it used — so `down` reverts a run set up with any flags. nat=true for the nat table.
func removeRules(cfg *Config, nat bool) {
	var base []string
	if nat {
		base = []string{"-t", "nat"}
	}
	out, _ := run("iptables", append(append([]string{}, base...), "-S", "OUTPUT")...)
	needle := "--match-set " + cfg.SetName + " dst"
	for _, ln := range strings.Split(out, "\n") {
		if !strings.Contains(ln, needle) {
			continue
		}
		f := strings.Fields(ln) // "-A OUTPUT -m set ..."
		if len(f) < 2 || f[0] != "-A" {
			continue
		}
		del := append(append([]string{}, base...), "-D")
		del = append(del, f[1:]...) // OUTPUT -m set ...
		_ = runQ("iptables", del...)
	}
}

// ---- sysctl ------------------------------------------------------------

func sysctlGet(key string) string {
	out, _ := run("sysctl", "-n", key)
	return strings.TrimSpace(out)
}

func sysctlSet(key, val string) {
	_ = runQ("sysctl", "-q", "-w", key+"="+val)
}

// ---- proxy user --------------------------------------------------------

func ensureUser(name, home string) error {
	if _, err := user.Lookup(name); err == nil {
		return nil
	}
	fmt.Printf("[*] creating user '%s'\n", name)
	return runQ("useradd", "-r", "-s", "/usr/sbin/nologin", "-d", home, name)
}

func lookupUIDGID(name string) (uint32, uint32, error) {
	u, err := user.Lookup(name)
	if err != nil {
		return 0, 0, err
	}
	uid, _ := strconv.Atoi(u.Uid)
	gid, _ := strconv.Atoi(u.Gid)
	return uint32(uid), uint32(gid), nil
}

// ---- process helpers ---------------------------------------------------

func processAlive(pid int) bool {
	return syscall.Kill(pid, 0) == nil
}

// killPidfile reads a pid from path, signals it, and removes the file. When graceful,
// it sends SIGTERM, waits up to 3s, then SIGKILL (so `down` returns only once dead).
func killPidfile(path string, graceful bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return
	}
	os.Remove(path)
	pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil || pid <= 1 || !processAlive(pid) {
		return
	}
	_ = syscall.Kill(pid, syscall.SIGTERM)
	if !graceful {
		return
	}
	for i := 0; i < 6; i++ {
		if !processAlive(pid) {
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
	_ = syscall.Kill(pid, syscall.SIGKILL)
}

// pkillTag SIGTERMs any process whose cmdline contains tag (fallback for a
// refresher whose pidfile was lost). Never signals ourselves.
func pkillTag(tag string) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return
	}
	self := os.Getpid()
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid == self {
			continue
		}
		b, err := os.ReadFile("/proc/" + e.Name() + "/cmdline")
		if err != nil {
			continue
		}
		if strings.Contains(strings.ReplaceAll(string(b), "\x00", " "), tag) {
			_ = syscall.Kill(pid, syscall.SIGTERM)
		}
	}
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

func copyFile(src, dst string) error {
	b, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, b, 0644)
}
