package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// parseScopeLine normalizes one raw scope line. Returns ("", _) to skip.
// isHost=false means the entry is a literal IP or CIDR (added verbatim to ipset).
func parseScopeLine(raw string) (entry string, isHost bool) {
	line := raw
	if i := strings.IndexByte(line, '#'); i >= 0 {
		line = line[:i]
	}
	line = strings.ToLower(strings.TrimSpace(line))
	line = strings.Map(func(r rune) rune {
		if r == ' ' || r == '\t' {
			return -1
		}
		return r
	}, line)
	if line == "" {
		return "", false
	}
	if i := strings.Index(line, "://"); i >= 0 { // pasted URL -> drop scheme
		line = line[i+3:]
	}
	if isIPorCIDR(line) { // keep the mask for CIDRs
		return line, false
	}
	if strings.HasPrefix(line, "*") {
		fmt.Fprintf(os.Stderr, "!! wildcard %q not resolvable — list explicit hosts or a CIDR\n", strings.TrimSpace(raw))
		return "", false
	}
	if i := strings.IndexByte(line, '/'); i >= 0 { // strip path
		line = line[:i]
	}
	if i := strings.IndexByte(line, ':'); i >= 0 { // strip port
		line = line[:i]
	}
	line = strings.TrimSuffix(line, ".")
	if line == "" {
		return "", false
	}
	return line, true
}

func isIPorCIDR(s string) bool {
	if _, _, err := net.ParseCIDR(s); err == nil {
		return true
	}
	return net.ParseIP(s) != nil
}

func ipsetAddV4(cfg *Config, host string) []string {
	ips, err := net.LookupIP(host)
	if err != nil {
		return nil
	}
	var added []string
	for _, ip := range ips {
		if v4 := ip.To4(); v4 != nil {
			if runQ("ipset", "add", cfg.SetName, v4.String(), "-exist") == nil {
				added = append(added, v4.String())
			}
		}
	}
	return added
}

// loadScope populates the ipset from the scope file, writes the cleaned scope.txt
// the addon reads, and returns the hostnames (for the auto-refresher).
func loadScope(cfg *Config, file string) (domains []string, err error) {
	needCmd(cfg, "ipset", "ipset")
	needCmd(cfg, "iptables", "iptables")
	if err := runQ("ipset", "create", cfg.SetName, "hash:net", "-exist"); err != nil {
		return nil, fmt.Errorf("ipset create: %w", err)
	}
	_ = runQ("ipset", "flush", cfg.SetName)

	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var cleaned []string
	seen := map[string]bool{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		entry, isHost := parseScopeLine(sc.Text())
		if entry == "" {
			continue
		}
		if !isHost {
			_ = runQ("ipset", "add", cfg.SetName, entry, "-exist")
			cleaned = append(cleaned, entry)
			continue
		}
		added := ipsetAddV4(cfg, entry)
		if len(added) == 0 {
			fmt.Fprintf(os.Stderr, "!! cannot resolve %q\n", entry)
			continue
		}
		if !seen[entry] {
			domains = append(domains, entry)
			cleaned = append(cleaned, entry)
			seen[entry] = true
		}
		for _, ip := range added {
			fmt.Printf("   %s -> %s\n", entry, ip)
		}
	}

	_ = os.MkdirAll(cfg.ConfDir, 0755)
	_ = os.WriteFile(cfg.ConfDir+"/scope.txt", []byte(strings.Join(cleaned, "\n")+"\n"), 0644)
	fmt.Printf("[*] ipset '%s': %d entries\n", cfg.SetName, ipsetCount(cfg))
	return domains, nil
}

// startRefresher launches a detached re-run of self that keeps the ipset fresh as a
// target's load-balancer / DNS rotates IPs. Skipped for pure IP/CIDR scope.
func startRefresher(cfg *Config, domains []string) {
	if cfg.Refresh == 0 || len(domains) == 0 {
		return
	}
	_ = os.MkdirAll(cfg.ConfDir, 0755)
	_ = os.WriteFile(cfg.ConfDir+"/domains.txt", []byte(strings.Join(domains, "\n")+"\n"), 0644)

	self, err := os.Executable()
	if err != nil {
		return
	}
	cmd := exec.Command(self, "__refresh", cfg.Tag, strconv.Itoa(cfg.Refresh), cfg.SetName, cfg.ConfDir)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		return
	}
	_ = os.WriteFile(cfg.ConfDir+"/.refresh.pid", []byte(strconv.Itoa(cmd.Process.Pid)), 0644)
	_ = cmd.Process.Release()
	fmt.Printf("[*] auto-refresh scope every %ds to track LB/DNS IP rotation (--refresh 0 disables)\n", cfg.Refresh)
}

// runRefresher is the detached loop. args: __refresh <tag> <interval> <setName> <confDir>
func runRefresher(args []string) {
	if len(args) < 5 {
		return
	}
	interval := atoi(args[2])
	if interval <= 0 {
		interval = defRefresh
	}
	setName, confDir := args[3], args[4]
	for {
		time.Sleep(time.Duration(interval) * time.Second)
		data, err := os.ReadFile(confDir + "/domains.txt")
		if err != nil {
			continue
		}
		for _, d := range strings.Split(string(data), "\n") {
			d = strings.TrimSpace(d)
			if d == "" {
				continue
			}
			ips, err := net.LookupIP(d)
			if err != nil {
				continue
			}
			for _, ip := range ips {
				if v4 := ip.To4(); v4 != nil {
					_ = runQ("ipset", "add", setName, v4.String(), "-exist")
				}
			}
		}
	}
}
