package main

// up/down/status: kernel WireGuard (wgctrl + netlink, iface tw0) or embedded Nebula (tun tw-neb0). One tunnel at a time.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"crypto/ecdh"

	"github.com/slackhq/nebula"
	ncert "github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/config"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const (
	wgIface    = "tw0"
	nebIface   = "tw-neb0"
	fwmark     = 51820 // exit: the tunnel's own UDP carries this mark and skips the exit table
	ladderWait = 8 * time.Second
	stale      = 3 * time.Minute
	renewEvery = 6 * time.Hour
)

var runDir = "/run/transwarp"

func hub() (string, error) {
	r, err := readState()
	if err != nil || !alive(r.PID) || r.HubIP == "" {
		return "", errors.New("no tunnel is up (transwarp up)")
	}
	return r.HubIP, nil
}

// runState is /run/transwarp/state.json (0644, no secrets): what status/services/beam/admin read from a running up.
type runState struct {
	PID         int       `json:"pid"`
	Name        string    `json:"name"`
	Kind        string    `json:"kind"`
	Iface       string    `json:"iface"`
	MeshIP      string    `json:"mesh_ip"`
	HubIP       string    `json:"hub_ip"`
	Exit        string    `json:"exit"`
	Skipped     []string  `json:"skipped_routes"`
	Endpoint    string    `json:"endpoint,omitempty"`
	Lighthouses []string  `json:"lighthouses,omitempty"`
	Hosts       []nebHost `json:"hosts,omitempty"` // Nebula hostmap, refreshed every 5 s
	Renewed     string    `json:"renewed,omitempty"`
	Expires     string    `json:"expires,omitempty"`
}

type nebHost struct {
	Name   string   `json:"name"`
	Addrs  []string `json:"addrs"`
	Remote string   `json:"remote"`
	Relays []string `json:"relays"`
}

func statePath() string { return filepath.Join(runDir, "state.json") }

func writeState(r runState) {
	os.MkdirAll(runDir, 0o755)
	b, _ := json.MarshalIndent(r, "", "  ")
	tmp := statePath() + ".tmp"
	if os.WriteFile(tmp, b, 0o644) == nil {
		os.Rename(tmp, statePath())
	}
}

func readState() (runState, error) {
	var r runState
	b, err := os.ReadFile(statePath())
	if err == nil {
		err = json.Unmarshal(b, &r)
	}
	return r, err
}

func alive(pid int) bool {
	err := syscall.Kill(pid, 0)
	return pid > 0 && (err == nil || err == syscall.EPERM) // EPERM: a root up seen by a normal user
}

// localAddrs are this machine's addresses on real links (with a hardware address: Ethernet, Wi-Fi), so other
// tunnels (tun/wg have none) don't count as "the LAN we are on".
func localAddrs() []netip.Addr {
	var out []netip.Addr
	ifs, _ := net.Interfaces()
	for _, ifi := range ifs {
		if len(ifi.HardwareAddr) == 0 || ifi.Flags&net.FlagLoopback != 0 {
			continue
		}
		as, _ := ifi.Addrs()
		for _, a := range as {
			if n, ok := a.(*net.IPNet); ok {
				if ip, ok := netip.AddrFromSlice(n.IP); ok && !ip.IsLinkLocalUnicast() {
					out = append(out, ip.Unmap())
				}
			}
		}
	}
	return out
}

// splitLAN drops routes that contain one of our own addresses: the machine is ON that network (e.g. the home LAN
// 10.0.0.0/16), so routing it into the tunnel would cut it off. Default routes are left to the exit logic.
func splitLAN(routes []netip.Prefix, local []netip.Addr) (keep, skip []netip.Prefix) {
	for _, r := range routes {
		on := false
		for _, a := range local {
			on = on || r.Bits() > 0 && r.Contains(a)
		}
		if on {
			skip = append(skip, r)
		} else {
			keep = append(keep, r)
		}
	}
	return keep, skip
}

func cmdUp(ctx context.Context, name, exit string) error {
	if os.Geteuid() != 0 {
		return errors.New("up needs root (sudo transwarp up)")
	}
	if r, err := readState(); err == nil && alive(r.PID) {
		return fmt.Errorf("%s is already up (pid %d): transwarp down first", r.Name, r.PID)
	}
	s, key, err := loadProfile(name)
	if err != nil {
		return err
	}
	local := localAddrs()
	if s.Kind == "nebula" {
		return upNebula(ctx, s, key, exit, local)
	}
	return upWG(ctx, s, key, exit, local)
}

// --- WireGuard ---

type wgPeer struct {
	Name, PublicKey, Endpoint string
	AllowedIPs                []netip.Prefix
}

type wgConf struct {
	Address []netip.Prefix
	DNS     []netip.Addr
	Peers   []wgPeer
}

// parseWG reads the server's wg-quick text (no PrivateKey; "# Name = x" comments name peers). PostUp etc. are ignored.
func parseWG(text string) (wgConf, error) {
	var c wgConf
	sect := ""
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if line[0] == '[' {
			if sect = strings.ToLower(line); sect == "[peer]" {
				c.Peers = append(c.Peers, wgPeer{})
			}
			continue
		}
		comment := line[0] == '#'
		k, v, ok := strings.Cut(strings.TrimLeft(line, "# "), "=")
		if !ok {
			continue
		}
		k, v = strings.ToLower(strings.TrimSpace(k)), strings.TrimSpace(v)
		var p *wgPeer
		if sect == "[peer]" {
			p = &c.Peers[len(c.Peers)-1]
		}
		switch {
		case p != nil && comment && k == "name":
			p.Name = v
		case comment:
		case sect == "[interface]" && k == "address":
			for _, s := range strings.Split(v, ",") {
				pf, err := netip.ParsePrefix(strings.TrimSpace(s))
				if err != nil {
					return c, err
				}
				c.Address = append(c.Address, pf)
			}
		case sect == "[interface]" && k == "dns":
			for _, s := range strings.Split(v, ",") {
				if a, err := netip.ParseAddr(strings.TrimSpace(s)); err == nil {
					c.DNS = append(c.DNS, a)
				}
			}
		case p != nil && k == "publickey":
			p.PublicKey = v
		case p != nil && k == "endpoint":
			p.Endpoint = v
		case p != nil && k == "allowedips":
			for _, s := range strings.Split(v, ",") {
				pf, err := netip.ParsePrefix(strings.TrimSpace(s))
				if err != nil {
					return c, err
				}
				p.AllowedIPs = append(p.AllowedIPs, pf.Masked())
			}
		}
	}
	if len(c.Address) == 0 || len(c.Peers) == 0 {
		return c, errors.New("config has no Address or no [Peer]")
	}
	return c, nil
}

// hub is the peer carrying a range (client range or default route), else the first.
func (c wgConf) hub() int {
	for i, p := range c.Peers {
		for _, a := range p.AllowedIPs {
			if a.Bits() < 32 {
				return i
			}
		}
	}
	return 0
}

func ipnet(p netip.Prefix) *net.IPNet {
	return &net.IPNet{IP: p.Addr().AsSlice(), Mask: net.CIDRMask(p.Bits(), p.Addr().BitLen())}
}

func upWG(ctx context.Context, s saved, key []byte, exit string, local []netip.Addr) error {
	c, err := parseWG(s.Config)
	if err != nil {
		return err
	}
	pk, err := wgtypes.ParseKey(strings.TrimSpace(string(key)))
	if err != nil {
		return fmt.Errorf("private key: %w", err)
	}
	h := c.hub()
	hasDefault := false
	var routes []netip.Prefix
	for _, p := range c.Peers {
		for _, a := range p.AllowedIPs {
			if a.Bits() == 0 {
				hasDefault = hasDefault || a.Addr().Is4()
			} else {
				routes = append(routes, a)
			}
		}
	}
	useExit := exit != "" && exit != "none"
	if useExit && !hasDefault {
		return errors.New("this client has no internet exit (gofire mesh client set NAME --exit=true, then re-enroll)")
	}
	if useExit && exit != "hub" && !strings.EqualFold(exit, c.Peers[h].Name) {
		return fmt.Errorf("WireGuard exits: only the hub (%s); use --exit %s", c.Peers[h].Name, c.Peers[h].Name)
	}
	routes, skipped := splitLAN(routes, local)
	if _, err := netlink.LinkByName(wgIface); err == nil {
		return fmt.Errorf("%s already exists (stale? transwarp down)", wgIface)
	}
	if err := netlink.LinkAdd(&netlink.Wireguard{LinkAttrs: netlink.LinkAttrs{Name: wgIface, MTU: 1420}}); err != nil {
		if errors.Is(err, unix.EOPNOTSUPP) {
			return errors.New("kernel WireGuard is not available (modprobe wireguard; Linux >= 5.6)")
		}
		return fmt.Errorf("create %s: %w", wgIface, err)
	}
	defer teardown()
	wg, err := wgctrl.New()
	if err != nil {
		return err
	}
	defer wg.Close()
	link, err := netlink.LinkByName(wgIface)
	if err != nil {
		return err
	}
	for _, a := range c.Address {
		if err := netlink.AddrAdd(link, &netlink.Addr{IPNet: ipnet(a)}); err != nil {
			return fmt.Errorf("address %s: %w", a, err)
		}
	}
	ka := 25 * time.Second
	cfg := wgtypes.Config{PrivateKey: &pk, ReplacePeers: true}
	if useExit {
		m := fwmark
		cfg.FirewallMark = &m
	}
	for _, p := range c.Peers {
		ppk, err := wgtypes.ParseKey(p.PublicKey)
		if err != nil {
			return fmt.Errorf("peer %s: %w", p.Name, err)
		}
		pc := wgtypes.PeerConfig{PublicKey: ppk, PersistentKeepaliveInterval: &ka, ReplaceAllowedIPs: true}
		for _, a := range p.AllowedIPs {
			pc.AllowedIPs = append(pc.AllowedIPs, *ipnet(a))
		}
		if p.Endpoint != "" {
			pc.Endpoint, _ = net.ResolveUDPAddr("udp", p.Endpoint)
		}
		cfg.Peers = append(cfg.Peers, pc)
	}
	if err := wg.ConfigureDevice(wgIface, cfg); err != nil {
		return err
	}
	if err := netlink.LinkSetUp(link); err != nil {
		return err
	}
	var owned []netip.Prefix
	for _, r := range routes {
		// never steal a route another interface owns (another VPN, a second tunnel): only our own traffic uses it
		if err := netlink.RouteAdd(&netlink.Route{LinkIndex: link.Attrs().Index, Dst: ipnet(r), Scope: netlink.SCOPE_LINK}); errors.Is(err, unix.EEXIST) {
			fmt.Printf("route %s: already routed by %s; only transwarp's own traffic uses %s for it\n", r, routedBy(r), wgIface)
			owned = append(owned, r)
		} else if err != nil {
			return fmt.Errorf("route %s: %w", r, err)
		}
	}
	if err := sourceRoutes(link, c.Address[0].Addr(), owned); err != nil {
		return fmt.Errorf("source routes: %w", err)
	}
	rs := runState{PID: os.Getpid(), Name: s.Name, Kind: s.Kind, Iface: wgIface, MeshIP: c.Address[0].Addr().String(), Exit: "none"}
	logSkipped(skipped, &rs)
	if useExit {
		if err := exitRouting(link); err != nil {
			return fmt.Errorf("exit routing: %w", err)
		}
		rs.Exit = c.Peers[h].Name
	}
	if len(c.DNS) > 0 {
		rs.HubIP = c.DNS[0].String()
		setDNS(wgIface, c.DNS[0])
	}
	if s.ExpiresAt != nil {
		rs.Expires = *s.ExpiresAt
	}
	// Endpoint ladder over the UDP rungs. ponytail: the wss:// relay rung is skipped (needs the WS bridge from
	// gofire's meshup); add it when a desktop sits behind UDP-blocking networks.
	var ladder []string
	for _, e := range s.Endpoints {
		if !strings.Contains(e, "://") {
			ladder = append(ladder, e)
		}
	}
	if len(ladder) == 0 && c.Peers[h].Endpoint != "" {
		ladder = []string{c.Peers[h].Endpoint}
	}
	hubKey, _ := wgtypes.ParseKey(c.Peers[h].PublicKey)
	idx, setAt := 0, time.Now()
	setEndpoint := func(i int) {
		idx, setAt = i, time.Now()
		if ua, err := net.ResolveUDPAddr("udp", ladder[i]); err == nil {
			wg.ConfigureDevice(wgIface, wgtypes.Config{Peers: []wgtypes.PeerConfig{{PublicKey: hubKey, UpdateOnly: true, Endpoint: ua}}})
		}
		rs.Endpoint = ladder[i]
		writeState(rs)
	}
	if len(ladder) > 0 {
		setEndpoint(0)
	}
	writeState(rs)
	fmt.Printf("%s up as %s (%s), exit %s. Ctrl-C or 'transwarp down' to stop.\n", wgIface, s.Name, rs.MeshIP, rs.Exit)
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
		if len(ladder) < 2 {
			continue
		}
		dev, err := wg.Device(wgIface)
		if err != nil {
			return fmt.Errorf("%s vanished: %w", wgIface, err)
		}
		var hs time.Time
		for _, p := range dev.Peers {
			if p.PublicKey == hubKey {
				hs = p.LastHandshakeTime
			}
		}
		if hs.After(setAt) && time.Since(hs) > stale || !hs.After(setAt) && time.Since(setAt) > ladderWait {
			setEndpoint((idx + 1) % len(ladder))
			fmt.Printf("%s trying %s\n", time.Now().Format(time.TimeOnly), ladder[idx])
		}
	}
}

func logSkipped(skipped []netip.Prefix, rs *runState) {
	for _, r := range skipped {
		fmt.Printf("route %s skipped: this machine is on that network\n", r)
		rs.Skipped = append(rs.Skipped, r.String())
	}
}

// routedBy names the link that already has a main-table route for exactly p, or "".
func routedBy(p netip.Prefix) string {
	rs, err := netlink.RouteListFiltered(netlink.FAMILY_ALL, &netlink.Route{Dst: ipnet(p), Table: unix.RT_TABLE_MAIN}, netlink.RT_FILTER_DST|netlink.RT_FILTER_TABLE)
	if err != nil || len(rs) == 0 {
		return ""
	}
	if l, err := netlink.LinkByIndex(rs[0].LinkIndex); err == nil {
		return l.Attrs().Name
	}
	return "another link"
}

const srcTable = fwmark + 1

// sourceRoutes keeps prefixes that another link owns reachable for OUR traffic only: "from <src> lookup srcTable"
// with those prefixes via link. transwarp's own sockets (hub calls, beam) bind src, so they work without taking
// the route away from the other VPN.
func sourceRoutes(link netlink.Link, src netip.Addr, prefixes []netip.Prefix) error {
	if len(prefixes) == 0 {
		return nil
	}
	for _, p := range prefixes {
		if err := netlink.RouteReplace(&netlink.Route{LinkIndex: link.Attrs().Index, Dst: ipnet(p), Table: srcTable, Scope: netlink.SCOPE_LINK}); err != nil {
			return err
		}
	}
	r := srcRule(src)
	if err := netlink.RuleAdd(r); err != nil && !errors.Is(err, unix.EEXIST) {
		return err
	}
	return nil
}

func srcRule(src netip.Addr) *netlink.Rule {
	r := netlink.NewRule()
	r.Src, r.Table, r.Priority = ipnet(netip.PrefixFrom(src, 32)), srcTable, 32000
	return r
}

// exitRouting is wg-quick's full tunnel: default route in table fwmark, "not fwmark -> that table", and "main,
// suppress_prefixlength 0" so LAN and other specific routes keep working. v6 goes into the tunnel too (a sink:
// the hub has no v6 exit, so nothing leaks).
func exitRouting(link netlink.Link) error {
	for _, fam := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		dst := netip.MustParsePrefix("0.0.0.0/0")
		if fam == netlink.FAMILY_V6 {
			dst = netip.MustParsePrefix("::/0")
		}
		if err := netlink.RouteReplace(&netlink.Route{LinkIndex: link.Attrs().Index, Dst: ipnet(dst), Table: fwmark, Scope: netlink.SCOPE_LINK, Family: fam}); err != nil {
			return err
		}
		for _, r := range exitRules(fam) {
			if err := netlink.RuleAdd(r); err != nil && !errors.Is(err, unix.EEXIST) {
				return err
			}
		}
	}
	return nil
}

func exitRules(fam int) []*netlink.Rule {
	notMark := netlink.NewRule()
	notMark.Family, notMark.Mark, notMark.Invert, notMark.Table, notMark.Priority = fam, fwmark, true, fwmark, 32760
	suppress := netlink.NewRule()
	suppress.Family, suppress.Table, suppress.SuppressPrefixlen, suppress.Priority = fam, unix.RT_TABLE_MAIN, 0, 32759
	return []*netlink.Rule{suppress, notMark}
}

// setDNS points systemd-resolved at the hub for ~mesh on the link; deleting the link reverts it.
func setDNS(iface string, hub netip.Addr) {
	if _, err := exec.LookPath("resolvectl"); err != nil {
		fmt.Printf("warning: no systemd-resolved (resolvectl): *.mesh names won't resolve; use %s as DNS for them\n", hub)
		return
	}
	for _, a := range [][]string{{"dns", iface, hub.String()}, {"domain", iface, "~mesh"}} {
		if b, err := exec.Command("resolvectl", a...).CombinedOutput(); err != nil {
			fmt.Printf("warning: resolvectl %s: %v %s\n", strings.Join(a, " "), err, strings.TrimSpace(string(b)))
			return
		}
	}
}

// teardown removes whatever up created; safe on a half-built or missing tunnel.
func teardown() {
	for _, fam := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		for _, r := range exitRules(fam) {
			netlink.RuleDel(r) // missing = fine
		}
	}
	if rules, err := netlink.RuleList(netlink.FAMILY_V4); err == nil {
		for _, r := range rules {
			if r.Table == srcTable {
				netlink.RuleDel(&r)
			}
		}
	}
	for _, n := range []string{wgIface, nebIface} {
		if l, err := netlink.LinkByName(n); err == nil {
			exec.Command("resolvectl", "revert", n).Run()
			netlink.LinkDel(l)
		}
	}
	if r, err := readState(); err == nil && (r.PID == os.Getpid() || !alive(r.PID)) {
		os.Remove(statePath())
	}
	fmt.Println("tunnel down")
}

func cmdDown() error {
	if os.Geteuid() != 0 {
		return errors.New("down needs root (sudo transwarp down)")
	}
	if r, err := readState(); err == nil && alive(r.PID) && r.PID != os.Getpid() {
		syscall.Kill(r.PID, syscall.SIGTERM)
		for i := 0; i < 50 && alive(r.PID); i++ {
			time.Sleep(200 * time.Millisecond)
		}
		if alive(r.PID) {
			return fmt.Errorf("pid %d did not stop", r.PID)
		}
	}
	teardown() // stale leftovers (crash, kill -9)
	return nil
}

// --- Nebula ---

type nebLighthouse struct {
	Name      string   `json:"name"`
	IP        string   `json:"ip"`
	Endpoints []string `json:"endpoints"`
}

type nebRoute struct {
	CIDR string `json:"cidr"`
	Via  string `json:"via"`
}

type nebExit struct {
	Name string `json:"name"`
	IP   string `json:"ip"`
}

// nebProfile is gofire's Nebula profile (enroll/renew response "nebula").
type nebProfile struct {
	IP              string           `json:"ip"`
	IP6             string           `json:"ip6"`
	CAPEM           string           `json:"ca_pem"`
	CertPEM         string           `json:"cert_pem"`
	Lighthouses     []nebLighthouse  `json:"lighthouses"`
	Relays          []string         `json:"relays"`
	Routes          []nebRoute       `json:"routes"`
	DNS             string           `json:"dns"`
	PreferredRanges []string         `json:"preferred_ranges"`
	FirewallInbound []map[string]any `json:"firewall_inbound"`
	Exits           []nebExit        `json:"exits"`
}

// exitIP resolves --exit for Nebula: "" = no exit; NAME or ip from exits (the hub = the profile's default route).
func (p nebProfile) exitIP(exit string) (string, error) {
	if exit == "" || exit == "none" {
		return "", nil
	}
	hubVia := ""
	for _, r := range p.Routes {
		if r.CIDR == "0.0.0.0/0" {
			hubVia = r.Via
		}
	}
	if hubVia == "" {
		return "", errors.New("this client has no internet exit (gofire mesh client set NAME --exit=true, then renew)")
	}
	for _, e := range p.Exits {
		if strings.EqualFold(e.Name, exit) || e.IP == exit {
			return e.IP, nil
		}
	}
	if exit == "hub" {
		return hubVia, nil
	}
	var names []string
	for _, e := range p.Exits {
		names = append(names, e.Name)
	}
	return "", fmt.Errorf("unknown exit %q (offered: %s)", exit, strings.Join(names, ", "))
}

// nebulaConfig renders the member config like the app's Nebula.yaml() (role client), as JSON (= valid YAML).
// exitIP "" drops the default route; skip lists routes not installed in the kernel (LAN we are on). With an exit the
// default route is not installed either: exitRouting's policy routing sends it into the tun, Nebula's own UDP carries
// so_mark and bypasses it.
func nebulaConfig(p nebProfile, keyPEM, exitIP string, skip map[string]bool) (string, error) {
	relays := p.Relays
	if len(relays) == 0 && len(p.Lighthouses) > 0 {
		relays = []string{p.Lighthouses[0].IP} // pre-Phase-36 gofire: the hub
	}
	shm := map[string][]string{}
	hosts := []string{}
	for _, lh := range p.Lighthouses {
		shm[lh.IP] = lh.Endpoints
		hosts = append(hosts, lh.IP)
	}
	routes := []any{}
	for _, r := range p.Routes {
		via, install := r.Via, !skip[r.CIDR]
		if r.CIDR == "0.0.0.0/0" {
			if exitIP == "" {
				continue
			}
			via, install = exitIP, false
		}
		routes = append(routes, map[string]any{"route": r.CIDR, "via": via, "install": install})
	}
	anyRule := map[string]any{"port": "any", "proto": "any", "host": "any"}
	inbound := []any{anyRule}
	if len(p.FirewallInbound) > 0 {
		inbound = nil
		for _, r := range p.FirewallInbound {
			inbound = append(inbound, r)
		}
	}
	pkiC := map[string]any{"ca": p.CAPEM, "cert": p.CertPEM, "key": keyPEM, "disconnect_invalid": true}
	if p.IP6 != "" {
		pkiC["initiating_version"] = 2 // a v1-only cert must stay on v1
	}
	listen := map[string]any{"host": "0.0.0.0", "port": 0}
	if exitIP != "" {
		listen["so_mark"] = fwmark
	}
	cfg := map[string]any{
		"pki":             pkiC,
		"static_host_map": shm,
		"lighthouse":      map[string]any{"am_lighthouse": false, "hosts": hosts},
		"listen":          listen,
		"punchy":          map[string]any{"punch": true, "respond": true},
		"relay":           map[string]any{"use_relays": true, "relays": relays},
		"tun":             map[string]any{"dev": nebIface, "mtu": 1300, "unsafe_routes": routes},
		"firewall":        map[string]any{"outbound": []any{anyRule}, "inbound": inbound},
		"logging":         map[string]any{"level": "warning"},
	}
	if len(p.PreferredRanges) > 0 {
		cfg["preferred_ranges"] = p.PreferredRanges
	}
	b, err := json.Marshal(cfg)
	return string(b), err
}

func nebPublicKey(keyPEM []byte) (string, error) {
	raw, _, _, err := ncert.UnmarshalPrivateKeyFromPEM(keyPEM)
	if err != nil {
		return "", err
	}
	k, err := ecdh.X25519().NewPrivateKey(raw)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(k.PublicKey().Bytes()), nil
}

func upNebula(ctx context.Context, s saved, key []byte, exit string, local []netip.Addr) error {
	var p nebProfile
	if err := json.Unmarshal(s.Nebula, &p); err != nil {
		return err
	}
	exitIP, err := p.exitIP(exit)
	if err != nil {
		return err
	}
	var all []netip.Prefix
	for _, r := range p.Routes {
		if pf, err := netip.ParsePrefix(r.CIDR); err == nil {
			all = append(all, pf)
		}
	}
	_, skipped := splitLAN(all, local)
	skip := map[string]bool{}
	for _, r := range skipped {
		skip[r.String()] = true
	}
	var owned []netip.Prefix
	for _, r := range all {
		if dev := routedBy(r); dev != "" && r.Bits() > 0 && !skip[r.String()] {
			fmt.Printf("route %s: already routed by %s; only transwarp's own traffic uses %s for it\n", r, dev, nebIface)
			skip[r.String()] = true
			owned = append(owned, r)
		}
	}
	if n, err := netip.ParsePrefix(p.IP); err == nil {
		if dev := routedBy(n.Masked()); dev != "" {
			fmt.Printf("warning: %s is already routed by %s (another Nebula?); %s takes it over while up\n", n.Masked(), dev, nebIface)
			// Nebula always installs its network route; give the other link its route back afterwards
			if old, err := netlink.RouteListFiltered(netlink.FAMILY_V4, &netlink.Route{Dst: ipnet(n.Masked()), Table: unix.RT_TABLE_MAIN}, netlink.RT_FILTER_DST|netlink.RT_FILTER_TABLE); err == nil && len(old) > 0 {
				defer func(r netlink.Route) {
					if _, err := netlink.LinkByIndex(r.LinkIndex); err == nil {
						netlink.RouteReplace(&r)
					}
				}(old[0])
			}
		}
	}
	conf, err := nebulaConfig(p, string(key), exitIP, skip)
	if err != nil {
		return err
	}
	if _, err := netlink.LinkByName(nebIface); err == nil {
		return fmt.Errorf("%s already exists (stale? transwarp down)", nebIface)
	}
	l := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	c := config.NewC(l)
	if err := c.LoadString(conf); err != nil {
		return err
	}
	ctl, err := nebula.Main(c, false, "transwarp-"+version, l, nil)
	if err != nil {
		return err
	}
	if err := ctl.Start(); err != nil {
		return err
	}
	defer teardown()
	defer ctl.Stop()
	ip, _, _ := strings.Cut(p.IP, "/")
	rs := runState{PID: os.Getpid(), Name: s.Name, Kind: s.Kind, Iface: nebIface, MeshIP: ip, HubIP: p.DNS, Exit: "none"}
	for _, lh := range p.Lighthouses {
		rs.Lighthouses = append(rs.Lighthouses, lh.IP)
	}
	if s.ExpiresAt != nil {
		rs.Expires = *s.ExpiresAt
	}
	logSkipped(skipped, &rs)
	if link, err := netlink.LinkByName(nebIface); err != nil {
		return err
	} else if err := sourceRoutes(link, netip.MustParseAddr(ip), owned); err != nil {
		return fmt.Errorf("source routes: %w", err)
	}
	if exitIP != "" {
		link, err := netlink.LinkByName(nebIface)
		if err == nil {
			err = exitRouting(link)
		}
		if err != nil {
			return fmt.Errorf("exit routing: %w", err)
		}
		rs.Exit = exitIP
	}
	if a, err := netip.ParseAddr(p.DNS); err == nil {
		setDNS(nebIface, a)
	}
	writeState(rs)
	fmt.Printf("%s up as %s (%s), exit %s. Ctrl-C or 'transwarp down' to stop.\n", nebIface, s.Name, ip, rs.Exit)

	pub, err := nebPublicKey(key)
	if err != nil {
		return err
	}
	nextRenew := time.Now().Add(15 * time.Second) // like the app: once shortly after start, then every 6 h
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ctl.Context().Done():
			return errors.New("nebula stopped")
		case <-t.C:
		}
		rs.Hosts = rs.Hosts[:0]
		seen := map[uint32]bool{}
		for _, h := range ctl.ListHostmapHosts(false) {
			if seen[h.LocalIndex] { // the hostmap lists a host once per vpn address
				continue
			}
			seen[h.LocalIndex] = true
			nh := nebHost{Remote: h.CurrentRemote.String()}
			if h.Cert != nil {
				nh.Name = h.Cert.Name()
			}
			for _, a := range h.VpnAddrs {
				nh.Addrs = append(nh.Addrs, a.String())
			}
			for _, a := range h.CurrentRelaysToMe {
				nh.Relays = append(nh.Relays, a.String())
			}
			rs.Hosts = append(rs.Hosts, nh)
		}
		if time.Now().After(nextRenew) && rs.HubIP != "" {
			ns, err := renewNebula(ctx, rs.HubIP, pub, s)
			wait := renewEvery
			switch {
			case err != nil:
				fmt.Printf("%s nebula renew: %v (retry in 10 min)\n", time.Now().Format(time.TimeOnly), err)
				wait = 10 * time.Minute
			case string(ns.Nebula) != string(s.Nebula):
				var np nebProfile
				json.Unmarshal(ns.Nebula, &np)
				nconf, err := nebulaConfig(np, string(key), exitIP, skip)
				if err == nil {
					if r := c.ReloadConfigString(nconf); r.Err != nil {
						err = r.Err
					}
				}
				if err == nil {
					err = saveProfile(ns, nil)
				}
				if err != nil {
					fmt.Println("nebula renew: apply:", err)
				} else {
					s, p = ns, np
					fmt.Printf("%s nebula profile renewed (expires %v)\n", time.Now().Format(time.TimeOnly), deref(ns.ExpiresAt))
				}
			}
			if s.ExpiresAt != nil {
				rs.Expires = *s.ExpiresAt
				if exp, err := time.Parse(time.RFC3339, *s.ExpiresAt); err == nil && time.Until(exp)/2 < wait {
					wait = max(time.Until(exp)/2, time.Minute) // short-lived cert: half the time left
				}
			}
			nextRenew = time.Now().Add(wait)
			rs.Renewed = time.Now().Format(time.RFC3339)
		}
		writeState(rs)
	}
}

func deref(s *string) string {
	if s == nil {
		return "never"
	}
	return *s
}

// renewNebula is POST http://<hub>:7453/v1/mesh/nebula/renew {nebula_public_key} over the tunnel (the app's flow).
func renewNebula(ctx context.Context, hub, pub string, old saved) (saved, error) {
	b, err := hubCall(ctx, hub, "POST", "/v1/mesh/nebula/renew", map[string]string{"nebula_public_key": pub})
	if err != nil {
		return saved{}, err
	}
	var r struct {
		ExpiresAt *string         `json:"expires_at"`
		Nebula    json.RawMessage `json:"nebula"`
	}
	if err := json.Unmarshal(b, &r); err != nil || len(r.Nebula) == 0 {
		return saved{}, fmt.Errorf("bad renew response: %v", err)
	}
	old.Nebula, old.ExpiresAt = r.Nebula, r.ExpiresAt
	return old, nil
}

// --- status ---

func cmdStatus(ctx context.Context) error {
	r, err := readState()
	if err != nil || !alive(r.PID) {
		fmt.Println("down")
		return nil
	}
	fmt.Printf("%s up: %s %s (%s), hub %s, exit %s, pid %d\n", r.Iface, r.Kind, r.Name, r.MeshIP, r.HubIP, r.Exit, r.PID)
	if r.Expires != "" {
		fmt.Println("expires:", r.Expires)
	}
	for _, s := range r.Skipped {
		fmt.Printf("route %s not routed (local network)\n", s)
	}
	if r.Kind == "nebula" {
		if r.Renewed != "" {
			fmt.Println("last renew:", r.Renewed)
		}
		lh := map[string]bool{}
		for _, a := range r.Lighthouses {
			lh[a] = true
		}
		for _, h := range r.Hosts {
			path := "direct " + h.Remote
			if len(h.Relays) > 0 {
				path = "relayed via " + strings.Join(h.Relays, ",")
			}
			role := "peer"
			if len(h.Addrs) > 0 && lh[h.Addrs[0]] {
				role = "lighthouse"
			}
			fmt.Printf("  %-10s %-16s %-32s %s\n", role, safe(h.Name), strings.Join(h.Addrs, ","), path)
		}
		return nil
	}
	if r.Endpoint != "" {
		fmt.Println("endpoint:", r.Endpoint)
	}
	s, _, _ := loadProfile(r.Name)
	c, _ := parseWG(s.Config)
	names := map[string]string{}
	for _, p := range c.Peers {
		names[p.PublicKey] = p.Name
	}
	wg, err := wgctrl.New()
	if err != nil {
		return err
	}
	defer wg.Close()
	dev, err := wg.Device(r.Iface)
	if err != nil {
		fmt.Println("(peer stats need root: sudo transwarp status)")
		return nil
	}
	for _, p := range dev.Peers {
		age := "never"
		if !p.LastHandshakeTime.IsZero() {
			age = time.Since(p.LastHandshakeTime).Round(time.Second).String() + " ago"
		}
		fmt.Printf("  peer %-10s endpoint %v handshake %s rx %d tx %d\n", names[p.PublicKey.String()], p.Endpoint, age, p.ReceiveBytes, p.TransmitBytes)
	}
	return nil
}

func cmdProfiles() error {
	m, _ := filepath.Glob(filepath.Join(etcDir, "*", "profile.json"))
	for _, p := range m {
		fmt.Println(filepath.Base(filepath.Dir(p)))
	}
	if len(m) == 0 && os.Geteuid() != 0 {
		fmt.Println("(none readable; profiles are root-only: sudo transwarp profiles)")
	}
	return nil
}

// safe drops control characters from server-supplied names before printing them.
func safe(s string) string {
	return strings.Map(func(r rune) rune {
		if r < ' ' || r == 0x7f {
			return -1
		}
		return r
	}, s)
}
