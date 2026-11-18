package main

import (
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
)

func TestParseCode(t *testing.T) {
	ca := strings.Repeat("ab", 32)
	c, err := parseCode("transwarp://enroll?u=https%3A%2F%2F10.0.1.219%3A7443%2F&t=tok&ca=" + strings.ToUpper(ca) + "&k=nebula")
	if err != nil || c.URL != "https://10.0.1.219:7443" || c.Token != "tok" || c.CA != ca || !c.Nebula {
		t.Fatalf("%+v %v", c, err)
	}
	if c, _ := parseCode("transwarp://enroll?u=https://h&t=x&ca=" + ca); c.Nebula {
		t.Fatal("no k= must be WireGuard")
	}
	for _, bad := range []string{
		"transwarp://enroll?u=http://h&t=x&ca=" + ca, // not https
		"transwarp://enroll?u=https://h&ca=" + ca,    // no token
		"transwarp://enroll?u=https://h&t=x&ca=zz",   // bad pin
		"https://enroll?u=https://h&t=x&ca=" + ca,    // scheme
	} {
		if _, err := parseCode(bad); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
}

func TestSplitLAN(t *testing.T) {
	p := func(s ...string) (out []netip.Prefix) {
		for _, x := range s {
			out = append(out, netip.MustParsePrefix(x))
		}
		return
	}
	local := []netip.Addr{netip.MustParseAddr("10.0.1.130")}
	keep, skip := splitLAN(p("10.89.0.0/16", "10.0.0.0/16", "0.0.0.0/0", "10.90.0.0/16"), local)
	if len(skip) != 1 || skip[0].String() != "10.0.0.0/16" || len(keep) != 3 {
		t.Fatalf("keep %v skip %v", keep, skip)
	}
	if _, skip := splitLAN(p("10.0.0.0/16"), []netip.Addr{netip.MustParseAddr("192.168.1.5")}); len(skip) != 0 {
		t.Fatal("off-LAN must route the LAN")
	}
}

func TestNebulaConfig(t *testing.T) {
	p := nebProfile{IP: "10.90.200.9/16", IP6: "fdee::c8:9/64", CAPEM: "CA", CertPEM: "CERT", DNS: "10.89.0.1",
		Lighthouses:     []nebLighthouse{{Name: "pi-5-1", IP: "10.90.0.1", Endpoints: []string{"1.2.3.4:4242"}}, {Name: "mini-1", IP: "10.90.0.2", Endpoints: []string{"1.2.3.4:4243"}}},
		Relays:          []string{"10.90.0.1", "10.90.0.2"},
		Routes:          []nebRoute{{"10.89.0.0/16", "10.90.0.1"}, {"10.0.0.0/16", "10.90.0.1"}, {"0.0.0.0/0", "10.90.0.1"}},
		FirewallInbound: []map[string]any{{"port": 22, "proto": "tcp", "group": "ops"}},
		Exits:           []nebExit{{"pi-5-1", "10.90.0.1"}, {"zz-exit", "10.90.200.7"}},
	}
	ip, err := p.exitIP("zz-exit")
	if err != nil || ip != "10.90.200.7" {
		t.Fatal(ip, err)
	}
	s, err := nebulaConfig(p, "KEY", ip, map[string]bool{"10.0.0.0/16": true})
	if err != nil {
		t.Fatal(err)
	}
	var c struct {
		PKI   map[string]any            `json:"pki"`
		SHM   map[string][]string       `json:"static_host_map"`
		LH    struct{ Hosts []string }  `json:"lighthouse"`
		Relay struct{ Relays []string } `json:"relay"`
		Punch map[string]bool           `json:"punchy"`
		Tun   struct {
			Dev    string           `json:"dev"`
			Routes []map[string]any `json:"unsafe_routes"`
		} `json:"tun"`
		Listen   map[string]any                     `json:"listen"`
		Firewall struct{ Inbound []map[string]any } `json:"firewall"`
	}
	if err := json.Unmarshal([]byte(s), &c); err != nil {
		t.Fatal(err)
	}
	if c.PKI["disconnect_invalid"] != true || c.PKI["initiating_version"] != 2.0 || c.PKI["key"] != "KEY" {
		t.Errorf("pki %v", c.PKI)
	}
	if len(c.SHM) != 2 || len(c.LH.Hosts) != 2 || len(c.Relay.Relays) != 2 || !c.Punch["respond"] || c.Tun.Dev != nebIface {
		t.Errorf("lighthouses/relays/punchy: %s", s)
	}
	want := map[string]string{"10.89.0.0/16": "10.90.0.1 true", "10.0.0.0/16": "10.90.0.1 false", "0.0.0.0/0": "10.90.200.7 false"}
	for _, r := range c.Tun.Routes {
		if got := r["via"].(string) + " " + map[bool]string{true: "true", false: "false"}[r["install"].(bool)]; want[r["route"].(string)] != got {
			t.Errorf("route %v: got %s", r["route"], got)
		}
	}
	if len(c.Tun.Routes) != 3 || c.Listen["so_mark"] != float64(fwmark) || c.Firewall.Inbound[0]["group"] != "ops" {
		t.Errorf("routes/so_mark/firewall: %s", s)
	}
	// no exit: default route dropped, no so_mark
	s, _ = nebulaConfig(p, "KEY", "", nil)
	if strings.Contains(s, "0.0.0.0/0") || strings.Contains(s, "so_mark") {
		t.Errorf("exit none still routes default: %s", s)
	}
}

func TestBeamRequest(t *testing.T) {
	got := beamRequest("10.90.200.4", "my file+1.txt", 42)
	want := "PUT /my%20file%2B1.txt HTTP/1.1\r\nHost: 10.90.200.4:7449\r\nContent-Length: 42\r\nConnection: close\r\n\r\n"
	if got != want {
		t.Fatalf("%q", got)
	}
	if n := sanitizeName("/..%2F..%2Fetc%2Fpasswd"); n != "passwd" {
		t.Fatalf("sanitize: %q", n)
	}
}

func TestGuestBody(t *testing.T) {
	b, err := newClientBody("zz-g", map[string]string{"--guest": "true"})
	if err != nil || b["ttl"] != "24h" || b["lan"] != false || b["exit"] != false || b["peers"] != nil || b["kind"] != "wireguard" {
		t.Fatal(b, err)
	}
	if _, err := newClientBody("zz-g", map[string]string{"--guest": "true", "--lan": "true"}); err == nil {
		t.Fatal("guest with --lan accepted")
	}
}
