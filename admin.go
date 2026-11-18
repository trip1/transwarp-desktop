package main

// Phase 38 admin API: /v1/mesh/admin/X on the hub mirrors the operator /v1/mesh/X; auth = this client's tunnel
// source + key (gofire mesh client set NAME --admin=true). Responses to add/renew carry join codes: print them to
// stdout for the operator, never log them.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	qrcode "github.com/skip2/go-qrcode"
)

const adminUsage = `usage: transwarp admin clients | add NAME [--nebula] [--lan] [--exit] [--peers] [--admin] [--groups a,b] [--ttl D] [--guest]
       | renew NAME [--ttl D] | revoke NAME | set NAME [--lan=B] [--exit=B] [--peers=B] [--admin=B] [--groups a,b]
       | rules [add FROM TO PROTO PORT | rm ID] | wol [add NAME MAC [BROADCAST] | rm NAME] | services [add NAME URL [KIND] | rm NAME]`

func apath(segs ...string) string {
	for i, s := range segs {
		segs[i] = url.PathEscape(s)
	}
	return "/v1/mesh/admin/" + strings.Join(segs, "/")
}

// newClientBody is POST clients. Guest = 24 h, no lan/exit/peers (the app's MeshAdmin.guest preset).
func newClientBody(name string, f map[string]string) (map[string]any, error) {
	b := map[string]any{"name": name}
	if f["--guest"] == "true" {
		for _, k := range []string{"--lan", "--exit", "--peers", "--admin", "--ttl"} {
			if f[k] != "" {
				return nil, errors.New("--guest takes no " + k)
			}
		}
		f["--ttl"] = "24h"
	}
	nebula := f["--nebula"] == "true"
	b["kind"] = map[bool]string{true: "nebula", false: "wireguard"}[nebula]
	for _, k := range []string{"lan", "exit", "admin"} {
		b[k] = f["--"+k] == "true"
	}
	if f["--peers"] == "true" {
		if nebula {
			return nil, errors.New("--peers is WireGuard only (Nebula members always reach each other)")
		}
		b["peers"] = true
	}
	if g := f["--groups"]; g != "" {
		b["groups"] = strings.Split(g, ",")
	}
	if t := f["--ttl"]; t != "" {
		b["ttl"] = t
	}
	return b, nil
}

func printCode(raw []byte) error {
	var r struct {
		Name      string `json:"name"`
		MeshIP    string `json:"mesh_ip"`
		Code      string `json:"code"`
		ExpiresAt string `json:"expires_at"`
	}
	if err := json.Unmarshal(raw, &r); err != nil || !strings.HasPrefix(r.Code, "transwarp://") {
		return errors.New("no join code in response")
	}
	q, err := qrcode.New(r.Code, qrcode.Medium)
	if err != nil {
		return err
	}
	fmt.Print(q.ToSmallString(false))
	fmt.Printf("%s (%s) join code, one-time, valid until %s:\n%s\n", safe(r.Name), r.MeshIP, r.ExpiresAt, r.Code)
	return nil
}

func cmdAdmin(ctx context.Context, hub string, args []string) error {
	f, pos, err := flags(args, "--nebula", "--lan", "--exit", "--peers", "--admin", "--guest", "--groups=", "--ttl=")
	if err != nil || len(pos) == 0 {
		return errors.New(adminUsage)
	}
	call := func(method, path string, body any) ([]byte, error) { return hubCall(ctx, hub, method, path, body) }
	n := len(pos)
	switch {
	case pos[0] == "clients" && n == 1:
		b, err := call("GET", apath("clients"), nil)
		if err != nil {
			return err
		}
		var cs []struct {
			Name          string     `json:"name"`
			Kind          string     `json:"kind"`
			MeshIP        string     `json:"mesh_ip"`
			Peers         bool       `json:"peers"`
			Exit          bool       `json:"exit"`
			Lan           bool       `json:"lan"`
			Admin         bool       `json:"admin"`
			Groups        []string   `json:"groups"`
			ExpiresAt     *string    `json:"expires_at"`
			LastHandshake *time.Time `json:"last_handshake"`
		}
		if err := json.Unmarshal(b, &cs); err != nil {
			return err
		}
		yn := map[bool]string{true: "yes", false: "-"}
		fmt.Printf("%-18s %-9s %-13s %-5s %-4s %-3s %-5s %-6s %s\n", "NAME", "KIND", "MESH IP", "PEERS", "EXIT", "LAN", "ADMIN", "ONLINE", "EXPIRES")
		for _, c := range cs {
			on := c.LastHandshake != nil && time.Since(*c.LastHandshake) < 3*time.Minute
			fmt.Printf("%-18s %-9s %-13s %-5s %-4s %-3s %-5s %-6s %s\n", safe(c.Name), c.Kind, c.MeshIP, yn[c.Peers], yn[c.Exit], yn[c.Lan], yn[c.Admin], yn[on], deref(c.ExpiresAt))
		}
		return nil
	case pos[0] == "add" && n == 2:
		body, err := newClientBody(pos[1], f)
		if err != nil {
			return err
		}
		b, err := call("POST", apath("clients"), body)
		if err != nil {
			return err
		}
		return printCode(b)
	case pos[0] == "renew" && n == 2:
		var body any
		if f["--ttl"] != "" {
			body = map[string]string{"ttl": f["--ttl"]}
		}
		b, err := call("POST", apath("clients", pos[1], "renew"), body)
		if err != nil {
			return err
		}
		return printCode(b)
	case pos[0] == "revoke" && n == 2:
		if _, err := call("DELETE", apath("clients", pos[1]), nil); err != nil {
			return err
		}
		fmt.Println("revoked", pos[1])
		return nil
	case pos[0] == "set" && n == 2:
		body := map[string]any{}
		for _, k := range []string{"lan", "exit", "peers", "admin"} {
			if v := f["--"+k]; v != "" {
				bv, err := strconv.ParseBool(v)
				if err != nil {
					return fmt.Errorf("--%s=%s: not a bool", k, v)
				}
				body[k] = bv
			}
		}
		if g, ok := f["--groups"]; ok {
			body["groups"] = strings.FieldsFunc(g, func(r rune) bool { return r == ',' })
		}
		if len(body) == 0 {
			return errors.New(adminUsage)
		}
		if _, err := call("PATCH", apath("clients", pos[1]), body); err != nil {
			return err
		}
		fmt.Println("updated", pos[1])
		return nil
	case pos[0] == "rules" && n == 1, pos[0] == "wol" && n == 1, pos[0] == "services" && n == 1:
		p := map[string]string{"rules": "nebula/rules", "wol": "wol-hosts", "services": "services"}[pos[0]]
		b, err := call("GET", "/v1/mesh/admin/"+p, nil)
		if err != nil {
			return err
		}
		var rows []map[string]any
		if err := json.Unmarshal(b, &rows); err != nil {
			return err
		}
		cols := map[string][]string{"rules": {"id", "from_group", "to_group", "proto", "port"}, "wol": {"name", "mac", "broadcast"}, "services": {"name", "kind", "source", "url"}}[pos[0]]
		for _, r := range rows {
			var out []string
			for _, c := range cols {
				out = append(out, safe(fmt.Sprint(r[c])))
			}
			fmt.Println(strings.Join(out, "  "))
		}
		if len(rows) == 0 {
			fmt.Println("(none)")
		}
		return nil
	case pos[0] == "rules" && n == 6 && pos[1] == "add":
		b, err := call("POST", apath("nebula", "rules"), map[string]string{"from_group": pos[2], "to_group": pos[3], "proto": pos[4], "port": pos[5]})
		if err == nil {
			fmt.Printf("%s\n", b)
		}
		return err
	case pos[0] == "rules" && n == 3 && pos[1] == "rm":
		_, err := call("DELETE", apath("nebula", "rules", pos[2]), nil)
		return err
	case pos[0] == "wol" && (n == 4 || n == 5) && pos[1] == "add":
		body := map[string]string{"mac": pos[3]}
		if n == 5 {
			body["broadcast"] = pos[4]
		}
		_, err := call("PUT", apath("wol-hosts", pos[2]), body)
		return err
	case pos[0] == "wol" && n == 3 && pos[1] == "rm":
		_, err := call("DELETE", apath("wol-hosts", pos[2]), nil)
		return err
	case pos[0] == "services" && (n == 4 || n == 5) && pos[1] == "add":
		body := map[string]string{"name": pos[2], "url": pos[3]}
		if n == 5 {
			body["kind"] = pos[4]
		}
		_, err := call("POST", apath("services"), body)
		return err
	case pos[0] == "services" && n == 3 && pos[1] == "rm":
		_, err := call("DELETE", apath("services", pos[2]), nil)
		return err
	}
	fmt.Fprintln(os.Stderr, adminUsage)
	return errors.New("bad admin command")
}
