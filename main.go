// transwarp: Linux desktop client for the gofire mesh (WireGuard or Nebula), the Transwarp app's sibling.
//
// ponytail: Linux only, CLI only (no tray), no Mac/Windows yet; WireGuard uses kernel wireguard, Nebula is embedded.
package main

import (
	"context"
	"errors"
	"io"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
)

var version = "dev"

const usage = `usage: transwarp COMMAND
  enroll 'transwarp://enroll?...' | -    enroll (- reads stdin) (WireGuard or Nebula), save to /etc/transwarp/<name>/
  up [NAME] [--exit NAME|none]            bring the tunnel up (foreground; Ctrl-C or 'down' stops it)
  daemon [NAME] [--exit NAME|none]        same as up, for the systemd unit
  down | status | profiles
  services | devices | wake NAME | speed
  beam send FILE PEER | beam receive [DIR]
  admin clients | add NAME [--nebula] [--lan] [--exit] [--peers] [--admin] [--groups a,b] [--ttl D] [--guest]
        renew NAME [--ttl D] | revoke NAME | set NAME [--lan=B] [--exit=B] [--peers=B] [--admin=B] [--groups a,b]
        rules [add FROM TO PROTO PORT | rm ID] | wol [add NAME MAC [BROADCAST] | rm NAME]
        services [add NAME URL [KIND] | rm NAME]
  version`

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "transwarp:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return errors.New(usage)
	}
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "version":
		fmt.Println(version)
		return nil
	case "enroll":
		if len(rest) != 1 {
			return errors.New("usage: transwarp enroll 'transwarp://enroll?...'")
		}
		return cmdEnroll(ctx, rest[0])
	case "up", "daemon":
		f, pos, err := flags(rest, "--exit=")
		if err != nil || len(pos) > 1 {
			return errors.New(usage)
		}
		name := ""
		if len(pos) == 1 {
			name = pos[0]
		}
		return cmdUp(ctx, name, f["--exit"])
	case "down":
		return cmdDown()
	case "status":
		return cmdStatus(ctx)
	case "profiles":
		return cmdProfiles()
	case "services", "devices", "speed":
		h, err := hub()
		if err != nil {
			return err
		}
		switch cmd {
		case "services":
			return cmdServices(ctx, h)
		case "devices":
			return cmdDevices(ctx, h)
		}
		return cmdSpeed(ctx, h)
	case "wake":
		if len(rest) != 1 {
			return errors.New("usage: transwarp wake NAME")
		}
		h, err := hub()
		if err != nil {
			return err
		}
		return cmdWake(ctx, h, rest[0])
	case "beam":
		switch {
		case len(rest) == 3 && rest[0] == "send":
			return cmdBeamSend(ctx, rest[1], rest[2])
		case len(rest) <= 2 && len(rest) >= 1 && rest[0] == "receive":
			dir := "."
			if len(rest) == 2 {
				dir = rest[1]
			}
			return cmdBeamReceive(ctx, dir)
		}
		return errors.New("usage: transwarp beam send FILE PEER | beam receive [DIR]")
	case "admin":
		h, err := hub()
		if err != nil {
			return err
		}
		return cmdAdmin(ctx, h, rest)
	}
	return errors.New(usage)
}

// flags splits flags from positionals. known: "--k=" takes a value (--k v or --k=v); "--k" is a bool (--k or --k=B).
func flags(args []string, known ...string) (map[string]string, []string, error) {
	f := map[string]string{}
	var pos []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if !strings.HasPrefix(a, "--") {
			pos = append(pos, a)
			continue
		}
		k, v, hasV := strings.Cut(a, "=")
		isBool, ok := false, false
		for _, n := range known {
			if n == k || n == k+"=" {
				ok, isBool = true, n == k
			}
		}
		if !ok {
			return nil, nil, fmt.Errorf("unknown flag %s", k)
		}
		switch {
		case hasV:
		case isBool:
			v = "true"
		case i+1 < len(args):
			i++
			v = args[i]
		default:
			return nil, nil, fmt.Errorf("%s needs a value", k)
		}
		f[k] = v
	}
	return f, pos, nil
}

func cmdEnroll(ctx context.Context, raw string) error {
	if os.Geteuid() != 0 {
		return errors.New("enroll stores keys in /etc/transwarp: run with sudo")
	}
	if raw == "-" { // keeps the code off argv/shell history
		b, _ := io.ReadAll(io.LimitReader(os.Stdin, 4096))
		raw = string(b)
	}
	c, err := parseCode(raw)
	if err != nil {
		return err
	}
	s, key, err := enroll(ctx, c)
	if err != nil {
		return err
	}
	if err := saveProfile(s, key); err != nil {
		return fmt.Errorf("enrolled as %s but saving failed: %w", s.Name, err)
	}
	fmt.Printf("Enrolled %s as %s (%s), saved %s/%s\n", s.Kind, s.Name, s.MeshIP, etcDir, s.Name)
	return nil
}
