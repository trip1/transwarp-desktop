package main

// Hub directory listener (:7453) calls: directory, services, devices, wake, speed (Phase 37) and Beam (tcp/7449).
// Auth is the tunnel source address, so these only work while `up` runs.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	dirPort  = 7453
	beamPort = 7449
	beamMax  = 512 << 20
)

var hc = &http.Client{Timeout: 60 * time.Second, Transport: &http.Transport{DialContext: dialMesh}}

// dialMesh binds the tunnel address as source: the hub authenticates callers by it.
func dialMesh(ctx context.Context, network, addr string) (net.Conn, error) {
	d := &net.Dialer{Timeout: 10 * time.Second}
	if r, err := readState(); err == nil {
		if ip := net.ParseIP(r.MeshIP); ip != nil {
			d.LocalAddr = &net.TCPAddr{IP: ip}
		}
	}
	return d.DialContext(ctx, network, addr)
}

// hubCall does METHOD http://hub:7453PATH with an optional JSON body and returns the 2xx body.
func hubCall(ctx context.Context, hub, method, path string, body any) ([]byte, error) {
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, "http://"+net.JoinHostPort(hub, fmt.Sprint(dirPort))+path, rd)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if resp.StatusCode/100 != 2 {
		msg := strings.TrimSpace(string(b))
		if ra := resp.Header.Get("Retry-After"); ra != "" {
			msg += " (retry after " + ra + "s)"
		}
		return nil, fmt.Errorf("%s: HTTP %d %.200s", path, resp.StatusCode, msg)
	}
	return b, nil
}

type device struct {
	Name   string `json:"name"`
	MeshIP string `json:"mesh_ip"`
	IP6    string `json:"ip6"`
	Kind   string `json:"kind"`
	Online bool   `json:"online"`
}

type directory struct {
	Self struct {
		Name   string `json:"name"`
		MeshIP string `json:"mesh_ip"`
		Admin  bool   `json:"admin"`
	} `json:"self"`
	Devices  []device `json:"devices"`
	Services []struct {
		Name   string `json:"name"`
		URL    string `json:"url"`
		Kind   string `json:"kind"`
		Source string `json:"source"`
	} `json:"services"`
	WoL []struct {
		Name string `json:"name"`
	} `json:"wol"`
}

func fetchDirectory(ctx context.Context, hub string) (directory, error) {
	var d directory
	b, err := hubCall(ctx, hub, "GET", "/v1/mesh/directory", nil)
	if err == nil {
		err = json.Unmarshal(b, &d)
	}
	return d, err
}

func cmdServices(ctx context.Context, hub string) error {
	d, err := fetchDirectory(ctx, hub)
	if err != nil {
		return err
	}
	for _, s := range d.Services {
		fmt.Printf("%-24s %-6s %s\n", safe(s.Name), safe(s.Kind), safe(s.URL))
	}
	if len(d.Services) == 0 {
		fmt.Println("(no services)")
	}
	return nil
}

func cmdDevices(ctx context.Context, hub string) error {
	d, err := fetchDirectory(ctx, hub)
	if err != nil {
		return err
	}
	fmt.Printf("self %s (%s) admin=%v\n", safe(d.Self.Name), d.Self.MeshIP, d.Self.Admin)
	for _, x := range d.Devices {
		on := "offline"
		if x.Online {
			on = "online"
		}
		fmt.Printf("  %-22s %-15s %-8s %s\n", safe(x.Name), x.MeshIP, safe(x.Kind), on)
	}
	if len(d.WoL) > 0 {
		var n []string
		for _, w := range d.WoL {
			n = append(n, safe(w.Name))
		}
		fmt.Println("wake-on-lan:", strings.Join(n, ", "))
	}
	return nil
}

func cmdWake(ctx context.Context, hub, name string) error {
	if _, err := hubCall(ctx, hub, "POST", "/v1/mesh/wol", map[string]string{"name": name}); err != nil {
		return err
	}
	fmt.Println("magic packet sent for", name)
	return nil
}

const speedBytes = 10_000_000

// cmdSpeed: GET /v1/mesh/speed/down?bytes=N (time the body), then POST /v1/mesh/speed/up with N bytes. Mbit/s.
func cmdSpeed(ctx context.Context, hub string) error {
	base := "http://" + net.JoinHostPort(hub, fmt.Sprint(dirPort))
	t0 := time.Now()
	req, _ := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("%s/v1/mesh/speed/down?bytes=%d", base, speedBytes), nil)
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	n, _ := io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("speed down: HTTP %d", resp.StatusCode)
	}
	down := mbps(n, time.Since(t0))
	t0 = time.Now()
	req, _ = http.NewRequestWithContext(ctx, "POST", base+"/v1/mesh/speed/up", io.LimitReader(zeros{}, speedBytes))
	req.ContentLength = speedBytes
	req.Header.Set("Content-Type", "application/octet-stream")
	resp, err = hc.Do(req)
	if err != nil {
		return err
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("speed up: HTTP %d", resp.StatusCode)
	}
	fmt.Printf("down %.1f Mbit/s · up %.1f Mbit/s (%d MB each way, hub %s)\n", down, mbps(speedBytes, time.Since(t0)), speedBytes/1_000_000, hub)
	return nil
}

func mbps(bytes int64, d time.Duration) float64 {
	if d <= 0 {
		return 0
	}
	return float64(bytes) * 8 / d.Seconds() / 1e6
}

type zeros struct{}

func (zeros) Read(p []byte) (int, error) { clear(p); return len(p), nil }

// --- Beam ---

// resolvePeer: an IP, or a directory device name (also NAME.mesh); v4 first like the app.
func resolvePeer(ctx context.Context, peer string) (string, error) {
	if ip := net.ParseIP(peer); ip != nil {
		return peer, nil
	}
	h, err := hub()
	if err != nil {
		return "", err
	}
	d, err := fetchDirectory(ctx, h)
	if err != nil {
		return "", err
	}
	name := strings.TrimSuffix(peer, ".mesh")
	for _, x := range d.Devices {
		if strings.EqualFold(x.Name, name) {
			if x.MeshIP != "" {
				return x.MeshIP, nil
			}
			return x.IP6, nil
		}
	}
	return "", fmt.Errorf("%s is not in the directory (transwarp devices)", peer)
}

// beamRequest is the app's Beam.send head: PUT /<urlencoded name, %20 for spaces> with Content-Length, close.
func beamRequest(host, name string, length int64) string {
	path := strings.ReplaceAll(url.QueryEscape(name), "+", "%20")
	return fmt.Sprintf("PUT /%s HTTP/1.1\r\nHost: %s\r\nContent-Length: %d\r\nConnection: close\r\n\r\n", path, net.JoinHostPort(host, fmt.Sprint(beamPort)), length)
}

func cmdBeamSend(ctx context.Context, file, peer string) error {
	fh, err := os.Open(file)
	if err != nil {
		return err
	}
	defer fh.Close()
	st, err := fh.Stat()
	if err != nil {
		return err
	}
	if !st.Mode().IsRegular() || st.Size() > beamMax {
		return fmt.Errorf("%s: must be a regular file of at most 512 MiB", file)
	}
	ip, err := resolvePeer(ctx, peer)
	if err != nil {
		return err
	}
	conn, err := (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, "tcp", net.JoinHostPort(ip, fmt.Sprint(beamPort)))
	if err != nil {
		return err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Minute))
	if _, err := io.WriteString(conn, beamRequest(ip, filepath.Base(file), st.Size())); err != nil {
		return err
	}
	if _, err := io.Copy(conn, fh); err != nil {
		return err
	}
	line, err := readLine(conn)
	if err != nil {
		return fmt.Errorf("no response: %w", err)
	}
	if f := strings.Fields(line); len(f) < 2 || f[1] != "201" {
		return fmt.Errorf("%s refused it: %s", peer, line)
	}
	fmt.Printf("beamed %s (%d bytes) to %s (%s)\n", filepath.Base(file), st.Size(), peer, ip)
	return nil
}

func readLine(r io.Reader) (string, error) {
	var b []byte
	one := make([]byte, 1)
	for len(b) < 8192 {
		if _, err := r.Read(one); err != nil {
			return string(b), err
		}
		if one[0] == '\n' {
			return strings.TrimRight(string(b), "\r"), nil
		}
		b = append(b, one[0])
	}
	return "", errors.New("line too long")
}

// sanitizeName keeps a safe basename (the app's rule): no dirs, traversal, control or <>:"|?* chars, no leading dots.
func sanitizeName(rawPath string) string {
	p, err := url.PathUnescape(strings.SplitN(rawPath, "?", 2)[0])
	if err != nil {
		return ""
	}
	p = strings.ReplaceAll(p, `\`, "/")
	p = p[strings.LastIndex(p, "/")+1:]
	p = strings.Map(func(r rune) rune {
		if r < ' ' || r == 0x7f || strings.ContainsRune(`<>:"|?*`, r) {
			return -1
		}
		return r
	}, p)
	p = strings.TrimLeft(strings.TrimSpace(p), ".")
	if r := []rune(p); len(r) > 200 {
		p = string(r[:200])
	}
	return p
}

func beamHandler(dir string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "PUT" && r.Method != "POST" || r.ContentLength < 0 {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if r.ContentLength > beamMax {
			w.WriteHeader(http.StatusRequestEntityTooLarge)
			return
		}
		name := sanitizeName(r.URL.EscapedPath())
		if name == "" {
			name = fmt.Sprintf("beam-%d", time.Now().UnixMilli())
		}
		var fh *os.File
		var path string
		var err error
		ext := filepath.Ext(name)
		for i := 0; i < 100; i++ { // never overwrite: "name (1).ext" …
			path = filepath.Join(dir, name)
			if i > 0 {
				path = filepath.Join(dir, fmt.Sprintf("%s (%d)%s", strings.TrimSuffix(name, ext), i, ext))
			}
			if fh, err = os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644); !errors.Is(err, os.ErrExist) {
				break
			}
		}
		if err != nil || fh == nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		n, err := io.Copy(fh, io.LimitReader(r.Body, r.ContentLength))
		if cerr := fh.Close(); err == nil {
			err = cerr
		}
		if err != nil || n != r.ContentLength {
			os.Remove(path)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusCreated)
		fmt.Printf("%s received %s (%d bytes) from %s\n", time.Now().Format(time.TimeOnly), path, n, r.RemoteAddr)
	})
}

// cmdBeamReceive listens on the tunnel address only (the tunnel is the auth, like the app).
func cmdBeamReceive(ctx context.Context, dir string) error {
	r, err := readState()
	if err != nil || !alive(r.PID) {
		return errors.New("no tunnel is up (transwarp up)")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	addr := net.JoinHostPort(r.MeshIP, fmt.Sprint(beamPort))
	srv := &http.Server{Addr: addr, Handler: beamHandler(dir), ReadHeaderTimeout: 30 * time.Second}
	go func() { <-ctx.Done(); srv.Close() }()
	fmt.Printf("beam: listening on %s, saving to %s. Ctrl-C to stop.\n", addr, dir)
	if err := srv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
