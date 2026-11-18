package main

// Enrollment codes, the pinned enroll POST, and the profile store under /etc/transwarp/<name>/.

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	ncert "github.com/slackhq/nebula/cert"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

var etcDir = "/etc/transwarp" // var for tests

// code is a parsed transwarp://enroll?u=<https base>&t=<token>&ca=<sha256 hex of CA DER>[&k=nebula].
type code struct {
	URL, Token, CA string
	Nebula         bool
}

func parseCode(s string) (code, error) {
	u, err := url.Parse(strings.TrimSpace(s))
	if err != nil || !strings.EqualFold(u.Scheme, "transwarp") || !strings.EqualFold(u.Host, "enroll") {
		return code{}, errors.New("not a transwarp://enroll code")
	}
	q := u.Query()
	c := code{URL: strings.TrimRight(q.Get("u"), "/"), Token: q.Get("t"), CA: strings.ToLower(q.Get("ca")), Nebula: strings.EqualFold(q.Get("k"), "nebula")}
	if b, err := url.Parse(c.URL); err != nil || b.Scheme != "https" || b.Host == "" {
		return code{}, errors.New("enroll code: u must be an https URL")
	}
	if b, err := hex.DecodeString(c.CA); err != nil || len(b) != 32 {
		return code{}, errors.New("enroll code: ca must be a hex sha256")
	}
	if c.Token == "" {
		return code{}, errors.New("enroll code: missing t")
	}
	return c, nil
}

// pinnedTLS trusts only the presented CA whose DER sha256 is pin, and the leaf must chain to it (same rule as
// gofire's pki.PinnedTLS and the app's PinnedTrustManager: a CA cert in the chain alone proves nothing).
func pinnedTLS(pin string) *tls.Config {
	return &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true, // replaced by the pin check below; control is addressed by IP
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			if len(raw) == 0 {
				return errors.New("no server certificate")
			}
			leaf, err := x509.ParseCertificate(raw[0])
			if err != nil {
				return err
			}
			for _, r := range raw[1:] {
				h := sha256.Sum256(r)
				if hex.EncodeToString(h[:]) != pin {
					continue
				}
				ca, err := x509.ParseCertificate(r)
				if err != nil || !ca.IsCA {
					continue
				}
				pool := x509.NewCertPool()
				pool.AddCert(ca)
				if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
					return fmt.Errorf("server cert not signed by the pinned CA: %w", err)
				}
				return nil
			}
			return errors.New("server did not present the pinned CA (wrong cluster or interception)")
		},
	}
}

// saved is /etc/transwarp/<name>/profile.json (0600). The private key lives next to it in "key" (0600).
type saved struct {
	Name      string          `json:"name"`
	Kind      string          `json:"kind"` // wireguard | nebula
	MeshIP    string          `json:"mesh_ip"`
	ExpiresAt *string         `json:"expires_at"`
	Config    string          `json:"config,omitempty"`    // WG: wg-quick text without PrivateKey
	Endpoints []string        `json:"endpoints,omitempty"` // WG: the hub's endpoint ladder
	Nebula    json.RawMessage `json:"nebula,omitempty"`    // Nebula: profile as served
}

// enroll generates the key locally (WireGuard or Nebula X25519 — the same 32 bytes) and POSTs only the public half.
func enroll(ctx context.Context, c code) (saved, []byte, error) {
	var pub string
	var key []byte
	if c.Nebula {
		k, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			return saved{}, nil, err
		}
		pub, key = base64.StdEncoding.EncodeToString(k.PublicKey().Bytes()), ncert.MarshalPrivateKeyToPEM(ncert.Curve_CURVE25519, k.Bytes())
	} else {
		k, err := wgtypes.GeneratePrivateKey()
		if err != nil {
			return saved{}, nil, err
		}
		pub, key = k.PublicKey().String(), []byte(k.String())
	}
	field := "wg_public_key"
	if c.Nebula {
		field = "nebula_public_key"
	}
	body, _ := json.Marshal(map[string]string{"token": c.Token, field: pub})
	req, err := http.NewRequestWithContext(ctx, "POST", c.URL+"/v1/mesh/enroll", bytes.NewReader(body))
	if err != nil {
		return saved{}, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	hc := &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{TLSClientConfig: pinnedTLS(c.CA)}}
	resp, err := hc.Do(req)
	if err != nil {
		return saved{}, nil, fmt.Errorf("enroll: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != 200 {
		return saved{}, nil, fmt.Errorf("enroll: %s: %.200s", resp.Status, strings.TrimSpace(string(raw)))
	}
	var s saved
	if err := json.Unmarshal(raw, &s); err != nil {
		return saved{}, nil, fmt.Errorf("enroll: %w", err)
	}
	if !validName(s.Name) {
		return saved{}, nil, fmt.Errorf("enroll: unusable client name %q", s.Name)
	}
	s.Kind = "wireguard"
	if c.Nebula {
		s.Kind = "nebula"
		if len(s.Nebula) == 0 {
			return saved{}, nil, errors.New("enroll: no nebula profile in response")
		}
	} else if s.Config == "" {
		return saved{}, nil, errors.New("enroll: no config in response")
	}
	return s, key, nil
}

func validName(n string) bool {
	return n != "" && !strings.ContainsAny(n, `/\`) && !strings.HasPrefix(n, ".") && len(n) <= 64
}

// writeSecret writes path atomically with mode 0600 (the temp file is 0600 from creation).
func writeSecret(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

func saveProfile(s saved, key []byte) error {
	dir := filepath.Join(etcDir, s.Name)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	os.Chmod(etcDir, 0o700)
	os.Chmod(dir, 0o700)
	b, _ := json.MarshalIndent(s, "", "  ")
	if key != nil {
		if err := writeSecret(filepath.Join(dir, "key"), key); err != nil {
			return err
		}
	}
	return writeSecret(filepath.Join(dir, "profile.json"), b)
}

// loadProfile reads NAME, or the only profile when name is "".
func loadProfile(name string) (saved, []byte, error) {
	if name == "" {
		m, _ := filepath.Glob(filepath.Join(etcDir, "*", "profile.json"))
		if len(m) != 1 {
			return saved{}, nil, fmt.Errorf("%d profiles in %s: name one (transwarp up NAME)", len(m), etcDir)
		}
		name = filepath.Base(filepath.Dir(m[0]))
	}
	if !validName(name) {
		return saved{}, nil, errors.New("bad profile name")
	}
	var s saved
	b, err := os.ReadFile(filepath.Join(etcDir, name, "profile.json"))
	if err != nil {
		return s, nil, err
	}
	if err := json.Unmarshal(b, &s); err != nil {
		return s, nil, err
	}
	key, err := os.ReadFile(filepath.Join(etcDir, name, "key"))
	return s, key, err
}
