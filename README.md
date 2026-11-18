# transwarp (desktop)

Linux client for the gofire mesh — the desktop sibling of the Transwarp Android app. One static Go binary:
enroll with a `transwarp://enroll?...` code, bring up **WireGuard** (kernel, `tw0`) or **Nebula** (embedded,
`tw-neb0`), and use the hub's services, Beam, speed test, Wake-on-LAN and admin API.

Linux only for now (no tray, no macOS/Windows yet). One tunnel at a time.

## Install

```sh
V=v0.1.0; A=amd64   # or arm64
curl -LO https://github.com/trip1/transwarp-desktop/releases/download/$V/transwarp-$V-linux-$A.tar.gz
curl -LO https://github.com/trip1/transwarp-desktop/releases/download/$V/SHA256SUMS
sha256sum -c --ignore-missing SHA256SUMS
tar xzf transwarp-$V-linux-$A.tar.gz
sudo install transwarp-$V-linux-$A/transwarp /usr/local/bin/
```

WireGuard needs the kernel module (Linux ≥ 5.6). `*.mesh` names need systemd-resolved (`resolvectl`); without
it, transwarp warns and you can still use `10.89.0.1` as DNS for `.mesh`.

## Use

```sh
sudo transwarp enroll 'transwarp://enroll?u=...'   # or: ... | sudo transwarp enroll -   (keeps it off argv)
sudo transwarp up [NAME] [--exit NAME|none]       # foreground; Ctrl-C or `sudo transwarp down`
transwarp status                                   # sudo for WireGuard peer stats
transwarp devices | services | speed | wake NAME
transwarp beam send FILE PEER                      # PEER = directory name or mesh IP
transwarp beam receive [DIR]                       # listens on the tunnel address :7449 only
```

- Enrollment generates the key locally and only sends the public key, over TLS pinned to the code's `ca`
  (sha256 of the cluster CA; the server cert must chain to it). The code's `u=` is usually the LAN control URL,
  so enroll on the home network.
- Profiles live in `/etc/transwarp/<name>/` (`profile.json` + `key`, root-only 0600, dir 0700).
- `--exit`: route all traffic via the hub (WireGuard: the hub's name; Nebula: any name from the profile's `exits`).
  Default `none` = mesh routes only. The client needs the exit flag server-side.
- Routes containing one of this machine's own addresses (e.g. the home LAN `10.0.0.0/16` when you are at home)
  are skipped and logged. Routes another interface already owns are not taken over; only transwarp's own traffic
  uses the tunnel for them (source policy rule).
- Nebula renews its cert/profile over the tunnel shortly after start and every 6 h (`/v1/mesh/nebula/renew`),
  reloading only when the profile changed.

### As a service

```sh
sudo cp transwarp.service /etc/systemd/system/   # edit ExecStart for NAME / --exit
sudo systemctl enable --now transwarp
```

### Admin (clients with `gofire mesh client set NAME --admin=true`)

```sh
transwarp admin clients
transwarp admin add NAME [--nebula] [--lan] [--exit] [--peers] [--admin] [--groups a,b] [--ttl 90d]
transwarp admin add NAME --guest                   # 24 h, no lan/exit/peers; prints a terminal QR + the code
transwarp admin renew NAME [--ttl D] | revoke NAME
transwarp admin set NAME --lan=false --exit=true --groups a,b
transwarp admin rules [add FROM TO PROTO PORT | rm ID]
transwarp admin wol [add NAME MAC [BROADCAST] | rm NAME]
transwarp admin services [add NAME URL [KIND] | rm NAME]
```

Join codes are printed to stdout only (never logged); treat that output as a secret.

## Build

```sh
make test   # go vet + go test -race
make dist   # dist/transwarp-<ver>-linux-{amd64,arm64}.tar.gz + SHA256SUMS (static, CGO_ENABLED=0)
```

Go 1.27.4 (`mise exec go@1.27.4`). Not done yet: the `wss://` relay rung of the WireGuard endpoint ladder
(UDP rungs only), direct WG peer paths, tray UI, macOS/Windows.
