# Private DERP: encrypted maps, key sources, and admission control

This document describes the private-DERP customizations this fork
carries on top of upstream tailcat (branch `custom`; upstream `main`
stays untouched). It covers what each feature does, how it is
implemented, and where the code lives, so the design survives
rebases onto future upstream releases.

The customizations serve one deployment goal: relay all tailcat
traffic through privately operated DERP servers whose locations,
maps, and users are not public, without putting long-lived secrets
in process listings or environments.

## 1. Encrypted DERP maps

A DERP map served from an HTTPS URL may still be fetched by anyone
who learns the URL (logs, scanners, referers). To keep the map
private to tailcat users, the map can be served encrypted:

- Format: `nonce (12 bytes) ‖ ciphertext ‖ tag (16)` of
  AES-256-GCM over the plain JSON, keyed by a 32-byte key,
  hex-encoded in configuration.
- Tool: `cmd/derpmap-encrypt` encrypts (`derpmap-encrypt -key <hex>
  derpmap.json` writes `derpmap.json.enc`), decrypts
  (`-decrypt`), and generates keys (`-genkey [-o keyfile]`, file
  mode 0600). It refuses to encrypt input that is not valid JSON.
- Decryption: `decryptDERPMap` in `tailcat.go` sits inside the
  shared decode closure of `fetchDERPMap` (tailcat.go), so every
  map source decrypts uniformly. The in-memory DERP map cache
  stores whatever the server sent — ciphertext included — which
  keeps ETag semantics meaningful across restarts and keeps the
  plaintext map out of caches.

## 2. DERP map sources

`--derpmap-url` accepts six source forms; the flag documentation in
`cmd/tailcat/tailcat.go` is the normative list:

| Source | Form | Notes |
|---|---|---|
| HTTP(S) URL | `https://...` | fetched, cached per freshness policy |
| Local file path | `/path/to/map` | re-read on every use, never cached |
| `file://` URL | `file:///path` | same semantics as a bare path |
| Inline base64 | `base64:<payload>` | explicit prefix avoids path ambiguity; std/url alphabet, optional padding, surrounding whitespace tolerated |
| File descriptor | `--derpmap-url-fd N` | payload piped by the parent process |
| Standard input | `--derpmap-url-stdin` | pipe/redirection only, refused on a terminal; identical on Unix and Windows |

Payloads may be plain JSON or AES-GCM ciphertext (decrypted when a
key source is set). At the library level the payload form maps to
the `DERPMapBytes` option (`tailcat.go`), which `Expand` and the
server-mode map loader accept in place of fetching.

## 3. Key sources and hygiene

The decryption key for the map (`--derpmap-key*`) and the admission
secret (`--derp-auth-secret*`, section 4) each come from four
mutually exclusive sources, checked up front in `main` before any
network activity:

- a literal flag value (works, but visible in `ps`; discouraged)
- a file (`-file`; on Unix, group/world-readable files are
  rejected at startup)
- a file descriptor (`-fd`; Unix-oriented, e.g. an anonymous pipe
  set up by a supervisor)
- standard input (`-stdin`; works the same on Unix and Windows,
  refused on a terminal)

All reader forms share `readSecret`-style semantics in
`cmd/tailcat/tailcat.go` (`resolveDerpAuth`): at most 1 KiB,
whitespace-trimmed, empty values are an error. Modes that own
their stdin (ssh/cp) refuse the stdin forms because OpenSSH uses
the pipe; ProxyCommand-style pass-through forwards file paths, not
secrets.

## 4. Admission control for private DERP servers

Without a control server, anyone who reaches the DERP port could
relay through it. The fork adds an admission step: the derper
forwards each new connection's claimed identity to an external
admission controller and rejects the connection when it answers no.

### Flow

```
tailcat                       derper (patched)            admit controller
  |                             |                             |
  | ClientInfo{Username,        |                             |
  |   AuthToken}                |                             |
  |  — sealed to server key —>  |                             |
  |                             | POST {NodePublic, Source,   |
  |                             |       Username, AuthHash}   |
  |                             | ——————————————————————————> |
  |                             |       {"Allow": bool}       |
  |                             | <—————————————————————————— |
  | <— connected / rejected —   |                             |
```

The credentials travel inside the DERP `ClientInfo`, which the
protocol seals to the server's public key (NaCl box), and then over
HTTPS to the controller. Neither the secret nor a reusable token
crosses the wire in the clear.

### Token algorithm

`token = hex(HMAC-SHA256(secret, username ":" window))` where
`window = unixTime / 300` (`derpAuthWindowSecs`, `tailcat.go`). The
controller accepts the current, previous, and next window, so
clocks may drift by up to five minutes. Comparison is
constant-time. Each user has an independent secret, so one leaked
secret does not enable forging another user's tokens.

### Client side

Two mutually exclusive flag groups (validated in
`resolveDerpAuth`, `cmd/tailcat/tailcat.go`):

- **Token mode** — `--derp-auth-token` / `--derp-auth-token-file`:
  an externally computed token, valid 5–10 minutes. For machines
  that must not hold a long-lived secret.
- **Secret mode** (recommended) — `--derp-auth-secret` /
  `-file` / `-fd` / `-stdin`: tailcat holds the secret and a
  goroutine (`startDerpAuth`, `tailcat.go`) recomputes the token
  every `derpAuthRefreshInterval` (one minute), pushing it into the
  engine. Long-running processes survive token rotation with no
  external help.

The username travels via `--derp-auth-user`. All flags have
`TAILCAT_DERP_AUTH_*` environment defaults.

### Server side

Not in this repository: the patched derper lives in the
[tailscale fork](https://github.com/xukongyang/tailscale) branch
`auth-patch` (four commits), and the admission controllers
(`admit`, `admit-sqlite`) plus build tooling live in the
derp-tools workspace. See `DESIGN.md` there for the derper patches
and the controllers' design.

## 5. Token rotation reaches live connections

Original bug (fixed 2026-10): `Conn.SetDERPAuth` stored credentials
in an atomic read only when a region was first dialed. Each
`derphttp.Client` snapshotted the token at creation, so after a
derper restart, long-lived tailcat processes reconnected forever
with the stale token from process start and the admission
controller kept rejecting them until the process itself restarted.

Fix (fork commit `derphttp, magicsock: push rotated admission
credentials to live clients`): `derphttp.Client.SetAuth` guards the
credentials with a leaf mutex and every connection establishment
reads them under that lock; `magicsock.Conn.SetDERPAuth` now also
walks `activeDerp` and pushes the new credentials into the clients
already connected. The rotation goroutine's next tick (≤ 60 s)
therefore re-arms every connection; a reconnection after a derper
restart presents a token at most one refresh old, always inside the
admission window tolerance. Regression test:
`TestClientSetAuthCarriesToReconnect` in the fork records which
token each connection presented through a fake admission
controller.

## 6. Repository layout and the three-way build

| Repository | Branch | Role |
|---|---|---|
| this fork | `main` | tracks upstream tailcat; fast-forward only |
| this fork | `custom` | carries the customizations; rebases onto `main` |
| xukongyang/tailscale | `auth-patch` | four derper/magicsock commits; `go.mod` `replace` target |
| derp-tools workspace | `main`/`dev` | `patches/` (single source of truth), `admit`, `admit-sqlite`, `build.sh` |

`go.mod` pins the fork by pseudo-version
(`replace tailscale.com => github.com/xukongyang/tailscale
v0.0.0-...`), so the tailcat binary and the derper built from
derp-tools always share identical patched sources.

Upgrade order (each step tested before the next): rebase
`auth-patch` onto tailscale upstream and force-push → rebase
`custom` onto upstream tailcat `main` and update the `replace`
pseudo-version (the timestamp is the commit's UTC committer date;
Go validates it) → re-export `patches/` and update `TAILSCALE_COMMIT`
in derp-tools `build.sh` → rebuild the derper → full test suite →
end-to-end check.

## 7. Testing

Customization survival is guarded by tests that must stay green
after every rebase:

- `tailcat_test.go` — decrypt vectors, source parsing, fd/stdin
  readers, admission flag resolution and mutual exclusion, the
  fixed-anchor `derpAuthHash` vector, rotation timer wiring.
- `cmd/tailcat/derpmap_key_test.go` — key-source permissions and
  pass-through behavior.
- Fork-side: `derphttp_auth_test.go` (rotation-to-reconnect
  regression), derp/derphttp/derpserver/magicsock suites.
- End-to-end (derp-tools testbed): patched derper + `admit` or
  `admit-sqlite` + two tailcat processes; correct credentials must
  `pong ... via DERP`, wrong credentials must be rejected with 403
  in the admit log. The rotation fix is verified by letting the
  startup token fully expire (≥ 2 windows), restarting only the
  derper, and observing the untouched client readmitted within
  seconds.
