# Changelog

All notable changes to **MiTH Terminal** are documented in this file.

## [v1.2.1] - 2026-10-26

### Consumer AppSec Hardening & Cross-OS Interactive Release

**MiTH Terminal v1.2.1** ships five defense-in-depth Application Security (AppSec) hardening guards for consumer localhost/tunnel deployments alongside native Windows interactive pipe streaming and a 3-OS (`Linux`, `macOS`, `Windows`) CI verification matrix.

### One-Click Downloads (No Git Required)
- **Windows & macOS (`.zip`)**: [`MiTH-Terminal-v1.2.1.zip`](https://github.com/cr4zyd34thg0d/MiTH-Terminal/releases/download/v1.2.1/MiTH-Terminal-v1.2.1.zip) — extract and run `.\start.ps1` (Windows PowerShell) or `./start.sh` (macOS Terminal)
- **Linux, macOS & WSL (`.tar.gz`)**: [`MiTH-Terminal-v1.2.1.tar.gz`](https://github.com/cr4zyd34thg0d/MiTH-Terminal/releases/download/v1.2.1/MiTH-Terminal-v1.2.1.tar.gz) — extract (`tar -xzf MiTH-Terminal-v1.2.1.tar.gz`) and run `./start.sh`
- **Checksums**: [`SHA256SUMS.txt`](https://github.com/cr4zyd34thg0d/MiTH-Terminal/releases/download/v1.2.1/SHA256SUMS.txt)

### Consumer AppSec Hardening (5 Patches)
- **Unauthenticated Host Metadata Redaction (`/api/ping`)**: Unauthenticated probes receive strictly redacted placeholders (`host="Protected Host"`, `user="locked"`, `home_dir="~"`, `lan_ip=""`, `tunnel_url=""`) until a valid paired `Bearer` token is presented.
- **DNS Rebinding & Stale-Tunnel `Host` Guard**: Enforces a strict `Host` header allowlist (`localhost`, `127.0.0.1`, `[::1]`, RFC 1918 LAN IPs, `.local` mDNS, and only the currently active ephemeral `*.trycloudflare.com` hostname), blocking external DNS-rebinding or stale tunnel requests with `HTTP 403`.
- **Zero Wildcard CORS & Cross-Origin `POST` Blocking**: Removed `Access-Control-Allow-Origin: *` across all daemon responses and rejects cross-origin `POST` mutations from untrusted browser `Origin` headers with `HTTP 403`.
- **Pre-Allocation Payload Cap (`HTTP 413`)**: Enforces a hard `64 KiB` JSON body ceiling prior to socket allocation to prevent memory-exhaustion DoS attacks.
- **Server-Enforced WebAuthn Passkey Leases**: Rejects empty WebAuthn verification payloads (`HTTP 403`) and, whenever hardware passkeys are enrolled in `~/.mith-terminal/pairing_vault.json`, blocks client-supplied `biometric_verified: true` boolean bypasses (`HTTP 403`) — requiring a server-minted `/api/auth/webauthn/challenge` ➔ `/api/auth/webauthn/verify` execution lease.

### Cross-Platform & CI Improvements
- **Native Windows Shell & PowerShell Hardening**: Executes commands via UTF-16LE `-EncodedCommand` PowerShell invocation, cleans up process trees via `taskkill /F /T`, and streams interactive `COMSPEC` pipes without buffering lag.
- **3-OS GitHub Actions CI Matrix**: Every push and pull request is verified automatically across `ubuntu-latest`, `macos-latest`, and `windows-latest` (`18/18` unit, WebSocket CSWSH, Multi-PTY, QR, OPSEC, and AppSec tests).

---

## [v1.2.0] - 2026-10-26

### Turnkey Mobile Developer Console Release

**MiTH Terminal v1.2.0** packages the zero-dependency Python 3.10+ host companion daemon and obsidian mobile console into a 30-second turnkey setup for macOS, Linux, Windows, and WSL — with zero cloud accounts, zero VPN setup, and zero router port forwarding.

### One-Click Downloads (No Git Required)
- **Windows & macOS (`.zip`)**: [`MiTH-Terminal-v1.2.0.zip`](https://github.com/cr4zyd34thg0d/MiTH-Terminal/releases/download/v1.2.0/MiTH-Terminal-v1.2.0.zip) — extract and run `.\start.ps1` (Windows PowerShell) or `./start.sh` (macOS Terminal)
- **Linux, macOS & WSL (`.tar.gz`)**: [`MiTH-Terminal-v1.2.0.tar.gz`](https://github.com/cr4zyd34thg0d/MiTH-Terminal/releases/download/v1.2.0/MiTH-Terminal-v1.2.0.tar.gz) — extract (`tar -xzf MiTH-Terminal-v1.2.0.tar.gz`) and run `./start.sh`
- **Checksums**: [`SHA256SUMS.txt`](https://github.com/cr4zyd34thg0d/MiTH-Terminal/releases/download/v1.2.0/SHA256SUMS.txt)

### Highlights
- **Multi-Session Live PTY Tab Bar (`Term 1` – `Term 8`)**: Spawn, switch, and close up to 8 concurrent persistent kernel PTY sessions (`+ New`) with 64 KiB server-side scrollback replay across Wi-Fi/5G handoffs and app reloads.
- **Zero-Config Outbound HTTPS Tunneling**: Automatically detects your OS/CPU (`macOS`, `Linux`, `Windows` across `x86_64` and `arm64`) and downloads the official standalone `cloudflared` binary into `~/.mith-terminal/bin/` with a 150 MiB safety cap and Tar-Slip extraction guard — or pass `--no-tunnel` for strictly local Wi-Fi/LAN operation.
- **Instant Camera QR Code Pairing**: Pure-Python ISO/IEC 18004 QR encoder (`daemon/qr_banner.py`) prints a high-contrast Unicode QR code directly in your computer terminal so iPhone and Android cameras pair in one tap (`#pin=...` immediately scrubbed from URL history).
- **Hardware WebAuthn Biometric Gatekeeper**: Protects destructive or privileged commands (`sudo`, `rm -rf`, `mkfs`, `dd if=`, `shutdown`, `reboot`) across chained shell pipelines behind Apple Face ID / Touch ID passkey challenges.
- **Dual Execution Modes (`🟢 PTY` + `⚡ Shell`)**: Switch seamlessly between full-duplex RFC 6455 binary WebSockets (`xterm-256color` + dynamic `TIOCSWINSZ` resize + HTTP long-poll fallback) and fast command/output shell mode with server-side `TAB` completion.
- **Standalone Full-Screen Mobile Web App (PWA)**: Add to your iPhone or Android Home Screen (`MiTH Term`) for an edge-to-edge console supporting both portrait and landscape orientations plus a 3-mode haptic thumb keypad (`Keys`, `Folders`, `Macros`).
- **Optional Free BYOK Gemini Flash Copilot**: Prefix natural-language requests with `?` or `ai ` using your own free Google AI Studio key (`gemini-2.5-flash` with automatic `gemini-2.0-flash` fallback) — staged safely into your input bar before execution.

### Security & Verification
- Constant-time 6-digit PIN verification (`hmac.compare_digest`) with 5-attempt brute-force lockout.
- Single-use 30-second WebSocket upgrade tickets paired with strict `Origin` CSWSH validation.
- SHA-256 hashed device tokens stored at `~/.mith-terminal/pairing_vault.json` (`0600` owner-only permissions).
- Verified against all 17 unit/integration/OPSEC tests (`tests/test_daemon.py`) and OWASP static security audit (`0` findings).

---
Crafted by **MiTH** • Released under the [MIT License](LICENSE).
