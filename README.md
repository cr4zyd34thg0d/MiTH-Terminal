# MiTH Terminal

[![CI](https://github.com/cr4zyd34thg0d/MiTH-Terminal/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/cr4zyd34thg0d/MiTH-Terminal/actions/workflows/ci.yml)
[![Latest Release](https://img.shields.io/github/v/release/cr4zyd34thg0d/MiTH-Terminal?style=flat-square&color=8b5cf6&label=Release)](https://github.com/cr4zyd34thg0d/MiTH-Terminal/releases/latest)
[![Zero Dependencies](https://img.shields.io/badge/Dependencies-Zero_(Python_Stdlib)-10b981?style=flat-square)](#30-second-setup-phone-to-computer)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-3b82f6?style=flat-square&logo=python&logoColor=white)](#30-second-setup-phone-to-computer)
[![Multi-Session PTY](https://img.shields.io/badge/Live_PTY-Up_to_8_Tabs_(xterm.js)-6366f1?style=flat-square)](#key-features)
[![WebAuthn Biometrics](https://img.shields.io/badge/Security-Face_ID_%2F_Touch_ID_WebAuthn-f59e0b?style=flat-square)](#security--privacy-architecture)
[![License: MIT](https://img.shields.io/badge/License-MIT-a1a1aa?style=flat-square)](#license)

**Turn your iPhone or Android into an obsidian, biometric-protected terminal for your Mac, Windows, or Linux computer in 30 seconds — zero cloud accounts, zero VPN setup, and zero router port forwarding.**

---

## ⚡ 30-Second Setup (Phone to Computer)

Run a single command on the computer you want to access:

### macOS / Linux / WSL
```bash
git clone https://github.com/cr4zyd34thg0d/MiTH-Terminal.git && cd MiTH-Terminal && ./start.sh
```

### Windows (PowerShell)
```powershell
git clone https://github.com/cr4zyd34thg0d/MiTH-Terminal.git; cd MiTH-Terminal; .\start.ps1
```

### Node.js / `npx` (One-Liner)
```bash
npx github:cr4zyd34thg0d/MiTH-Terminal
```

### No Git Installed? (One-Click Zip / Tarball)
Download **[`MiTH-Terminal-v1.2.1.zip`](https://github.com/cr4zyd34thg0d/MiTH-Terminal/releases/download/v1.2.1/MiTH-Terminal-v1.2.1.zip)** (Windows / macOS) or **[`MiTH-Terminal-v1.2.1.tar.gz`](https://github.com/cr4zyd34thg0d/MiTH-Terminal/releases/download/v1.2.1/MiTH-Terminal-v1.2.1.tar.gz)** (Linux / macOS / WSL) directly from the **[Official v1.2.1 Release Page](https://github.com/cr4zyd34thg0d/MiTH-Terminal/releases/tag/v1.2.1)**, extract it, and run `./start.sh` or `.\start.ps1`.

### What Happens Automatically on First Run
1. **Zero-Dependency Host Daemon**: Starts a lightweight Python 3.10+ companion daemon on port `8790` using only the standard library.
2. **Automatic Outbound HTTPS Tunnel**: If `cloudflared` isn't installed yet, MiTH Terminal automatically downloads the official standalone binary into `~/.mith-terminal/bin/` and opens an encrypted outbound Cloudflare Quick Tunnel — **no account, no login, and no open router ports required**.
3. **Instant Terminal QR Code**: Prints a scannable **QR code** and a 6-digit **Pairing PIN** directly inside your computer terminal.

---

## 📱 Connecting Your iPhone / Android (Full-Screen Web App)

1. **Scan the QR Code**: Point your iPhone or Android camera at the QR code printed in your computer terminal and tap the link.
2. **Instant Auto-Pairing**: Your browser automatically completes the 6-digit PIN handshake (`#pin=...`) and scrubs the PIN from the URL bar immediately so it never lingers in browser history.
3. **Enroll Face ID / Touch ID**: Register a hardware WebAuthn passkey in one tap so high-impact commands stay gated behind your biometrics.
4. **Install Full-Screen Console Mode**:
   - **iPhone (Safari)**: Tap **Share** (`↑`) ➔ **Add to Home Screen**.
   - **Android (Chrome)**: Tap **⋮** ➔ **Add to Home screen / Install app**.
   - Launch **MiTH Term** from your home screen for a distraction-free, edge-to-edge obsidian console that adapts seamlessly to both **portrait** and **landscape** orientations.

---

## 🚀 Key Features

### 1. Multi-Session Live PTY Tabs (Up to 8 Concurrent Shells)
Tap **`+ New`** on the obsidian PTY tab bar to run up to **8 independent, persistent kernel PTY sessions** (`Term 1` – `Term 8`) simultaneously:
- Run `htop` in **Term 1**, edit code with `vim` in **Term 2**, tail logs in **Term 3**, and run `git` or builds in **Term 4**.
- Switching tabs detaches the WebSocket stream cleanly **without** killing your background shell.
- Each live session buffers **64 KiB of scrollback** in memory — even if you lock your phone, switch from Wi-Fi to 5G, or reload the app, reconnecting replays your exact terminal screen and discovers all active server tabs automatically.

### 2. Dual Execution Modes: `🟢 PTY` vs `⚡ Shell`
Switch anytime via the top-right header pill:

| Mode | Best For | How It Works |
| :--- | :--- | :--- |
| **`⚡ Shell`** *(Fast Line Mode)* | Quick commands (`ls`, `git status`, `df -h`), instant output copying, natural-language AI queries | Clean command/output stream with automatic directory (`cwd`) tracking, server-side `TAB` path completion, and automatic promotion to PTY when launching TUI apps (`vim`, `htop`, `tmux`, `tail -f`). |
| **`🟢 PTY`** *(Interactive Live Mode)* | Full-screen TUIs (`vim`, `nvim`, `htop`, `btop`, `tmux`, `ssh`, Python/Node REPLs) | Full-duplex RFC 6455 binary WebSocket (`xterm-256color` + `truecolor`) with dynamic mobile viewport resizing (`TIOCSWINSZ`) and automatic HTTP long-poll fallback on restrictive networks. |

### 3. Hardware Biometric Gatekeeper (Face ID / Touch ID)
Destructive or privileged commands — including `sudo`, `rm -rf`, `mkfs`, `dd if=`, `drop table`, `killall`, `shutdown`, and `reboot` — are inspected across **every chained pipeline segment** (`;`, `&&`, `||`, `|`):
1. Execution pauses before reaching the shell.
2. Your phone prompts for **Face ID / Touch ID** (`navigator.credentials.get` via platform Secure Enclave).
3. Only after cryptographic challenge verification does the host daemon mint a short-lived execution lease.

### 4. Smart 3-Mode Mobile Thumb Keypad
Designed for fast one-handed mobile workflows with tactile haptics right above the keyboard:
- **`⌨️` Keys Mode**: Context-aware keys — `TAB` autocomplete, `▲`/`▼` history, `Ctrl+C`, pipes/flags (`-`, `/`, `~`, `|`, `&&`), plus `ESC`, `:wq`, `:q!`, `Ctrl+D`, `Ctrl+Z`, and arrow keys in `🟢 PTY` mode.
- **`📁` Folders Mode**: 1-tap jump to host folders (`~`, `Desktop`, `Documents`, `Downloads`) plus **`📌 +Pin CWD`** to bookmark any project directory you visit.
- **`⚡` Macros Mode**: Built-in ops (`htop`, `vim`, `git status`, `git diff`, `ports`, `top cpu`, `disk`) plus **`⚡ +Save`** to turn any custom command into a reusable 1-tap button.

### 5. Optional Free BYOK Gemini Flash Copilot
Prefix any prompt with `?` or `ai ` (or type plain English in `⚡ Shell` mode), such as:
```text
? find the 5 largest folders in this directory
ai show which process is listening on port 3000
```
- **100% Optional & Free**: Paste a free [Google AI Studio](https://aistudio.google.com/app/apikey) API key during onboarding or in **Console Settings (`⚙️`)** — stored strictly in your phone's local storage.
- **Safe Staging**: Automatically uses `gemini-2.5-flash` (with seamless fallback to `gemini-2.0-flash`) to stage the proposed command directly into your input bar with a clear explanation before anything executes.

---

## 🔒 Security & Privacy Architecture

```text
┌──────────────────────────────────────────────────────────────┐
│            📱 iPhone / Android Standalone Web App            │
│  • Hardware WebAuthn Passkeys (Face ID / Touch ID)           │
│  • URL Hash PIN Auto-Scrubbing & Local-Only BYOK Storage     │
└──────────────────────────────┬───────────────────────────────┘
                               │ TLS 1.3 (HTTPS / WSS)
┌──────────────────────────────▼───────────────────────────────┐
│        ☁️ Outbound-Only Ephemeral Tunnel (cloudflared)       │
│  • Zero inbound firewall ports opened on your home router    │
│  • Optional `--no-tunnel` flag for strictly local Wi-Fi/LAN  │
└──────────────────────────────┬───────────────────────────────┘
                               │ 127.0.0.1:8790
┌──────────────────────────────▼───────────────────────────────┐
│              💻 MiTH Host Companion Daemon (Python)          │
│  • Constant-time PIN verification (`hmac.compare_digest`)    │
│  • 5-attempt brute-force PIN lockout                         │
│  • Single-use 30s WebSocket tickets + Origin CSWSH guard     │
│  • Hashed token vault (`~/.mith-terminal/pairing_vault.json`)│
└──────────────────────────────────────────────────────────────┘
```

- **Outbound-Only Connectivity**: Your computer initiates an outbound TLS connection to Cloudflare's edge; your home IP and router ports remain closed to inbound internet scans.
- **DNS Rebinding, Stale-Tunnel & Zero-Wildcard CORS Defense**: Strict `Host` allowlisting rejects untrusted external or stale `*.trycloudflare.com` hostnames (`HTTP 403`), strips `Access-Control-Allow-Origin: *`, blocks cross-origin `POST` mutations (`HTTP 403`), and caps pre-allocation JSON bodies at `64 KiB` (`HTTP 413`).
- **Zero Unauthenticated Recon**: Unauthenticated `/api/ping` health probes return strictly redacted placeholders (`Protected Host` / `locked`) until a paired `Bearer` token is authenticated.
- **Brute-Force & Timing Resistance**: Pairing PINs are verified in constant time via `hmac.compare_digest` and enforce an automatic lockout after **5 failed attempts**.
- **Server-Enforced WebAuthn Leases & CSWSH Protection**: Enrolled Face ID / Touch ID passkeys enforce server-minted challenge-verify execution leases (blocking client boolean bypasses), while live PTY WebSockets authenticate via **single-use, 30-second cryptographic tickets** (`/api/terminal/ws-ticket`) paired with strict `Origin` header validation.
- **Least-Privilege Local Vault**: Paired device tokens are SHA-256 hashed at rest inside `~/.mith-terminal/pairing_vault.json` with `0600` owner-only file permissions.

### Running Strictly on Local Wi-Fi / LAN (`--no-tunnel`)
Prefer to keep traffic 100% inside your local network (or existing WireGuard/Tailscale mesh) without starting a public tunnel? Pass `--no-tunnel`:

```bash
# macOS / Linux / WSL
python3 daemon/server.py --port 8790 --no-tunnel

# Windows
python daemon\server.py --port 8790 --no-tunnel
```

---

## 🛠️ CLI Options & Native iOS Wrapper

### Daemon Flags
| Flag | Default | Description |
| :--- | :--- | :--- |
| `--host` | `0.0.0.0` | Network interface to bind (`127.0.0.1` for tunnel/localhost only, `0.0.0.0` for LAN + tunnel). |
| `--port` | `8790` | Local TCP port for the HTTP + WebSocket companion daemon. |
| `--no-tunnel` | `False` | Disable automatic `cloudflared` tunnel and serve strictly over local Wi-Fi / LAN. |

### Optional Capacitor iOS Build
MiTH Terminal works out of the box as an installable full-screen mobile web app (PWA), and also includes Capacitor configuration if you want to compile a native Xcode wrapper:
```bash
npm install
npx cap sync
npx cap open ios
```

---

## 📄 License

Released under the [MIT License](https://opensource.org/licenses/MIT).  
Crafted by **MiTH**.
