#!/usr/bin/env python3
"""
MiTH Terminal — Standalone Commercial Companion Daemon
Lightweight, zero-dependency host daemon for the MiTH Terminal mobile app.
Enforces cryptographic pairing, biometrics gatekeeper, persistent CWD, 
zero-config public HTTPS tunnels (Cloudflare / Tailscale), and WebAuthn.
"""

from __future__ import annotations

import argparse
import atexit
import base64
import getpass
import hashlib
import hmac
import json
import logging
import os
import platform
import re
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import tarfile
import threading
import time
import urllib.error
import urllib.request
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, quote, urlparse

DAEMON_MODULE_DIR = Path(__file__).resolve().parent
if str(DAEMON_MODULE_DIR) not in sys.path:
    sys.path.insert(0, str(DAEMON_MODULE_DIR))

from pty_engine import (
    MAX_ACTIVE_PTY_SESSIONS,
    PtySessionManager,
    serve_websocket_pty,
    ws_compute_accept_key,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("mith-terminal-daemon")

BASE_DIR = DAEMON_MODULE_DIR.parent
CLIENT_DIR = BASE_DIR / "client"
VENDOR_DIR = CLIENT_DIR / "vendor"
INDEX_HTML = CLIENT_DIR / "index.html"
ICON_180_PNG = CLIENT_DIR / "icon-180.png"
ICON_512_PNG = CLIENT_DIR / "icon-512.png"
VAULT_DIR = Path.home() / ".mith_terminal"
VAULT_FILE = VAULT_DIR / "pairing_vault.json"

PIN_RATE_WINDOW_SECONDS = 600.0  # 10 minutes
PIN_MAX_FAILED_ATTEMPTS = 5
BIOMETRIC_LEASE_SECONDS = 90.0   # Active Face ID grant duration for dangerous ops


def _sha256_hex(val: str) -> str:
    return hashlib.sha256(val.encode("utf-8")).hexdigest()


def _current_username() -> str:
    """Resolve current OS username without hardcoded personal defaults."""
    env_user = (os.getenv("USER") or os.getenv("USERNAME") or "").strip()
    if env_user:
        return env_user
    try:
        gp_user = (getpass.getuser() or "").strip()
        if gp_user:
            return gp_user
    except Exception:
        pass
    return "user"


def _get_lan_ip() -> str:
    """Determine the host's primary outbound LAN IPv4 address."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"
    finally:
        s.close()


def _get_system_vitals(cwd: str = ".") -> dict[str, Any]:
    """Gather live machine telemetry (CPU, RAM, Disk, Uptime) for mobile HUD."""
    try:
        disk = shutil.disk_usage(cwd if Path(cwd).is_dir() else ".")
    except Exception:
        disk = shutil.disk_usage(".")

    mem_total_mb, mem_avail_mb = 0, 0
    if os.path.exists("/proc/meminfo"):
        try:
            with open("/proc/meminfo", "r", encoding="utf-8") as f:
                for line in f:
                    if line.startswith("MemTotal:"):
                        mem_total_mb = int(line.split()[1]) // 1024
                    elif line.startswith("MemAvailable:"):
                        mem_avail_mb = int(line.split()[1]) // 1024
        except Exception:
            pass

    mem_used_mb = max(0, mem_total_mb - mem_avail_mb)
    mem_pct = round((mem_used_mb / mem_total_mb) * 100, 1) if mem_total_mb else 0

    load_avg = os.getloadavg() if hasattr(os, "getloadavg") else (0.0, 0.0, 0.0)
    cpu_cores = os.cpu_count() or 1
    cpu_pct = min(100.0, round((load_avg[0] / cpu_cores) * 100, 1))

    return {
        "cpu_pct": cpu_pct,
        "cpu_load": round(load_avg[0], 2),
        "cpu_cores": cpu_cores,
        "mem_total_gb": round(mem_total_mb / 1024, 1),
        "mem_used_gb": round(mem_used_mb / 1024, 1),
        "mem_pct": mem_pct,
        "disk_total_gb": round(disk.total / (1024**3), 1),
        "disk_used_gb": round(disk.used / (1024**3), 1),
        "disk_free_gb": round(disk.free / (1024**3), 1),
        "disk_pct": round((disk.used / disk.total) * 100, 1),
        "system": platform.system(),
        "release": platform.release(),
        "arch": platform.machine(),
    }


def is_destructive_command(cmd: str) -> bool:
    """
    Deep pipeline security check: analyzes compound pipelines, subshells,
    and chained operations (split by ;, &&, ||, |, &, \n) to prevent command bypass.
    """
    clean = cmd.strip()
    if not clean:
        return False

    segments = re.split(r'[;&|\n]+', clean)
    destructive_patterns = (
        r'^\s*sudo\b',
        r'^\s*rm\s+-[a-zA-Z]*r[a-zA-Z]*f\b',
        r'^\s*rm\s+-[a-zA-Z]*f[a-zA-Z]*r\b',
        r'^\s*rm\s+--recursive\b',
        r'^\s*mkfs\b',
        r'^\s*dd\s+if=',
        r'^\s*drop\s+table\b',
        r'^\s*killall\b',
        r'^\s*reboot\b',
        r'^\s*shutdown\b',
        r'^\s*format\b',
    )
    for seg in segments:
        seg_str = seg.strip()
        for pat in destructive_patterns:
            if re.search(pat, seg_str, re.IGNORECASE):
                return True
    return False


def _detect_host_bookmarks() -> list[dict[str, str]]:
    """Auto-detect existing quick-navigation directories on this host PC/Mac/Linux."""
    home = Path.home()
    candidates: list[tuple[str, str, Path]] = [
        ("🏠", "~", home),
        ("📁", "docs", home / "Documents"),
        ("🎵", "music", home / "Music"),
        ("🤖", "bridge", home / "bridge"),
        ("🐙", "github", home / "github"),
        ("🖥️", "desktop", home / "Desktop"),
        ("📥", "downloads", home / "Downloads"),
        ("💻", "win", home / "win"),
        ("💽", "C:\\", Path("/mnt/c")),
    ]
    seen_targets: set[str] = set()
    bookmarks: list[dict[str, str]] = []
    for icon, label, path_obj in candidates:
        try:
            if not path_obj.exists() or not path_obj.is_dir():
                continue
            resolved = str(path_obj.resolve())
            if resolved in seen_targets and label not in ("~", "C:\\"):
                continue
            seen_targets.add(resolved)
            cmd_target = "~" if path_obj == home else str(path_obj)
            safe_target = cmd_target if cmd_target == "~" else f'"{cmd_target}"'
            bookmarks.append({
                "icon": icon,
                "label": label,
                "path": resolved,
                "cmd": f"cd {safe_target} && ls",
            })
        except OSError:
            continue
    return bookmarks


def _common_prefix(strings: list[str]) -> str:
    if not strings:
        return ""
    s1 = min(strings)
    s2 = max(strings)
    for i, ch in enumerate(s1):
        if i >= len(s2) or ch != s2[i]:
            return s1[:i]
    return s1


def _complete_terminal_input(line: str, cwd: str) -> dict[str, Any]:
    """
    Zero-exec safe tab completion for paths, directories, and common commands.
    Never spawns a shell; inspects the filesystem and $PATH directly.
    """
    raw_line = line or ""
    base_dir = Path(cwd) if cwd and Path(cwd).is_dir() else Path.home()

    # Split line into prefix + active last token (preserving quotes/operators)
    m = re.search(r'([^\s|;&"\']*)$', raw_line)
    token = m.group(1) if m else ""
    line_prefix = raw_line[: len(raw_line) - len(token)]

    # Determine whether token is in command position (first word of line or after | ; &)
    stripped_prefix = line_prefix.rstrip()
    is_cmd_pos = (not stripped_prefix) or stripped_prefix[-1] in "|;&"
    prev_words = stripped_prefix.split()
    active_verb = prev_words[-1].lower() if prev_words and not is_cmd_pos else ""
    dirs_only = active_verb in ("cd", "pushd", "rmdir")

    # Normalize Windows drive prefix if typed on POSIX/WSL (e.g. C:\Users -> /mnt/c/Users)
    lookup_token = token
    if platform.system() != "Windows" and re.match(r"^[A-Za-z]:[\\/]", lookup_token):
        drive_letter = lookup_token[0].lower()
        rest = lookup_token[2:].lstrip("\\/").replace("\\", "/")
        lookup_token = f"/mnt/{drive_letter}/{rest}"
        token = lookup_token

    has_slash = ("/" in lookup_token) or ("\\" in lookup_token) or lookup_token.startswith(("~", "."))

    # Case 1: Command position with no path separator -> match builtins/aliases + $PATH + local dirs
    if is_cmd_pos and not has_slash:
        if not lookup_token:
            return {"ok": True, "completed_line": raw_line, "matches": []}
        builtins = [
            "cd", "ls", "ll", "la", "pwd", "clear", "docs", "music", "mith",
            "bridge", "github", "win", "git", "python3", "python", "node",
            "npm", "npx", "agy", "tmux", "cat", "grep", "find", "curl", "df",
            "du", "ps", "top", "htop", "mkdir", "touch", "cp", "mv", "rm", "tar",
        ]
        cand_set: set[str] = {b for b in builtins if b.startswith(lookup_token)}
        # Include local subdirectories/executables
        try:
            for entry in base_dir.iterdir():
                if entry.name.startswith(lookup_token):
                    cand_set.add(entry.name + ("/" if entry.is_dir() else ""))
        except OSError:
            pass
        # Scan $PATH only if token is >= 2 chars to keep completion <5ms
        if len(lookup_token) >= 2:
            for p_dir in os.environ.get("PATH", "").split(os.pathsep):
                if not p_dir:
                    continue
                try:
                    for entry in os.scandir(p_dir):
                        if entry.name.startswith(lookup_token):
                            cand_set.add(entry.name)
                            if len(cand_set) >= 60:
                                break
                except OSError:
                    continue
                if len(cand_set) >= 60:
                    break

        matches = sorted(cand_set)[:40]
        if len(matches) == 1:
            single = matches[0]
            suffix = "" if single.endswith("/") else " "
            return {
                "ok": True,
                "completed_line": f"{line_prefix}{single}{suffix}",
                "matches": matches,
            }
        if len(matches) > 1:
            cp = _common_prefix([m_item.rstrip("/") for m_item in matches])
            new_tok = cp if len(cp) > len(lookup_token) else lookup_token
            return {
                "ok": True,
                "completed_line": f"{line_prefix}{new_tok}",
                "matches": matches,
            }
        return {"ok": True, "completed_line": raw_line, "matches": []}

    # Case 2: Path / filename / directory completion
    home_str = str(Path.home())
    tilde_prefix = False
    expanded = lookup_token
    if expanded == "~":
        expanded = home_str + "/"
        tilde_prefix = True
        lookup_token = "~/"
    elif expanded.startswith("~/"):
        expanded = home_str + expanded[1:]
        tilde_prefix = True

    if "/" in expanded:
        dir_part, partial_name = expanded.rsplit("/", 1)
        search_dir = Path(dir_part if dir_part else "/")
        if not search_dir.is_absolute():
            search_dir = base_dir / search_dir
        typed_dir_prefix = lookup_token.rsplit("/", 1)[0] + "/"
    else:
        partial_name = expanded
        search_dir = base_dir
        typed_dir_prefix = ""

    if not search_dir.exists() or not search_dir.is_dir():
        return {"ok": True, "completed_line": raw_line, "matches": []}

    show_hidden = partial_name.startswith(".")
    exact_entries: list[tuple[str, bool]] = []
    ci_entries: list[tuple[str, bool]] = []

    try:
        for entry in search_dir.iterdir():
            name = entry.name
            if not show_hidden and name.startswith("."):
                continue
            is_d = entry.is_dir()
            if dirs_only and not is_d:
                continue
            if name.startswith(partial_name):
                exact_entries.append((name, is_d))
            elif partial_name and name.lower().startswith(partial_name.lower()):
                ci_entries.append((name, is_d))
    except OSError:
        return {"ok": True, "completed_line": raw_line, "matches": []}

    chosen = sorted(exact_entries or ci_entries, key=lambda item: (not item[1], item[0].lower()))[:40]
    if not chosen:
        return {"ok": True, "completed_line": raw_line, "matches": []}

    display_matches = [name + ("/" if is_d else "") for name, is_d in chosen]

    def _fmt_path_piece(name_str: str) -> str:
        # Escape spaces for unquoted shell tokens
        return name_str.replace(" ", "\\ ")

    if len(chosen) == 1:
        name, is_d = chosen[0]
        tail = "/" if is_d else " "
        completed_tok = f"{typed_dir_prefix}{_fmt_path_piece(name)}{tail}"
        if tilde_prefix and completed_tok.startswith(home_str):
            completed_tok = "~" + completed_tok[len(home_str):]
        return {
            "ok": True,
            "completed_line": f"{line_prefix}{completed_tok}",
            "matches": display_matches,
        }

    # Multiple matches: complete shared prefix (case-preserving from candidates)
    names_only = [name for name, _ in chosen]
    cp = _common_prefix(names_only)
    if not cp and partial_name:
        # Case-insensitive common prefix
        cp_low = _common_prefix([n.lower() for n in names_only])
        if len(cp_low) >= len(partial_name):
            cp = names_only[0][: len(cp_low)]

    if len(cp) >= len(partial_name) and cp:
        completed_tok = f"{typed_dir_prefix}{_fmt_path_piece(cp)}"
    else:
        completed_tok = token

    return {
        "ok": True,
        "completed_line": f"{line_prefix}{completed_tok}",
        "matches": display_matches,
    }


class PairingVault:
    """Thread-safe persistent pairing secrets, tokens, and WebAuthn passkey management."""

    def __init__(self, vault_path: Path = VAULT_FILE) -> None:
        self.vault_path = vault_path
        self._lock = threading.Lock()
        self.pairing_pin: str = ""
        self.pairing_secret: str = ""
        self.paired_tokens: dict[str, dict[str, Any]] = {}
        self.webauthn_credentials: dict[str, dict[str, Any]] = {}
        self.failed_attempts: list[float] = []
        self.active_challenges: dict[str, float] = {}
        self.biometric_leases: dict[str, float] = {}
        self._load_or_create()

    def _load_or_create(self) -> None:
        self.vault_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if self.vault_path.exists():
            try:
                data = json.loads(self.vault_path.read_text(encoding="utf-8"))
                self.pairing_pin = str(data.get("pairing_pin", "")).strip()
                self.pairing_secret = str(data.get("pairing_secret", "")).strip()
                self.paired_tokens = data.get("tokens", {})
                self.webauthn_credentials = data.get("webauthn_credentials", {})
                if self.pairing_pin and self.pairing_secret:
                    return
            except Exception as exc:
                logger.warning("Could not read vault (%s); generating fresh credentials.", exc)

        # Generate fresh pairing credentials
        self.pairing_pin = f"{secrets.randbelow(900000) + 100000}"
        self.pairing_secret = secrets.token_urlsafe(32)
        self.paired_tokens = {}
        self.webauthn_credentials = {}
        self._save_unlocked()

    def _save_unlocked(self) -> None:
        payload = {
            "pairing_pin": self.pairing_pin,
            "pairing_secret": self.pairing_secret,
            "tokens": self.paired_tokens,
            "webauthn_credentials": self.webauthn_credentials,
            "updated_at": time.time(),
        }
        tmp_file = self.vault_path.with_suffix(".tmp")
        tmp_file.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        try:
            os.chmod(tmp_file, 0o600)
        except OSError:
            pass
        tmp_file.replace(self.vault_path)
        try:
            os.chmod(self.vault_path, 0o600)
        except OSError:
            pass

    def verify_pin(self, candidate_pin: str) -> tuple[bool, str]:
        with self._lock:
            now = time.time()
            self.failed_attempts = [t for t in self.failed_attempts if now - t < PIN_RATE_WINDOW_SECONDS]
            if len(self.failed_attempts) >= PIN_MAX_FAILED_ATTEMPTS:
                retry_wait = int(PIN_RATE_WINDOW_SECONDS - (now - self.failed_attempts[0]))
                return False, f"Too many failed attempts. Rate limited for {max(1, retry_wait)}s."

            clean_cand = candidate_pin.replace("-", "").replace(" ", "").strip()
            clean_pin = self.pairing_pin.replace("-", "").replace(" ", "").strip()
            if hmac.compare_digest(clean_cand, clean_pin):
                return True, "OK"

            self.failed_attempts.append(now)
            return False, "Invalid 6-digit pairing PIN."

    def verify_secret(self, candidate_secret: str) -> bool:
        with self._lock:
            return hmac.compare_digest(candidate_secret.strip(), self.pairing_secret)

    def mint_token(self, client_name: str = "Mobile Client") -> str:
        token = secrets.token_hex(32)
        token_hash = _sha256_hex(token)
        with self._lock:
            self.paired_tokens[token_hash] = {
                "client_name": client_name,
                "created_at": time.time(),
                "last_used": time.time(),
            }
            self._save_unlocked()
        return token

    def verify_token(self, token: str | None) -> bool:
        if not token or not isinstance(token, str):
            return False
        token_hash = _sha256_hex(token.strip())
        with self._lock:
            entry = self.paired_tokens.get(token_hash)
            if entry:
                entry["last_used"] = time.time()
                return True
            return False

    def revoke_token(self, token: str) -> bool:
        token_hash = _sha256_hex(token.strip())
        with self._lock:
            if token_hash in self.paired_tokens:
                del self.paired_tokens[token_hash]
                self._save_unlocked()
                return True
            return False

    def mint_webauthn_challenge(self) -> str:
        with self._lock:
            now = time.time()
            self.active_challenges = {c: exp for c, exp in self.active_challenges.items() if exp > now}
            raw_bytes = secrets.token_bytes(32)
            challenge_str = base64.urlsafe_b64encode(raw_bytes).decode("ascii").rstrip("=")
            self.active_challenges[challenge_str] = now + 180.0
            return challenge_str

    def verify_webauthn_challenge(self, challenge_str: str) -> bool:
        with self._lock:
            now = time.time()
            exp = self.active_challenges.pop(challenge_str, None)
            return exp is not None and exp > now

    def register_passkey(self, cred_id: str, public_key_b64: str, client_name: str = "iPhone Face ID") -> None:
        with self._lock:
            self.webauthn_credentials[cred_id] = {
                "public_key": public_key_b64,
                "client_name": client_name,
                "registered_at": time.time(),
            }
            self._save_unlocked()

    def grant_biometric_lease(self, token_hash: str, duration: float = BIOMETRIC_LEASE_SECONDS) -> None:
        with self._lock:
            self.biometric_leases[token_hash] = time.time() + duration

    def has_active_biometric_lease(self, token_hash: str) -> bool:
        with self._lock:
            exp = self.biometric_leases.get(token_hash, 0.0)
            return exp > time.time()


CLOUDFLARED_RELEASE_BASE = "https://github.com/cloudflare/cloudflared/releases/latest/download"
MAX_CLOUDFLARED_DOWNLOAD_BYTES = 150 * 1024 * 1024  # 150 MiB safety ceiling


class TunnelManager:
    """Manages zero-config outbound tunnels (Cloudflare Quick Tunnels / Tailscale)."""

    def __init__(self, port: int = 8790) -> None:
        self.port = port
        self.proc: subprocess.Popen[str] | None = None
        self.tunnel_url: str = ""
        self.active: bool = False
        self._lock = threading.Lock()

    @staticmethod
    def _managed_cloudflared_path() -> Path:
        return Path.home() / ".mith-terminal" / "bin" / (
            "cloudflared.exe" if platform.system() == "Windows" else "cloudflared"
        )

    @staticmethod
    def _resolve_cloudflared_asset(
        sys_name: str | None = None,
        machine: str | None = None,
    ) -> tuple[str, bool] | None:
        """Map host (OS, arch) to official Cloudflare GitHub release (asset_filename, is_tgz)."""
        s = (sys_name or platform.system()).strip().lower()
        m = (machine or platform.machine()).strip().lower()
        if s == "linux":
            if m in ("x86_64", "amd64"):
                return ("cloudflared-linux-amd64", False)
            if m in ("aarch64", "arm64"):
                return ("cloudflared-linux-arm64", False)
        elif s == "darwin":
            if m in ("arm64", "aarch64"):
                return ("cloudflared-darwin-arm64.tgz", True)
            if m in ("x86_64", "amd64"):
                return ("cloudflared-darwin-amd64.tgz", True)
        elif s == "windows":
            if m in ("amd64", "x86_64"):
                return ("cloudflared-windows-amd64.exe", False)
            if m in ("arm64", "aarch64"):
                return ("cloudflared-windows-arm64.exe", False)
        return None

    @staticmethod
    def _safe_extract_cloudflared_tgz(archive_path: Path, dest_file: Path) -> None:
        """Safely extract only the `cloudflared` regular-file member from a .tgz without path traversal."""
        with tarfile.open(archive_path, mode="r:gz") as tf:
            target_member: tarfile.TarInfo | None = None
            for member in tf.getmembers():
                norm_parts = Path(member.name.replace("\\", "/")).parts
                if ".." in norm_parts:
                    raise PermissionError(f"Blocked unsafe tar member path: {member.name}")
                if not member.isfile() or member.issym() or member.islnk():
                    continue
                if Path(member.name).name == "cloudflared":
                    target_member = member
                    break

            if target_member is None:
                raise FileNotFoundError("Archive did not contain a regular 'cloudflared' binary member.")
            if target_member.size <= 0 or target_member.size > MAX_CLOUDFLARED_DOWNLOAD_BYTES:
                raise ValueError(f"Invalid cloudflared binary size in archive: {target_member.size}")

            src_stream = tf.extractfile(target_member)
            if src_stream is None:
                raise OSError("Unable to stream 'cloudflared' member from tar archive.")
            with src_stream, open(dest_file, "wb") as out_f:
                shutil.copyfileobj(src_stream, out_f, length=65536)

    def find_cloudflared(self) -> str | None:
        cand = shutil.which("cloudflared")
        if cand:
            return cand
        managed_bin = self._managed_cloudflared_path()
        bin_name = "cloudflared.exe" if platform.system() == "Windows" else "cloudflared"
        user_paths = [
            managed_bin,
            Path.home() / ".local" / "bin" / bin_name,
            Path("/usr/local/bin/cloudflared"),
            Path("/opt/homebrew/bin/cloudflared"),
        ]
        for p in user_paths:
            if p.exists() and p.is_file() and (platform.system() == "Windows" or os.access(p, os.X_OK)):
                return str(p)
        return None

    def ensure_cloudflared(self) -> str | None:
        existing = self.find_cloudflared()
        if existing:
            return existing

        if os.getenv("MITH_NO_AUTO_CLOUDFLARED", "0") == "1":
            logger.info("Auto-download of cloudflared skipped (MITH_NO_AUTO_CLOUDFLARED=1).")
            return None

        asset_info = self._resolve_cloudflared_asset()
        if asset_info is None:
            logger.warning(
                "Unsupported platform for automatic cloudflared binary (%s %s); continuing on LAN.",
                platform.system(),
                platform.machine(),
            )
            return None

        asset_name, is_tgz = asset_info
        dest_bin = self._managed_cloudflared_path()
        bin_dir = dest_bin.parent
        tmp_dl = bin_dir / f".{asset_name}.{os.getpid()}.part"
        tmp_bin = bin_dir / f".cloudflared.{os.getpid()}.stage"

        try:
            bin_dir.mkdir(mode=0o755, parents=True, exist_ok=True)
            download_url = f"{CLOUDFLARED_RELEASE_BASE}/{asset_name}"
            logger.info(
                "cloudflared not found; auto-downloading official binary (%s) into %s ...",
                asset_name,
                dest_bin,
            )

            def _fetch_bytes(url: str) -> bytes:
                with urllib.request.urlopen(url, timeout=25) as resp:
                    hdrs = getattr(resp, "headers", None)
                    if hdrs is not None:
                        cl_val = hdrs.get("Content-Length")
                        if cl_val and int(cl_val) > MAX_CLOUDFLARED_DOWNLOAD_BYTES:
                            raise ValueError("Remote cloudflared binary exceeds safety size limit.")
                    payload_bytes = resp.read()
                    if not isinstance(payload_bytes, (bytes, bytearray)) or len(payload_bytes) == 0:
                        raise OSError("Empty response while downloading cloudflared.")
                    if len(payload_bytes) > MAX_CLOUDFLARED_DOWNLOAD_BYTES:
                        raise ValueError("Downloaded cloudflared binary exceeds safety size limit.")
                    return bytes(payload_bytes)

            try:
                raw_bytes = _fetch_bytes(download_url)
            except urllib.error.HTTPError as http_exc:
                # Windows ARM64 seamlessly runs amd64 under Prism if upstream lacks a separate arm64 exe
                if http_exc.code == 404 and asset_name == "cloudflared-windows-arm64.exe":
                    fallback_url = f"{CLOUDFLARED_RELEASE_BASE}/cloudflared-windows-amd64.exe"
                    logger.info("cloudflared-windows-arm64.exe returned 404; falling back to cloudflared-windows-amd64.exe ...")
                    raw_bytes = _fetch_bytes(fallback_url)
                else:
                    raise

            tmp_dl.write_bytes(raw_bytes)

            if is_tgz:
                self._safe_extract_cloudflared_tgz(tmp_dl, tmp_bin)
            else:
                tmp_dl.replace(tmp_bin)

            try:
                tmp_bin.chmod(0o755)
            except OSError:
                pass
            tmp_bin.replace(dest_bin)
            try:
                dest_bin.chmod(0o755)
            except OSError:
                pass

            logger.info(
                "Official cloudflared binary ready (%.1f MB) at %s",
                len(raw_bytes) / (1024 * 1024),
                dest_bin,
            )
            return str(dest_bin)
        except Exception as exc:
            logger.info(
                "Could not auto-download cloudflared (%s); continuing cleanly in LAN/Tailscale mode.",
                exc,
            )
            return None
        finally:
            for leftover in (tmp_dl, tmp_bin):
                try:
                    if leftover.exists():
                        leftover.unlink()
                except OSError:
                    pass

    def start_quick_tunnel(self) -> str | None:
        cf_bin = self.ensure_cloudflared()
        if not cf_bin:
            logger.info("Cloudflare tunnel (cloudflared) not available; using LAN/Tailscale direct routing.")
            return None

        with self._lock:
            if self.active and self.tunnel_url:
                return self.tunnel_url

            logger.info("Initializing zero-configuration Cloudflare Quick Tunnel on port %d...", self.port)
            try:
                self.proc = subprocess.Popen(
                    [cf_bin, "tunnel", "--no-autoupdate", "--url", f"http://127.0.0.1:{self.port}"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.PIPE,
                    text=True,
                    bufsize=1,
                )
                self.active = True

                # Read stderr for the ephemeral trycloudflare URL
                stderr_pipe = self.proc.stderr
                assert stderr_pipe is not None
                pattern = re.compile(r"https://[a-zA-Z0-9-]+\.trycloudflare\.com")
                start_ts = time.time()
                while time.time() - start_ts < 8.0:
                    line = stderr_pipe.readline()
                    if not line:
                        break
                    match = pattern.search(line)
                    if match:
                        self.tunnel_url = match.group(0)
                        logger.info("Zero-Config Public Tunnel Ready: %s", self.tunnel_url)
                        break

                # Continuously drain stderr in background so OS pipe buffer never fills/deadlocks
                def _drain_pipe(pipe: Any) -> None:
                    try:
                        for rem_line in pipe:
                            if not self.tunnel_url:
                                m_late = pattern.search(rem_line)
                                if m_late:
                                    self.tunnel_url = m_late.group(0)
                                    logger.info("Zero-Config Public Tunnel Ready (late): %s", self.tunnel_url)
                    except Exception:
                        pass

                threading.Thread(target=_drain_pipe, args=(stderr_pipe,), name="cf-stderr-drain", daemon=True).start()
                return self.tunnel_url or None
            except Exception as exc:
                logger.warning("Could not spawn Cloudflare tunnel: %s", exc)
                return None

    def stop(self) -> None:
        with self._lock:
            if self.proc:
                try:
                    self.proc.terminate()
                    self.proc.wait(timeout=2.0)
                except Exception:
                    try:
                        self.proc.kill()
                    except Exception:
                        pass
                self.proc = None
            self.active = False


class DaemonState:
    def __init__(self, initial_cwd: Path | str | None = None, port: int = 8790) -> None:
        self.start_time = time.time()
        home = Path.home()
        cand = Path(initial_cwd) if initial_cwd else home
        if not cand.is_dir():
            cand = Path.cwd()
        self.current_cwd: str = str(cand.resolve())
        self.port: int = port
        self.lan_ip: str = _get_lan_ip()
        self.vault = PairingVault()
        self.tunnel = TunnelManager(port=port)
        self.pty_manager = PtySessionManager()
        self._proc_lock = threading.Lock()
        self.active_proc: subprocess.Popen[str] | None = None

    def set_active_proc(self, proc: subprocess.Popen[str] | None) -> None:
        with self._proc_lock:
            self.active_proc = proc

    def cancel_active_process(self) -> tuple[bool, int | None]:
        """Send SIGINT (with SIGTERM fallback) to the currently running command group."""
        with self._proc_lock:
            proc = self.active_proc
        if proc is None or proc.poll() is not None:
            return False, None
        pid = proc.pid
        try:
            if platform.system() != "Windows":
                pgid = os.getpgid(pid)
                os.killpg(pgid, signal.SIGINT)
                for _ in range(6):
                    if proc.poll() is not None:
                        return True, pid
                    time.sleep(0.05)
                if proc.poll() is None:
                    os.killpg(pgid, signal.SIGTERM)
            else:
                subprocess.run(
                    ["taskkill", "/F", "/T", "/PID", str(pid)],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=3.0,
                    check=False,
                )
                if proc.poll() is None:
                    proc.terminate()
            return True, pid
        except ProcessLookupError:
            return False, None
        except Exception as exc:
            logger.warning("Failed to interrupt process %s: %s", pid, exc)
            try:
                proc.kill()
                return True, pid
            except Exception:
                return False, None


daemon_state = DaemonState()
atexit.register(daemon_state.tunnel.stop)
atexit.register(daemon_state.pty_manager.close_all)


def _start_udp_discovery_responder(port: int = 8791, target_tcp_port: int = 8790) -> None:
    """Listen for UDP discovery broadcasts and respond with minimal non-sensitive service info."""
    def _responder() -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("0.0.0.0", port))
            sock.settimeout(2.0)
            logger.info("Local network auto-discovery listening on UDP port %d", port)
        except Exception as exc:
            logger.warning("Could not bind UDP discovery port %d: %s", port, exc)
            return

        while True:
            try:
                data, addr = sock.recvfrom(1024)
                msg = data.decode("utf-8", errors="ignore").strip()
                if "MITH_DISCOVER" in msg:
                    reply = json.dumps({
                        "ok": True,
                        "service": "mith-terminal",
                        "port": target_tcp_port,
                        "system": platform.system(),
                    }).encode("utf-8")
                    sock.sendto(reply, addr)
            except socket.timeout:
                continue
            except Exception:
                continue

    threading.Thread(target=_responder, name="mith-udp-discovery", daemon=True).start()


MAX_JSON_BODY_BYTES = 65_536  # 64 KiB DoS ceiling per JSON API request


def _is_ip_literal(hostname: str) -> bool:
    """Return True if hostname is an IPv4 or IPv6 address literal (immune to DNS rebinding)."""
    clean = hostname.strip("[]")
    if not clean:
        return False
    for fam in (socket.AF_INET, socket.AF_INET6):
        try:
            socket.inet_pton(fam, clean)
            return True
        except OSError:
            continue
    return False


class MithTerminalHandler(BaseHTTPRequestHandler):
    def _is_valid_host_header(self) -> bool:
        """Defend localhost/LAN consumers against DNS rebinding attacks."""
        raw_host = (self.headers.get("X-Forwarded-Host") or self.headers.get("Host") or "").strip()
        if not raw_host:
            return True
        first_host = raw_host.split(",")[0].strip()
        if first_host.startswith("["):
            host_only = first_host.split("]")[0] + "]"
        else:
            host_only = first_host.split(":")[0].lower()

        if not host_only:
            return True
        if host_only in {"localhost", "127.0.0.1", "[::1]", "::1"}:
            return True
        if _is_ip_literal(host_only):
            return True
        node_low = platform.node().strip().lower()
        if node_low and host_only in {node_low, f"{node_low}.local"}:
            return True
        if host_only.endswith((".local", ".ts.net")):
            return True
        if host_only.endswith(".trycloudflare.com") and daemon_state.tunnel.active:
            active_cf_host = (urlparse(daemon_state.tunnel.tunnel_url).hostname or "").lower()
            if not active_cf_host or host_only == active_cf_host:
                return True
        extra_allowed = {
            h.strip().lower()
            for h in os.getenv("MITH_ALLOWED_HOSTS", "").split(",")
            if h.strip()
        }
        if host_only in extra_allowed:
            return True
        logger.warning("Blocked untrusted Host header (DNS rebinding guard): Host=%s", raw_host)
        return False

    def _evaluate_origin(self) -> tuple[bool, str | None]:
        """
        Validate browser Origin header against trusted same-host / local / tunnel origins.
        Returns (is_allowed, echo_cors_origin_or_None).
        """
        origin_hdr = self.headers.get("Origin", "").strip()
        if not origin_hdr:
            return True, None
        parsed = urlparse(origin_hdr)
        scheme = (parsed.scheme or "").lower()
        origin_host = (parsed.hostname or "").lower()
        if not origin_host:
            return False, None
        if scheme in {"capacitor", "ionic"} and origin_host == "localhost":
            return True, origin_hdr
        raw_req_host = self.headers.get("X-Forwarded-Host") or self.headers.get("Host") or ""
        req_host = raw_req_host.split(",")[0].strip().split(":")[0].lower()
        if origin_host == req_host:
            return True, origin_hdr
        safe_local = {"localhost", "127.0.0.1"}
        if origin_host in safe_local and req_host in safe_local:
            return True, origin_hdr
        if origin_host.endswith(".ts.net") and (req_host in safe_local or req_host.endswith(".ts.net")):
            return True, origin_hdr
        tunnel_url = daemon_state.tunnel.tunnel_url or ""
        if tunnel_url:
            tunnel_host = (urlparse(tunnel_url).hostname or "").lower()
            if tunnel_host and origin_host == tunnel_host:
                return True, origin_hdr
        return False, None

    def _add_security_headers(self, is_html: bool = False) -> None:
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        if is_html:
            self.send_header(
                "Content-Security-Policy",
                "frame-ancestors 'none'; base-uri 'self'; object-src 'none'",
            )
        allowed_origin, cors_origin = self._evaluate_origin()
        if allowed_origin and cors_origin:
            self.send_header("Access-Control-Allow-Origin", cors_origin)
            self.send_header("Vary", "Origin")
            self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With, X-Biometric-Grant")
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS, HEAD")

    def _read_json_body(self, allow_empty: bool = False) -> dict[str, Any] | None:
        """Read and parse a bounded JSON request body (<= 64 KiB); sends HTTP error and returns None on failure."""
        try:
            content_length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self._send_json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "Invalid Content-Length header."})
            return None
        if content_length < 0 or content_length > MAX_JSON_BODY_BYTES:
            self._send_json(
                HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                {"ok": False, "error": f"Request payload exceeds {MAX_JSON_BODY_BYTES} byte limit."},
            )
            return None
        if content_length == 0:
            if allow_empty:
                return {}
            self._send_json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "Empty JSON body."})
            return None
        raw = self.rfile.read(content_length)
        try:
            parsed = json.loads(raw.decode("utf-8"))
        except Exception:
            self._send_json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "Invalid JSON"})
            return None
        if not isinstance(parsed, dict):
            self._send_json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "Expected JSON object."})
            return None
        return parsed

    def _send_json(self, status: int, payload: dict[str, Any], extra_headers: dict[str, str] | None = None) -> None:
        data = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self._add_security_headers(is_html=False)
        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def _send_bytes(self, status: int, data: bytes, content_type: str = "text/html", extra_headers: dict[str, str] | None = None) -> None:
        self.send_response(status)
        if content_type.startswith(("text/", "application/json", "application/javascript", "application/manifest+json")) and "charset=" not in content_type:
            ct_header = f"{content_type}; charset=utf-8"
        else:
            ct_header = content_type
        self.send_header("Content-Type", ct_header)
        self.send_header("Content-Length", str(len(data)))
        self._add_security_headers(is_html=content_type.startswith("text/html"))
        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def _extract_auth_token(self) -> str | None:
        auth_hdr = self.headers.get("Authorization", "")
        if auth_hdr.lower().startswith("bearer "):
            return auth_hdr[7:].strip()
        cookie_hdr = self.headers.get("Cookie", "")
        if "mith_term_token=" in cookie_hdr:
            for part in cookie_hdr.split(";"):
                if part.strip().startswith("mith_term_token="):
                    return part.strip().split("=", 1)[1].strip()
        return None

    def _is_authenticated(self) -> bool:
        tok = self._extract_auth_token()
        if not tok:
            return False
        return daemon_state.vault.verify_token(tok) or daemon_state.vault.verify_secret(tok)

    def _resolve_owner_hash(self) -> str | None:
        if not self._is_authenticated():
            return None
        tok = self._extract_auth_token()
        return _sha256_hex(tok) if tok else None

    def _is_allowed_ws_origin(self) -> bool:
        allowed, _ = self._evaluate_origin()
        if not allowed:
            raw_req_host = self.headers.get("X-Forwarded-Host") or self.headers.get("Host") or ""
            logger.warning(
                "Blocked cross-origin WebSocket upgrade: Origin=%s Host=%s",
                self.headers.get("Origin", ""),
                raw_req_host,
            )
        return allowed

    def _resolve_ws_owner_hash(self, qs: dict[str, list[str]]) -> str | None:
        """
        Authenticate WebSocket upgrade via:
          1. Single-use ephemeral ticket (?ticket=...) — preferred, zero token in URL logs
          2. Explicit Authorization: Bearer header (CLI / native clients)
          3. Same-origin mith_term_token cookie (after strict _is_allowed_ws_origin check)
        """
        ticket = (qs.get("ticket", [""])[0] or "").strip()
        if ticket:
            owner_h = daemon_state.pty_manager.consume_ws_ticket(ticket)
            if owner_h:
                return owner_h

        auth_hdr = self.headers.get("Authorization", "")
        if auth_hdr.lower().startswith("bearer "):
            bearer_tok = auth_hdr[7:].strip()
            if daemon_state.vault.verify_token(bearer_tok) or daemon_state.vault.verify_secret(bearer_tok):
                return _sha256_hex(bearer_tok)

        tok = self._extract_auth_token()
        if tok and (daemon_state.vault.verify_token(tok) or daemon_state.vault.verify_secret(tok)):
            return _sha256_hex(tok)
        return None

    def do_OPTIONS(self) -> None:
        if not self._is_valid_host_header():
            self._send_json(HTTPStatus.FORBIDDEN, {"ok": False, "error": "Forbidden Host header."})
            return
        allowed_origin, _ = self._evaluate_origin()
        if not allowed_origin:
            self._send_json(HTTPStatus.FORBIDDEN, {"ok": False, "error": "Forbidden cross-origin preflight."})
            return
        self.send_response(HTTPStatus.NO_CONTENT)
        self._add_security_headers()
        self.end_headers()

    def do_HEAD(self) -> None:
        if not self._is_valid_host_header():
            self.send_response(HTTPStatus.FORBIDDEN)
            self.end_headers()
            return
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self._add_security_headers(is_html=True)
        self.end_headers()

    def do_GET(self) -> None:
        if not self._is_valid_host_header():
            self._send_json(HTTPStatus.FORBIDDEN, {"ok": False, "error": "Forbidden Host header (DNS rebinding guard)."})
            return
        path = self.path.split("?")[0]

        if path in ("/", "/index.html"):
            if INDEX_HTML.exists():
                self._send_bytes(HTTPStatus.OK, INDEX_HTML.read_bytes(), "text/html")
            else:
                self._send_bytes(HTTPStatus.NOT_FOUND, b"index.html not found.", "text/plain")
            return

        if path.startswith(("/vendor/", "/api/terminal/vendor/")):
            rel_name = path.rsplit("/", 1)[-1]
            vendor_mime = {
                "xterm.js": "application/javascript",
                "xterm-addon-fit.js": "application/javascript",
                "xterm.css": "text/css",
            }
            if rel_name in vendor_mime:
                asset_path = VENDOR_DIR / rel_name
                if asset_path.exists():
                    self._send_bytes(
                        HTTPStatus.OK,
                        asset_path.read_bytes(),
                        vendor_mime[rel_name],
                        extra_headers={"Cache-Control": "public, max-age=86400"},
                    )
                    return
            self._send_json(HTTPStatus.NOT_FOUND, {"ok": False, "error": "Vendor asset not found"})
            return

        if path in ("/api/ws", "/api/terminal/ws"):
            if not self._is_allowed_ws_origin():
                self._send_json(
                    HTTPStatus.FORBIDDEN,
                    {"ok": False, "error": "Forbidden cross-origin WebSocket handshake."},
                )
                return
            qs = parse_qs(urlparse(self.path).query)
            owner_hash = self._resolve_ws_owner_hash(qs)
            if not owner_hash:
                self._send_json(HTTPStatus.UNAUTHORIZED, {"ok": False, "error": "Unauthorized WebSocket handshake."})
                return

            upgrade_hdr = self.headers.get("Upgrade", "").lower()
            sec_key = self.headers.get("Sec-WebSocket-Key", "").strip()
            if "websocket" not in upgrade_hdr or not sec_key:
                self._send_json(
                    HTTPStatus.BAD_REQUEST,
                    {"ok": False, "error": "Expected RFC 6455 WebSocket Upgrade headers."},
                )
                return

            try:
                cols = int(qs.get("cols", ["80"])[0])
                rows = int(qs.get("rows", ["26"])[0])
            except ValueError:
                cols, rows = 80, 26
            req_sid = (qs.get("session_id", [""])[0] or "").strip() or None
            req_label = (qs.get("label", [""])[0] or "").strip()[:40]
            init_cmd = (qs.get("cmd", [""])[0] or "").strip()

            sess, reattached = daemon_state.pty_manager.get_or_create(
                owner_hash=owner_hash,
                cwd=daemon_state.current_cwd,
                cols=cols,
                rows=rows,
                session_id=req_sid,
                label=req_label,
            )

            accept_val = ws_compute_accept_key(sec_key)
            handshake = (
                "HTTP/1.1 101 Switching Protocols\r\n"
                "Upgrade: websocket\r\n"
                "Connection: Upgrade\r\n"
                f"Sec-WebSocket-Accept: {accept_val}\r\n"
                "X-Mith-Pty-Session: " + sess.session_id + "\r\n"
                "\r\n"
            ).encode("ascii")

            self.close_connection = True
            self.connection.sendall(handshake)
            logger.info("WebSocket PTY connected (session=%s, reattached=%s, %dx%d)", sess.session_id, reattached, cols, rows)
            serve_websocket_pty(self.connection, sess, reattached=reattached, initial_cmd=init_cmd)
            return

        if path in ("/api/pty/list", "/api/terminal/pty/list"):
            owner_hash = self._resolve_owner_hash()
            if not owner_hash:
                self._send_json(HTTPStatus.UNAUTHORIZED, {"ok": False, "error": "Unauthorized."})
                return
            self._send_json(
                HTTPStatus.OK,
                {
                    "ok": True,
                    "sessions": daemon_state.pty_manager.list_sessions(owner_hash),
                    "max_sessions": MAX_ACTIVE_PTY_SESSIONS,
                },
            )
            return

        if path in ("/api/pty/poll", "/api/terminal/pty/poll"):
            owner_hash = self._resolve_owner_hash()
            if not owner_hash:
                self._send_json(HTTPStatus.UNAUTHORIZED, {"ok": False, "error": "Unauthorized."})
                return
            qs = parse_qs(urlparse(self.path).query)
            sid = (qs.get("session_id", [""])[0] or "").strip()
            try:
                cursor = int(qs.get("cursor", ["0"])[0])
                timeout_ms = int(qs.get("timeout_ms", ["8000"])[0])
            except ValueError:
                cursor, timeout_ms = 0, 8000

            sess_opt = daemon_state.pty_manager.get_owned(sid, owner_hash)
            if sess_opt is None:
                self._send_json(HTTPStatus.NOT_FOUND, {"ok": False, "error": "PTY session not found or expired."})
                return
            poll_res = sess_opt.poll_http_chunks(cursor=cursor, timeout_sec=max(0.0, min(15.0, timeout_ms / 1000.0)))
            self._send_json(HTTPStatus.OK, poll_res)
            return

        if path in ("/apple-touch-icon.png", "/apple-touch-icon-precomposed.png", "/icon-180.png", "/api/terminal/icon-180.png"):
            if ICON_180_PNG.exists():
                self._send_bytes(
                    HTTPStatus.OK,
                    ICON_180_PNG.read_bytes(),
                    "image/png",
                    extra_headers={"Cache-Control": "public, max-age=86400"},
                )
            else:
                self._send_bytes(HTTPStatus.NOT_FOUND, b"icon-180.png not found.", "text/plain")
            return

        if path in ("/icon-512.png", "/api/terminal/icon-512.png"):
            if ICON_512_PNG.exists():
                self._send_bytes(
                    HTTPStatus.OK,
                    ICON_512_PNG.read_bytes(),
                    "image/png",
                    extra_headers={"Cache-Control": "public, max-age=86400"},
                )
            else:
                self._send_bytes(HTTPStatus.NOT_FOUND, b"icon-512.png not found.", "text/plain")
            return

        if path in ("/manifest.json", "/api/terminal/manifest.json"):
            qs = parse_qs(urlparse(self.path).query)
            allowed_starts = {"/", "/terminal", "/mith-terminal"}
            raw_start = (qs.get("start", [""])[0] or "").strip()
            if raw_start not in allowed_starts:
                ref_path = urlparse(self.headers.get("Referer", "")).path.rstrip("/") or "/"
                if ref_path.startswith("/mith-terminal"):
                    raw_start = "/mith-terminal"
                elif ref_path.startswith("/terminal"):
                    raw_start = "/terminal"
                else:
                    raw_start = "/"
            start_url = raw_start
            manifest_payload = {
                "id": start_url,
                "name": "MiTH Terminal",
                "short_name": "MiTH Term",
                "start_url": start_url,
                "scope": start_url,
                "display": "standalone",
                "orientation": "any",
                "background_color": "#09090b",
                "theme_color": "#09090b",
                "description": "Zero-Clutter Mobile Developer Terminal with Biometric Gatekeeper",
                "icons": [
                    {
                        "src": "/api/terminal/icon-180.png",
                        "sizes": "180x180",
                        "type": "image/png",
                        "purpose": "any",
                    },
                    {
                        "src": "/api/terminal/icon-512.png",
                        "sizes": "512x512",
                        "type": "image/png",
                        "purpose": "any maskable",
                    },
                ],
            }
            self._send_bytes(
                HTTPStatus.OK,
                json.dumps(manifest_payload, indent=2).encode("utf-8"),
                "application/manifest+json",
                extra_headers={"Cache-Control": "no-cache"},
            )
            return

        if path in ("/api/bookmarks", "/api/terminal/bookmarks"):
            if not self._is_authenticated():
                self._send_json(
                    HTTPStatus.UNAUTHORIZED,
                    {"ok": False, "error": "Unauthorized. Pairing token required."},
                )
                return
            self._send_json(
                HTTPStatus.OK,
                {
                    "ok": True,
                    "cwd": daemon_state.current_cwd,
                    "bookmarks": _detect_host_bookmarks(),
                },
            )
            return

        if path in ("/api/ping", "/api/terminal/ping"):
            authed = self._is_authenticated()
            self._send_json(
                HTTPStatus.OK,
                {
                    "ok": True,
                    "service": "mith-terminal-daemon",
                    "version": "1.2.1",
                    "host": platform.node() if authed else "Protected Host",
                    "user": _current_username() if authed else "locked",
                    "home_dir": str(Path.home()) if authed else "~",
                    "cwd": daemon_state.current_cwd if authed else "~",
                    "system": platform.system(),
                    "release": platform.release() if authed else "",
                    "arch": platform.machine(),
                    "uptime_seconds": time.time() - daemon_state.start_time,
                    "authenticated": authed,
                    "lan_ip": daemon_state.lan_ip if authed else "",
                    "tunnel_url": daemon_state.tunnel.tunnel_url if authed else "",
                    "port": daemon_state.port,
                },
            )
            return

        if path in ("/api/auth/status", "/api/terminal/status"):
            authed = self._is_authenticated()
            self._send_json(
                HTTPStatus.OK,
                {
                    "ok": True,
                    "authenticated": authed,
                    "host": platform.node() if authed else "Protected Host",
                    "user": _current_username() if authed else "locked",
                    "home_dir": str(Path.home()) if authed else "~",
                    "cwd": daemon_state.current_cwd if authed else "~",
                    "tunnel_url": daemon_state.tunnel.tunnel_url if authed else "",
                },
            )
            return

        if path in ("/api/auth/webauthn/challenge", "/api/terminal/webauthn/challenge"):
            challenge = daemon_state.vault.mint_webauthn_challenge()
            self._send_json(
                HTTPStatus.OK,
                {
                    "ok": True,
                    "challenge": challenge,
                    "rp": {
                        "name": "MiTH Terminal",
                        "id": self.headers.get("Host", "").split(":")[0] or "localhost",
                    },
                },
            )
            return

        if path in ("/api/vitals", "/api/terminal/vitals"):
            if not self._is_authenticated():
                self._send_json(
                    HTTPStatus.UNAUTHORIZED,
                    {"ok": False, "error": "Unauthorized. Pairing token required for vitals telemetry."},
                )
                return
            vitals = _get_system_vitals(daemon_state.current_cwd)
            self._send_json(
                HTTPStatus.OK,
                {
                    "ok": True,
                    "host": platform.node(),
                    "user": _current_username(),
                    "cwd": daemon_state.current_cwd,
                    "uptime_seconds": round(time.time() - daemon_state.start_time),
                    "vitals": vitals,
                },
            )
            return

        self._send_json(HTTPStatus.NOT_FOUND, {"ok": False, "error": "Endpoint not found"})

    def do_POST(self) -> None:
        if not self._is_valid_host_header():
            self._send_json(HTTPStatus.FORBIDDEN, {"ok": False, "error": "Forbidden Host header (DNS rebinding guard)."})
            return
        allowed_origin, _ = self._evaluate_origin()
        if not allowed_origin:
            self._send_json(HTTPStatus.FORBIDDEN, {"ok": False, "error": "Forbidden cross-origin POST request."})
            return
        path = self.path.split("?")[0]

        if path in ("/api/ws-ticket", "/api/terminal/ws-ticket"):
            owner_hash = self._resolve_owner_hash()
            if not owner_hash:
                self._send_json(HTTPStatus.UNAUTHORIZED, {"ok": False, "error": "Unauthorized."})
                return
            if self._read_json_body(allow_empty=True) is None:
                return
            ticket = daemon_state.pty_manager.mint_ws_ticket(owner_hash, ttl_seconds=30.0)
            self._send_json(HTTPStatus.OK, {"ok": True, "ticket": ticket, "ttl_seconds": 30})
            return

        if path in ("/api/pty/open", "/api/terminal/pty/open"):
            owner_hash = self._resolve_owner_hash()
            if not owner_hash:
                self._send_json(HTTPStatus.UNAUTHORIZED, {"ok": False, "error": "Unauthorized."})
                return
            data = self._read_json_body(allow_empty=True)
            if data is None:
                return
            cols = int(data.get("cols", 80))
            rows = int(data.get("rows", 26))
            req_sid = str(data.get("session_id") or "").strip() or None
            req_label = str(data.get("label") or "").strip()[:40]
            init_cmd = str(data.get("cmd") or "").strip()
            sess, reattached = daemon_state.pty_manager.get_or_create(
                owner_hash=owner_hash,
                cwd=daemon_state.current_cwd,
                cols=cols,
                rows=rows,
                session_id=req_sid,
                label=req_label,
            )
            if init_cmd:
                sess.write_input(init_cmd + "\r")
            self._send_json(
                HTTPStatus.OK,
                {
                    "ok": True,
                    "session_id": sess.session_id,
                    "label": sess.label,
                    "reattached": reattached,
                    "cols": sess.cols,
                    "rows": sess.rows,
                },
            )
            return

        if path in ("/api/pty/input", "/api/terminal/pty/input"):
            owner_hash = self._resolve_owner_hash()
            if not owner_hash:
                self._send_json(HTTPStatus.UNAUTHORIZED, {"ok": False, "error": "Unauthorized."})
                return
            data = self._read_json_body(allow_empty=False)
            if data is None:
                return
            sid = str(data.get("session_id") or "").strip()
            sess_opt = daemon_state.pty_manager.get_owned(sid, owner_hash)
            if sess_opt is None:
                self._send_json(HTTPStatus.NOT_FOUND, {"ok": False, "error": "PTY session not found."})
                return
            payload_str = data.get("data", "")
            ok_w = sess_opt.write_input(str(payload_str))
            self._send_json(HTTPStatus.OK, {"ok": ok_w})
            return

        if path in ("/api/pty/resize", "/api/terminal/pty/resize"):
            owner_hash = self._resolve_owner_hash()
            if not owner_hash:
                self._send_json(HTTPStatus.UNAUTHORIZED, {"ok": False, "error": "Unauthorized."})
                return
            data = self._read_json_body(allow_empty=False)
            if data is None:
                return
            sid = str(data.get("session_id") or "").strip()
            sess_opt = daemon_state.pty_manager.get_owned(sid, owner_hash)
            if sess_opt is None:
                self._send_json(HTTPStatus.NOT_FOUND, {"ok": False, "error": "PTY session not found."})
                return
            ok_r = sess_opt.resize(int(data.get("cols", 80)), int(data.get("rows", 26)))
            self._send_json(HTTPStatus.OK, {"ok": ok_r})
            return

        if path in ("/api/pty/close", "/api/terminal/pty/close"):
            owner_hash = self._resolve_owner_hash()
            if not owner_hash:
                self._send_json(HTTPStatus.UNAUTHORIZED, {"ok": False, "error": "Unauthorized."})
                return
            data = self._read_json_body(allow_empty=True)
            if data is None:
                return
            sid = str(data.get("session_id") or "").strip()
            closed = daemon_state.pty_manager.close_session(sid, owner_hash)
            self._send_json(HTTPStatus.OK, {"ok": True, "closed": closed})
            return

        if path in ("/api/auth/pair", "/api/terminal/pair"):
            data = self._read_json_body(allow_empty=False)
            if data is None:
                return

            pin = str(data.get("pin", "")).strip()
            secret = str(data.get("secret", "")).strip()
            client_name = str(data.get("client_name", "iPhone Client")).strip()[:64]

            valid = False
            err_msg = "Invalid PIN or Secret"

            if secret:
                valid = daemon_state.vault.verify_secret(secret)
                if not valid:
                    err_msg = "Invalid pairing secret."
            elif pin:
                valid, err_msg = daemon_state.vault.verify_pin(pin)

            if not valid:
                logger.warning("Pairing rejected from %s (name: %s): %s", self.client_address[0], client_name, err_msg)
                self._send_json(HTTPStatus.UNAUTHORIZED, {"ok": False, "error": err_msg})
                return

            token = daemon_state.vault.mint_token(client_name)
            logger.info("Successfully paired client: %s (%s)", client_name, self.client_address[0])

            is_https = (self.headers.get("X-Forwarded-Proto", "").lower() == "https")
            sec_attr = "; Secure" if is_https else ""
            cookie_hdr = {
                "Set-Cookie": f"mith_term_token={token}; Path=/; Max-Age=7776000; SameSite=Strict; HttpOnly{sec_attr}"
            }
            self._send_json(
                HTTPStatus.OK,
                {
                    "ok": True,
                    "token": token,
                    "host": platform.node(),
                    "user": _current_username(),
                    "home_dir": str(Path.home()),
                    "cwd": daemon_state.current_cwd,
                    "tunnel_url": daemon_state.tunnel.tunnel_url,
                    "message": "Machine paired successfully.",
                },
                extra_headers=cookie_hdr,
            )
            return

        if path in ("/api/auth/webauthn/register", "/api/terminal/webauthn/register"):
            if not self._is_authenticated():
                self._send_json(HTTPStatus.UNAUTHORIZED, {"ok": False, "error": "Unauthorized."})
                return
            data = self._read_json_body(allow_empty=False)
            if data is None:
                return
            cred_id = str(data.get("id") or data.get("credential_id") or "").strip()[:256]
            pubkey = str(data.get("public_key") or "")[:4096]
            if cred_id:
                daemon_state.vault.register_passkey(cred_id, pubkey)
                self._send_json(HTTPStatus.OK, {"ok": True, "registered": True, "credential_id": cred_id})
            else:
                self._send_json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "Missing credential ID."})
            return

        if path in ("/api/auth/webauthn/verify", "/api/terminal/webauthn/verify"):
            if not self._is_authenticated():
                self._send_json(HTTPStatus.UNAUTHORIZED, {"ok": False, "error": "Unauthorized."})
                return
            data = self._read_json_body(allow_empty=False)
            if data is None:
                return
            challenge = str(data.get("challenge") or "").strip()

            valid_chal = bool(challenge) and daemon_state.vault.verify_webauthn_challenge(challenge)
            if not valid_chal:
                self._send_json(HTTPStatus.FORBIDDEN, {"ok": False, "error": "WebAuthn challenge expired or invalid."})
                return

            # Grant lease for current active session
            tok = self._extract_auth_token()
            if tok:
                tok_h = _sha256_hex(tok)
                daemon_state.vault.grant_biometric_lease(tok_h, duration=BIOMETRIC_LEASE_SECONDS)

            self._send_json(HTTPStatus.OK, {
                "ok": True,
                "biometric_verified": True,
                "lease_seconds": int(BIOMETRIC_LEASE_SECONDS)
            })
            return

        if path in ("/api/auth/unpair", "/api/terminal/unpair"):
            tok = self._extract_auth_token()
            if tok:
                daemon_state.vault.revoke_token(tok)
            self._send_json(HTTPStatus.OK, {"ok": True, "message": "Machine unlinked."})
            return

        if path in ("/api/copilot", "/api/terminal/copilot"):
            if not self._is_authenticated():
                self._send_json(HTTPStatus.UNAUTHORIZED, {"ok": False, "error": "Unauthorized."})
                return
            data = self._read_json_body(allow_empty=True)
            if data is None:
                return
            user_prompt = str(data.get("prompt", "")).strip()

            sys_prompt = (
                "You are MiTH Terminal Copilot. Propose a single concise shell command for the user's intent. "
                f"Current host: {platform.node()}, User: {_current_username()}, OS: {platform.system()}, CWD: {daemon_state.current_cwd}. "
                "Return strictly a JSON object: {\"command\": \"...\", \"explanation\": \"...\", \"is_destructive\": false}."
            )

            # 1. Host-side BYOK Gemini Flash API (GEMINI_API_KEY)
            host_gemini_key = os.getenv("GEMINI_API_KEY", "").strip()
            if host_gemini_key:
                try:
                    gemini_url = (
                        "https://generativelanguage.googleapis.com/v1beta/models/"
                        f"gemini-2.5-flash:generateContent?key={quote(host_gemini_key, safe='')}"
                    )
                    gemini_body = json.dumps(
                        {
                            "systemInstruction": {"parts": [{"text": sys_prompt}]},
                            "contents": [{"role": "user", "parts": [{"text": user_prompt}]}],
                            "generationConfig": {
                                "temperature": 0.1,
                                "responseMimeType": "application/json",
                            },
                        }
                    ).encode("utf-8")
                    req_obj = urllib.request.Request(
                        gemini_url,
                        data=gemini_body,
                        headers={"Content-Type": "application/json"},
                        method="POST",
                    )
                    with urllib.request.urlopen(req_obj, timeout=15) as g_resp:
                        resp_json = json.loads(g_resp.read().decode("utf-8"))
                    cand_text = (
                        resp_json.get("candidates", [{}])[0]
                        .get("content", {})
                        .get("parts", [{}])[0]
                        .get("text", "")
                        .strip()
                    )
                    action: dict[str, Any] | None = None
                    if cand_text:
                        try:
                            parsed = json.loads(cand_text)
                            if isinstance(parsed, dict):
                                action = parsed
                        except json.JSONDecodeError:
                            m_json = re.search(r"\{.*\}", cand_text, re.DOTALL)
                            if m_json:
                                parsed = json.loads(m_json.group(0))
                                if isinstance(parsed, dict):
                                    action = parsed
                    if action is not None:
                        cmd_cand = str(action.get("command", ""))
                        action["is_destructive"] = bool(action.get("is_destructive", False)) or is_destructive_command(cmd_cand)
                        self._send_json(HTTPStatus.OK, {"ok": True, "action": action, "source": "host-gemini"})
                        return
                except urllib.error.HTTPError as http_err:
                    logger.warning("Host Gemini API returned HTTP %d during copilot request.", http_err.code)
                except Exception:
                    logger.debug("Host Gemini copilot call failed; checking local fallback.")

            # 2. Silent local fallback if agy CLI exists on disk
            agy_cand = shutil.which("agy")
            agy_path = Path(agy_cand) if agy_cand else (Path.home() / ".local" / "bin" / "agy")
            if agy_path.exists() and agy_path.is_file():
                try:
                    res = subprocess.run(
                        [str(agy_path), "--print", f"{sys_prompt}\nUser request: {user_prompt}", "--model", "gemini-3.8-flash-high", "--effort", "low"],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                        timeout=15,
                    )
                    out = res.stdout.strip()
                    m = re.search(r"\{.*\}", out, re.DOTALL)
                    if m:
                        action = json.loads(m.group(0))
                        if isinstance(action, dict):
                            cmd_cand = str(action.get("command", ""))
                            action["is_destructive"] = bool(action.get("is_destructive", False)) or is_destructive_command(cmd_cand)
                        self._send_json(HTTPStatus.OK, {"ok": True, "action": action, "source": "host-agy"})
                        return
                except Exception as exc:
                    logger.debug("Host agy copilot notice: %s", exc)

            self._send_json(HTTPStatus.OK, {
                "ok": False,
                "error": "Host copilot unavailable; please provide BYOK Gemini Flash key in mobile onboarding."
            })
            return

        if path in ("/api/complete", "/api/terminal/complete"):
            if not self._is_authenticated():
                self._send_json(HTTPStatus.UNAUTHORIZED, {"ok": False, "error": "Unauthorized."})
                return
            data = self._read_json_body(allow_empty=True)
            if data is None:
                return
            line_str = str(data.get("line", ""))
            req_cwd = str(data.get("cwd") or daemon_state.current_cwd)
            result = _complete_terminal_input(line_str, req_cwd)
            self._send_json(HTTPStatus.OK, result)
            return

        if path in ("/api/cancel", "/api/terminal/cancel"):
            if not self._is_authenticated():
                self._send_json(HTTPStatus.UNAUTHORIZED, {"ok": False, "error": "Unauthorized."})
                return
            cancelled, pid = daemon_state.cancel_active_process()
            self._send_json(HTTPStatus.OK, {"ok": True, "cancelled": cancelled, "pid": pid})
            return

        if path in ("/api/exec", "/api/terminal/exec"):
            if not self._is_authenticated():
                self._send_json(
                    HTTPStatus.UNAUTHORIZED,
                    {"ok": False, "error": "Unauthorized. Enter your 6-digit Pairing PIN to link this device."},
                )
                return

            data = self._read_json_body(allow_empty=False)
            if data is None:
                return

            cmd = str(data.get("command", "")).strip()
            biometric_verified = bool(data.get("biometric_verified", False))

            if not cmd:
                self._send_json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "No command provided"})
                return

            # Check destructive commands across all pipeline segments
            is_destructive = is_destructive_command(cmd)

            # Check active server-side WebAuthn biometric lease; if hardware passkeys are enrolled
            # on this host, require an active server-minted lease rather than client boolean alone.
            tok = self._extract_auth_token()
            tok_h = _sha256_hex(tok) if tok else ""
            has_lease = daemon_state.vault.has_active_biometric_lease(tok_h) if tok_h else False
            has_enrolled_passkeys = bool(daemon_state.vault.webauthn_credentials)
            is_authorized = has_lease if has_enrolled_passkeys else (has_lease or biometric_verified)

            if is_destructive and not is_authorized:
                self._send_json(
                    HTTPStatus.FORBIDDEN,
                    {
                        "ok": False,
                        "error": "Destructive command requires biometric (Face ID / Touch ID) authorization.",
                        "requires_biometric": True,
                        "command": cmd,
                    },
                )
                return

            logger.info("Executing command: %s (biometric=%s, cwd=%s)", cmd, is_authorized, daemon_state.current_cwd)
            proc: subprocess.Popen[str] | None = None
            try:
                sentinel = "__MITH_CWD__:"
                if platform.system() != "Windows":
                    # Auto-normalize Windows drive letters (e.g. C:\Users\... or C:/... -> /mnt/c/Users/...)
                    norm_cmd = cmd.strip()
                    if re.match(r'^(?:cd\s+)?([a-zA-Z]):[\\/]?$', norm_cmd):
                        m_drive = re.match(r'^(?:cd\s+)?([a-zA-Z]):[\\/]?$', norm_cmd)
                        norm_cmd = f"cd /mnt/{m_drive.group(1).lower()}"
                    else:
                        norm_cmd = re.sub(
                            r'([A-Za-z]):[\\/]([^\s"\']*)',
                            lambda m: f"/mnt/{m.group(1).lower()}/{m.group(2).replace(chr(92), '/')}",
                            norm_cmd,
                        )

                    escaped_cmd = norm_cmd.replace('"', '\\"')
                    wrapped_cmd = (
                        f"shopt -s expand_aliases 2>/dev/null ; "
                        f"[ -f ~/.bashrc ] && . ~/.bashrc 2>/dev/null ; "
                        f"[ -f ~/.bash_aliases ] && . ~/.bash_aliases 2>/dev/null ; "
                        f"eval \"{escaped_cmd}\" ; __ec=$? ; printf '\\n{sentinel}%s\\n' \"$PWD\" ; exit $__ec"
                    )
                    shell_cmd = ["bash", "-O", "expand_aliases", "-c", wrapped_cmd]
                else:
                    ps_exe = shutil.which("pwsh") or shutil.which("powershell") or "powershell.exe"
                    ps_script = (
                        f"$LASTEXITCODE = 0\n"
                        f"{cmd}\n"
                        f"$__mith_ec = if (-not $?) {{ if ($LASTEXITCODE -ne 0) {{ $LASTEXITCODE }} else {{ 1 }} }} else {{ $LASTEXITCODE }}\n"
                        f"[Console]::Out.WriteLine('{sentinel}' + (Get-Location).Path)\n"
                        f"exit $__mith_ec\n"
                    )
                    encoded_ps = base64.b64encode(ps_script.encode("utf-16-le")).decode("ascii")
                    shell_cmd = [
                        ps_exe,
                        "-NoLogo",
                        "-NoProfile",
                        "-NonInteractive",
                        "-EncodedCommand",
                        encoded_ps,
                    ]

                proc = subprocess.Popen(
                    shell_cmd,
                    cwd=daemon_state.current_cwd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    start_new_session=(platform.system() != "Windows"),
                )
                daemon_state.set_active_proc(proc)
                raw_out, raw_err = proc.communicate(timeout=45)

                clean_stdout = raw_out or ""
                if sentinel in clean_stdout:
                    parts = clean_stdout.rsplit(sentinel, 1)
                    clean_stdout = parts[0].rstrip("\r\n")
                    new_cwd = parts[1].splitlines()[0].strip()
                    if new_cwd and Path(new_cwd).is_dir():
                        daemon_state.current_cwd = str(Path(new_cwd).resolve())

                rc = proc.returncode if proc.returncode is not None else 0
                if rc in (-signal.SIGINT, -signal.SIGTERM, 130, 143) and not raw_err:
                    raw_err = "^C (interrupted)"

                self._send_json(
                    HTTPStatus.OK,
                    {
                        "ok": True,
                        "exit_code": rc,
                        "stdout": clean_stdout,
                        "stderr": raw_err or "",
                        "cwd": daemon_state.current_cwd,
                    },
                )
            except subprocess.TimeoutExpired:
                if proc is not None:
                    try:
                        if platform.system() != "Windows":
                            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                        else:
                            proc.kill()
                    except Exception:
                        pass
                self._send_json(HTTPStatus.GATEWAY_TIMEOUT, {"ok": False, "error": "Command timed out (45s)"})
            except Exception as exc:
                self._send_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"ok": False, "error": str(exc)})
            finally:
                daemon_state.set_active_proc(None)
            return

        self._send_json(HTTPStatus.NOT_FOUND, {"ok": False, "error": "Endpoint not found"})


def run_daemon(
    host: str = "0.0.0.0",
    port: int = 8790,
    enable_tunnel: bool = True,
    enable_discovery: bool = True,
) -> None:
    daemon_state.port = port
    daemon_state.lan_ip = _get_lan_ip()
    stop_event = threading.Event()

    # Bind and start HTTP server immediately so local health checks pass in <15ms
    server = ThreadingHTTPServer((host, port), MithTerminalHandler)
    if enable_discovery and host not in ("127.0.0.1", "localhost", "::1"):
        _start_udp_discovery_responder(port=8791, target_tcp_port=port)
    http_thread = threading.Thread(target=server.serve_forever, name="mith-http-server", daemon=True)
    http_thread.start()
    logger.info("Host Companion HTTP socket active on %s:%d (LAN IP: %s)", host, port, daemon_state.lan_ip)

    def _graceful_shutdown(signum: int, _frame: Any) -> None:
        logger.info("Received signal %d; tearing down tunnel and PTY sessions...", signum)
        stop_event.set()

    for sig_name in ("SIGTERM", "SIGHUP"):
        sig_val = getattr(signal, sig_name, None)
        if sig_val is not None:
            try:
                signal.signal(sig_val, _graceful_shutdown)
            except (ValueError, OSError):
                pass

    # Spawn Cloudflare Quick Tunnel without blocking HTTP requests
    tunnel_url = ""
    if enable_tunnel:
        tunnel_url = daemon_state.tunnel.start_quick_tunnel() or ""

    pin = daemon_state.vault.pairing_pin
    formatted_pin = f"{pin[:3]}-{pin[3:]}" if len(pin) == 6 else pin
    pair_url = f"{tunnel_url}#pin={pin}" if tunnel_url else f"http://{daemon_state.lan_ip}:{port}#pin={pin}"

    qr_section = ""
    try:
        from qr_banner import render_qr_ascii  # type: ignore[import-not-found]

        raw_qr = render_qr_ascii(pair_url)
        if raw_qr and raw_qr.strip():
            qr_lines = raw_qr.rstrip("\n").splitlines()
            aligned_qr = "\n".join(line if line.startswith("   ") else f"   {line}" for line in qr_lines)
            qr_section = (
                "   ------------------------------------------------------------------\n"
                "   📱 SCAN WITH IPHONE / ANDROID CAMERA TO PAIR INSTANTLY:\n"
                f"      {pair_url}\n\n"
                f"{aligned_qr}\n"
            )
    except Exception as exc:
        logger.debug("QR banner unavailable: %s", exc)

    banner = f"""
======================================================================
   🚀 MiTH Terminal — Zero-Config Host Companion v1.2.1
======================================================================
   Host Device:     {platform.node()} ({platform.system()} {platform.machine()})
   Local Host:      http://127.0.0.1:{port}
   Local Wi-Fi/LAN: http://{daemon_state.lan_ip}:{port}
"""
    if tunnel_url:
        banner += f"""   ------------------------------------------------------------------
   🌐 ZERO-CONFIG PUBLIC TUNNEL (No VPN / No Tailscale):
      {tunnel_url}#pin={pin}
"""
    if qr_section:
        banner += qr_section
    banner += f"""   ------------------------------------------------------------------
   🔑 PAIRING PIN:         [  {formatted_pin}  ]
   🛡️ BIOMETRICS GATE:     ACTIVE (Apple Face ID / WebAuthn Passkeys)
======================================================================
"""
    print(banner)
    logger.info("Host Companion ready on %s:%d (LAN IP: %s)", host, port, daemon_state.lan_ip)

    try:
        while http_thread.is_alive() and not stop_event.is_set():
            stop_event.wait(timeout=1.0)
    except KeyboardInterrupt:
        logger.info("Shutting down companion daemon...")
    finally:
        daemon_state.tunnel.stop()
        daemon_state.pty_manager.close_all()
        server.shutdown()
        server.server_close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="MiTH Terminal Host Daemon")
    parser.add_argument("--host", default="0.0.0.0", help="Host address (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=8790, help="Port (default: 8790)")
    parser.add_argument("--no-tunnel", action="store_true", help="Disable automatic Cloudflare Quick Tunnel")
    parser.add_argument("--no-discovery", action="store_true", help="Disable UDP LAN auto-discovery on port 8791")
    args = parser.parse_args()

    run_daemon(
        host=args.host,
        port=args.port,
        enable_tunnel=not args.no_tunnel,
        enable_discovery=not args.no_discovery,
    )
