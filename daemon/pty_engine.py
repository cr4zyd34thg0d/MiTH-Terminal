#!/usr/bin/env python3
"""
MiTH Terminal — Interactive Pseudo-Terminal (PTY) & RFC 6455 WebSocket Engine
Provides zero-dependency kernel PTY sessions (supporting htop, vim, nano, tmux,
less, tail -f, SSH, and full ANSI/truecolor TUI apps) over both:
  1. Native RFC 6455 Binary/Control WebSockets (/api/terminal/ws)
  2. Automatic HTTP Long-Poll Fallback (/api/terminal/pty/*)
"""

from __future__ import annotations

import base64
import errno
import hashlib
import json
import logging
import os
import platform
import queue
import secrets
import select
import shutil
import signal
import socket
import struct
import subprocess
import threading
import time
from pathlib import Path
from typing import Any

if platform.system() != "Windows":
    import fcntl
    import pty
    import termios

logger = logging.getLogger("mith-terminal-pty")

WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
MAX_WS_FRAME_BYTES = 1_048_576       # 1 MiB DoS ceiling per client frame
SCROLLBACK_RING_BYTES = 65_536       # 64 KiB replay ring buffer for mobile reconnects
MAX_ACTIVE_PTY_SESSIONS = 8
PTY_IDLE_TIMEOUT_SECONDS = 1800.0    # 30 minutes idle reaper

WS_OP_CONT = 0x0
WS_OP_TEXT = 0x1
WS_OP_BINARY = 0x2
WS_OP_CLOSE = 0x8
WS_OP_PING = 0x9
WS_OP_PONG = 0xA


def ws_compute_accept_key(sec_websocket_key: str) -> str:
    """Compute RFC 6455 Sec-WebSocket-Accept header value."""
    raw = (sec_websocket_key.strip() + WS_GUID).encode("ascii")
    digest = hashlib.sha1(raw).digest()
    return base64.b64encode(digest).decode("ascii")


def ws_encode_frame(payload: bytes, opcode: int = WS_OP_BINARY) -> bytes:
    """Encode an unmasked server-to-client RFC 6455 WebSocket frame."""
    first_byte = 0x80 | (opcode & 0x0F)
    length = len(payload)
    if length < 126:
        header = struct.pack("!BB", first_byte, length)
    elif length < 65536:
        header = struct.pack("!BBH", first_byte, 126, length)
    else:
        header = struct.pack("!BBQ", first_byte, 127, length)
    return header + payload


def _recv_exact(sock: socket.socket, num_bytes: int) -> bytes | None:
    """Read exactly num_bytes from sock, returning None on clean EOF."""
    buf = bytearray()
    while len(buf) < num_bytes:
        try:
            chunk = sock.recv(num_bytes - len(buf))
        except socket.timeout:
            raise
        except OSError:
            return None
        if not chunk:
            return None
        buf.extend(chunk)
    return bytes(buf)


def ws_read_frame(sock: socket.socket) -> tuple[int, bytes] | None:
    """
    Read and unmask a complete RFC 6455 WebSocket message (reassembling fragments).
    Returns (opcode, payload_bytes) or None on EOF / invalid framing.
    """
    msg_opcode: int | None = None
    assembled = bytearray()

    while True:
        hdr = _recv_exact(sock, 2)
        if hdr is None:
            return None
        b0, b1 = hdr[0], hdr[1]
        fin = bool(b0 & 0x80)
        opcode = b0 & 0x0F
        masked = bool(b1 & 0x80)
        length = b1 & 0x7F

        if length == 126:
            ext = _recv_exact(sock, 2)
            if ext is None:
                return None
            length = struct.unpack("!H", ext)[0]
        elif length == 127:
            ext = _recv_exact(sock, 8)
            if ext is None:
                return None
            length = struct.unpack("!Q", ext)[0]

        if length > MAX_WS_FRAME_BYTES or (len(assembled) + length) > MAX_WS_FRAME_BYTES:
            raise ValueError(f"WebSocket frame exceeds {MAX_WS_FRAME_BYTES} byte limit")

        mask_key = b""
        if masked:
            mk = _recv_exact(sock, 4)
            if mk is None:
                return None
            mask_key = mk

        payload = _recv_exact(sock, length) if length > 0 else b""
        if payload is None:
            return None

        if masked and payload:
            unmasked = bytearray(length)
            m0, m1, m2, m3 = mask_key[0], mask_key[1], mask_key[2], mask_key[3]
            masks = (m0, m1, m2, m3)
            for idx, val in enumerate(payload):
                unmasked[idx] = val ^ masks[idx & 3]
            payload = bytes(unmasked)

        # Control frames (Close, Ping, Pong) may arrive mid-fragment and must not be fragmented
        if opcode >= 0x8:
            return opcode, payload

        if opcode != WS_OP_CONT:
            msg_opcode = opcode
            assembled.clear()
        assembled.extend(payload)

        if fin:
            return (msg_opcode if msg_opcode is not None else opcode), bytes(assembled)


def _set_pty_winsize(fd: int, cols: int, rows: int) -> None:
    """Apply terminal dimensions (rows, cols) to a POSIX PTY descriptor."""
    if platform.system() == "Windows":
        return
    safe_cols = max(20, min(500, int(cols)))
    safe_rows = max(5, min(200, int(rows)))
    winsz = struct.pack("HHHH", safe_rows, safe_cols, 0, 0)
    fcntl.ioctl(fd, termios.TIOCSWINSZ, winsz)


class PtySession:
    """Represents a live interactive kernel PTY shell session with fan-out subscribers."""

    def __init__(
        self,
        session_id: str,
        owner_hash: str,
        cwd: str,
        cols: int = 80,
        rows: int = 26,
        label: str = "",
    ) -> None:
        self.session_id = session_id
        self.owner_hash = owner_hash
        self.label = str(label or "")
        self.cols = max(20, min(500, int(cols)))
        self.rows = max(5, min(200, int(rows)))
        self.created_at = time.time()
        self.last_activity = time.time()
        self.closed = False
        self.exit_code: int | None = None

        self._lock = threading.Lock()
        self._cond = threading.Condition(self._lock)
        self._subscribers: set[queue.Queue[bytes | None]] = set()
        self._ring = bytearray()
        self._stream_cursor = 0  # Monotonic total byte counter for HTTP poll cursors

        self.master_fd: int | None = None
        self.proc: subprocess.Popen[bytes] | None = None
        self._spawn(cwd)

    def _spawn(self, cwd: str) -> None:
        start_dir = cwd if cwd and Path(cwd).is_dir() else str(Path.home())
        env = os.environ.copy()
        env["TERM"] = "xterm-256color"
        env["COLORTERM"] = "truecolor"
        env.setdefault("LANG", "C.UTF-8")
        env["COLUMNS"] = str(self.cols)
        env["LINES"] = str(self.rows)

        if platform.system() == "Windows":
            ps_bin = shutil.which("pwsh.exe") or shutil.which("powershell.exe")
            shell_argv = [ps_bin, "-NoLogo", "-NoProfile"] if ps_bin else ["cmd.exe", "/Q"]
            self.proc = subprocess.Popen(
                shell_argv,
                cwd=start_dir,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                env=env,
            )
            threading.Thread(
                target=self._windows_reader_loop,
                name=f"pty-win-read-{self.session_id[:8]}",
                daemon=True,
            ).start()
            return

        self._spawn_posix(start_dir, env)

    def _spawn_posix(self, start_dir: str, env: dict[str, str] | None = None) -> None:
        if env is None:
            env = os.environ.copy()
            env["TERM"] = "xterm-256color"
            env["COLORTERM"] = "truecolor"
            env.setdefault("LANG", "C.UTF-8")
            env["COLUMNS"] = str(self.cols)
            env["LINES"] = str(self.rows)

        master_fd, slave_fd = pty.openpty()
        _set_pty_winsize(slave_fd, self.cols, self.rows)

        allowed_shells = {"zsh", "bash", "fish", "sh"}
        user_shell = os.getenv("SHELL", "").strip()
        shell_bin = ""
        if user_shell:
            cand = user_shell if os.path.isabs(user_shell) else (shutil.which(user_shell) or "")
            if cand:
                cand_path = Path(cand)
                if (
                    cand_path.name in allowed_shells
                    and cand_path.is_file()
                    and os.access(cand_path, os.X_OK)
                ):
                    shell_bin = str(cand_path)
        if not shell_bin:
            shell_bin = shutil.which("bash") or "/bin/sh"

        shell_name = os.path.basename(shell_bin)
        argv = [shell_bin, "-i"] if shell_name in ("bash", "zsh") else [shell_bin]
        env["SHELL"] = shell_bin

        def _child_setup() -> None:
            os.setsid()
            try:
                fcntl.ioctl(slave_fd, termios.TIOCSCTTY, 0)
            except OSError:
                pass

        try:
            self.proc = subprocess.Popen(
                argv,
                cwd=start_dir,
                stdin=slave_fd,
                stdout=slave_fd,
                stderr=slave_fd,
                env=env,
                preexec_fn=_child_setup,
                close_fds=True,
            )
        except Exception:
            os.close(master_fd)
            os.close(slave_fd)
            raise
        finally:
            try:
                os.close(slave_fd)
            except OSError:
                pass

        self.master_fd = master_fd
        threading.Thread(
            target=self._posix_reader_loop,
            name=f"pty-read-{self.session_id[:8]}",
            daemon=True,
        ).start()

    def _publish_output(self, chunk: bytes) -> None:
        if not chunk:
            return
        with self._cond:
            self.last_activity = time.time()
            self._ring.extend(chunk)
            if len(self._ring) > SCROLLBACK_RING_BYTES:
                overflow = len(self._ring) - SCROLLBACK_RING_BYTES
                del self._ring[:overflow]
            self._stream_cursor += len(chunk)
            dead_queues: list[queue.Queue[bytes | None]] = []
            for sub_q in self._subscribers:
                try:
                    sub_q.put_nowait(chunk)
                except queue.Full:
                    dead_queues.append(sub_q)
            for dq in dead_queues:
                self._subscribers.discard(dq)
            self._cond.notify_all()

    def _mark_terminated(self) -> None:
        rc: int | None = None
        if self.proc is not None:
            try:
                rc = self.proc.wait(timeout=0.5)
            except Exception:
                rc = self.proc.poll()
        with self._cond:
            self.closed = True
            self.exit_code = rc if rc is not None else 0
            for sub_q in list(self._subscribers):
                try:
                    sub_q.put_nowait(None)
                except queue.Full:
                    pass
            self._cond.notify_all()
        if self.master_fd is not None:
            fd_to_close = self.master_fd
            self.master_fd = None
            try:
                os.close(fd_to_close)
            except OSError:
                pass

    def _posix_reader_loop(self) -> None:
        fd = self.master_fd
        if fd is None:
            return
        try:
            while not self.closed:
                try:
                    chunk = os.read(fd, 16384)
                    if not chunk:
                        break
                    self._publish_output(chunk)
                except OSError as exc:
                    if exc.errno in (errno.EIO, errno.EBADF):
                        break
                    if exc.errno == errno.EINTR:
                        continue
                    break
        finally:
            self._mark_terminated()

    def _windows_reader_loop(self) -> None:
        if self.proc is None or self.proc.stdout is None:
            return
        try:
            while not self.closed:
                chunk = self.proc.stdout.read1(4096) if hasattr(self.proc.stdout, "read1") else self.proc.stdout.read(256)
                if not chunk:
                    break
                self._publish_output(chunk)
        finally:
            self._mark_terminated()

    def subscribe(self, replay_backlog: bool = True) -> tuple[queue.Queue[bytes | None], bytes]:
        sub_q: queue.Queue[bytes | None] = queue.Queue(maxsize=1024)
        with self._cond:
            backlog = bytes(self._ring) if replay_backlog else b""
            if self.closed:
                sub_q.put_nowait(None)
            else:
                self._subscribers.add(sub_q)
        return sub_q, backlog

    def unsubscribe(self, sub_q: queue.Queue[bytes | None]) -> None:
        with self._cond:
            self._subscribers.discard(sub_q)

    def poll_http_chunks(self, cursor: int, timeout_sec: float = 12.0) -> dict[str, Any]:
        """Long-poll output bytes starting from monotonic byte `cursor`."""
        deadline = time.time() + max(0.0, min(25.0, timeout_sec))
        with self._cond:
            while not self.closed and self._stream_cursor <= cursor:
                rem = deadline - time.time()
                if rem <= 0:
                    break
                self._cond.wait(timeout=rem)

            ring_len = len(self._ring)
            ring_start_cursor = self._stream_cursor - ring_len
            if cursor < ring_start_cursor:
                data = bytes(self._ring)
            else:
                offset = cursor - ring_start_cursor
                data = bytes(self._ring[offset:]) if offset < ring_len else b""

            return {
                "ok": True,
                "session_id": self.session_id,
                "b64": base64.b64encode(data).decode("ascii") if data else "",
                "cursor": self._stream_cursor,
                "closed": self.closed,
                "exit_code": self.exit_code,
            }

    def write_input(self, data: bytes | str) -> bool:
        if self.closed:
            return False
        raw = data.encode("utf-8", errors="replace") if isinstance(data, str) else data
        if not raw:
            return True
        self.last_activity = time.time()
        try:
            if platform.system() == "Windows":
                if self.proc and self.proc.stdin:
                    win_raw = raw.replace(b"\r\n", b"\n").replace(b"\r", b"\n").replace(b"\n", b"\r\n")
                    self.proc.stdin.write(win_raw)
                    self.proc.stdin.flush()
                    return True
                return False

            fd = self.master_fd
            if fd is None:
                return False
            view = memoryview(raw)
            written = 0
            while written < len(raw):
                n = os.write(fd, view[written:])
                if n <= 0:
                    break
                written += n
            return True
        except OSError:
            return False

    def resize(self, cols: int, rows: int) -> bool:
        if self.closed:
            return False
        self.cols = max(20, min(500, int(cols)))
        self.rows = max(5, min(200, int(rows)))
        self.last_activity = time.time()
        if platform.system() == "Windows":
            return True
        fd = self.master_fd
        if fd is None:
            return False
        try:
            _set_pty_winsize(fd, self.cols, self.rows)
            if self.proc is not None and self.proc.poll() is None:
                try:
                    os.killpg(os.getpgid(self.proc.pid), signal.SIGWINCH)
                except OSError:
                    pass
            return True
        except OSError:
            return False

    def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        if self.proc is not None and self.proc.poll() is None:
            try:
                if platform.system() != "Windows":
                    pgid = os.getpgid(self.proc.pid)
                    os.killpg(pgid, signal.SIGHUP)
                    time.sleep(0.05)
                    if self.proc.poll() is None:
                        os.killpg(pgid, signal.SIGTERM)
                else:
                    if self.proc.stdin:
                        try:
                            self.proc.stdin.close()
                        except OSError:
                            pass
                    self.proc.terminate()
                    try:
                        self.proc.wait(timeout=1.0)
                    except subprocess.TimeoutExpired:
                        self.proc.kill()
            except OSError:
                pass
        self._mark_terminated()


class PtySessionManager:
    """Thread-safe registry & lifecycle reaper for interactive PTY sessions."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._sessions: dict[str, PtySession] = {}
        self._ws_tickets: dict[str, tuple[str, float]] = {}

    def mint_ws_ticket(self, owner_hash: str, ttl_seconds: float = 30.0) -> str:
        ticket = secrets.token_urlsafe(24)
        now = time.time()
        with self._lock:
            self._ws_tickets = {k: v for k, v in self._ws_tickets.items() if v[1] > now}
            self._ws_tickets[ticket] = (owner_hash, now + ttl_seconds)
        return ticket

    def consume_ws_ticket(self, ticket: str) -> str | None:
        if not ticket:
            return None
        now = time.time()
        with self._lock:
            entry = self._ws_tickets.pop(ticket.strip(), None)
            if entry is not None and entry[1] > now:
                return entry[0]
        return None

    def _reap_locked(self) -> None:
        now = time.time()
        expired = [
            sid
            for sid, sess in self._sessions.items()
            if sess.closed or (now - sess.last_activity) > PTY_IDLE_TIMEOUT_SECONDS
        ]
        for sid in expired:
            sess = self._sessions.pop(sid, None)
            if sess is not None:
                sess.close()

    def get_or_create(
        self,
        owner_hash: str,
        cwd: str,
        cols: int = 80,
        rows: int = 26,
        session_id: str | None = None,
        label: str = "",
    ) -> tuple[PtySession, bool]:
        """Return (session, reattached_bool)."""
        clean_label = str(label or "")
        with self._lock:
            self._reap_locked()
            if session_id:
                existing = self._sessions.get(session_id)
                if existing and not existing.closed and existing.owner_hash == owner_hash:
                    if clean_label:
                        existing.label = clean_label
                    existing.resize(cols, rows)
                    return existing, True

            # Evict oldest session if cap reached
            if len(self._sessions) >= MAX_ACTIVE_PTY_SESSIONS:
                oldest_id = min(self._sessions, key=lambda k: self._sessions[k].last_activity)
                old_sess = self._sessions.pop(oldest_id, None)
                if old_sess:
                    old_sess.close()

            new_id = secrets.token_hex(12)
            sess = PtySession(
                session_id=new_id,
                owner_hash=owner_hash,
                cwd=cwd,
                cols=cols,
                rows=rows,
                label=clean_label,
            )
            self._sessions[new_id] = sess
            return sess, False

    def list_sessions(self, owner_hash: str) -> list[dict[str, Any]]:
        """Return active (non-closed) PTY sessions owned by `owner_hash`, sorted by `created_at`."""
        with self._lock:
            self._reap_locked()
            owned = [
                (sid, sess)
                for sid, sess in self._sessions.items()
                if not sess.closed and sess.owner_hash == owner_hash
            ]
            owned.sort(key=lambda item: item[1].created_at)
            return [
                {
                    "session_id": sid,
                    "label": sess.label,
                    "created_at": sess.created_at,
                    "last_activity": sess.last_activity,
                    "cols": sess.cols,
                    "rows": sess.rows,
                }
                for sid, sess in owned
            ]

    def get_owned(self, session_id: str, owner_hash: str) -> PtySession | None:
        with self._lock:
            self._reap_locked()
            sess = self._sessions.get(session_id)
            if sess and sess.owner_hash == owner_hash:
                return sess
            return None

    def close_session(self, session_id: str, owner_hash: str) -> bool:
        with self._lock:
            sess = self._sessions.get(session_id)
            if not sess or sess.owner_hash != owner_hash:
                return False
            self._sessions.pop(session_id, None)
        sess.close()
        return True

    def close_all(self) -> None:
        with self._lock:
            all_sessions = list(self._sessions.values())
            self._sessions.clear()
        for sess in all_sessions:
            sess.close()


def serve_websocket_pty(
    sock: socket.socket,
    session: PtySession,
    reattached: bool = False,
    initial_cmd: str = "",
) -> None:
    """
    Drive a full-duplex RFC 6455 WebSocket stream attached to `session`.
    - Binary frames (0x2): raw PTY output bytes (server->client) or raw input bytes (client->server)
    - Text frames (0x1): JSON control envelopes (ready, resize, input, ping/pong, exit)
    """
    sock.settimeout(1.0)
    sub_q, backlog = session.subscribe(replay_backlog=reattached)
    stop_event = threading.Event()
    send_lock = threading.Lock()

    def _safe_send(frame: bytes) -> bool:
        with send_lock:
            try:
                sock.sendall(frame)
                return True
            except OSError:
                stop_event.set()
                return False

    ready_payload = json.dumps({
        "type": "ready",
        "session_id": session.session_id,
        "label": session.label,
        "reattached": reattached,
        "cols": session.cols,
        "rows": session.rows,
    }).encode("utf-8")
    if not _safe_send(ws_encode_frame(ready_payload, opcode=WS_OP_TEXT)):
        session.unsubscribe(sub_q)
        return

    if backlog:
        _safe_send(ws_encode_frame(backlog, opcode=WS_OP_BINARY))

    if initial_cmd.strip():
        session.write_input(initial_cmd.strip() + "\r")

    def _writer_loop() -> None:
        last_ping = time.time()
        while not stop_event.is_set():
            try:
                chunk = sub_q.get(timeout=0.5)
                if chunk is None:
                    exit_msg = json.dumps({
                        "type": "exit",
                        "exit_code": session.exit_code if session.exit_code is not None else 0,
                    }).encode("utf-8")
                    _safe_send(ws_encode_frame(exit_msg, opcode=WS_OP_TEXT))
                    _safe_send(ws_encode_frame(b"", opcode=WS_OP_CLOSE))
                    stop_event.set()
                    break
                if not _safe_send(ws_encode_frame(chunk, opcode=WS_OP_BINARY)):
                    break
            except queue.Empty:
                if session.closed:
                    stop_event.set()
                    break
                if time.time() - last_ping >= 20.0:
                    last_ping = time.time()
                    if not _safe_send(ws_encode_frame(b"mith-hb", opcode=WS_OP_PING)):
                        break

    writer_thread = threading.Thread(
        target=_writer_loop,
        name=f"ws-pty-tx-{session.session_id[:8]}",
        daemon=True,
    )
    writer_thread.start()

    try:
        while not stop_event.is_set():
            try:
                frame = ws_read_frame(sock)
            except socket.timeout:
                continue
            except ValueError as exc:
                logger.warning("Closing WebSocket due to invalid frame: %s", exc)
                _safe_send(ws_encode_frame(struct.pack("!H", 1009), opcode=WS_OP_CLOSE))
                break

            if frame is None:
                break

            opcode, payload = frame
            if opcode == WS_OP_CLOSE:
                _safe_send(ws_encode_frame(b"", opcode=WS_OP_CLOSE))
                break
            if opcode == WS_OP_PING:
                _safe_send(ws_encode_frame(payload[:125], opcode=WS_OP_PONG))
                continue
            if opcode == WS_OP_PONG:
                continue
            if opcode == WS_OP_BINARY:
                session.write_input(payload)
                continue
            if opcode == WS_OP_TEXT:
                try:
                    msg = json.loads(payload.decode("utf-8", errors="replace"))
                except json.JSONDecodeError:
                    session.write_input(payload)
                    continue

                mtype = msg.get("type")
                if mtype == "input":
                    data_str = msg.get("data", "")
                    if isinstance(data_str, str) and data_str:
                        session.write_input(data_str)
                elif mtype == "resize":
                    session.resize(int(msg.get("cols", 80)), int(msg.get("rows", 26)))
                elif mtype == "ping":
                    pong = json.dumps({"type": "pong", "ts": msg.get("ts")}).encode("utf-8")
                    _safe_send(ws_encode_frame(pong, opcode=WS_OP_TEXT))
                elif mtype == "kill_session":
                    session.close()
                    break
    finally:
        stop_event.set()
        session.unsubscribe(sub_q)
        writer_thread.join(timeout=1.0)
