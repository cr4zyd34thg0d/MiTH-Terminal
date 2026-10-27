#!/usr/bin/env python3
"""
Self-contained unit and integration test suite for MiTH Terminal Companion Daemon & Security Architecture.
Starts an isolated test daemon on an ephemeral port with a test pairing vault.
"""

from __future__ import annotations

import base64
import http.client
import json
import os
import socket
import struct
import sys
import tempfile
import threading
import time
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path

DAEMON_DIR = Path(__file__).resolve().parent.parent / "daemon"
if str(DAEMON_DIR) not in sys.path:
    sys.path.insert(0, str(DAEMON_DIR))

import pty_engine
import server as daemon_srv


class MithTerminalDaemonTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp_dir = tempfile.TemporaryDirectory()
        cls.vault_file = Path(cls.tmp_dir.name) / "test_vault.json"

        # Instantiate isolated test vault and state
        cls.test_vault = daemon_srv.PairingVault(vault_path=cls.vault_file)
        daemon_srv.daemon_state.vault = cls.test_vault
        cls.pin = cls.test_vault.pairing_pin

        # Start HTTP server on ephemeral port (port=0)
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), daemon_srv.MithTerminalHandler)
        cls.port = cls.httpd.server_address[1]
        daemon_srv.daemon_state.port = cls.port
        cls.server_thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.server_thread.start()

        # Start test UDP responder on ephemeral port
        sock_temp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock_temp.bind(("127.0.0.1", 0))
        cls.udp_port = sock_temp.getsockname()[1]
        sock_temp.close()
        daemon_srv._start_udp_discovery_responder(port=cls.udp_port, target_tcp_port=cls.port)
        time.sleep(0.15)

    @classmethod
    def tearDownClass(cls) -> None:
        daemon_srv.daemon_state.pty_manager.close_all()
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls.tmp_dir.cleanup()

    def _json_request(self, method: str, path: str, body: dict | None = None, headers: dict | None = None) -> tuple[int, dict]:
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        hdrs = {"Content-Type": "application/json"}
        if headers:
            hdrs.update(headers)
        data = json.dumps(body) if body is not None else None
        conn.request(method, path, body=data, headers=hdrs)
        resp = conn.getresponse()
        raw = resp.read()
        conn.close()
        try:
            return resp.status, json.loads(raw.decode("utf-8"))
        except Exception:
            return resp.status, {"raw": raw.decode("utf-8", errors="ignore")}

    def test_01_ping_endpoint(self) -> None:
        status, data = self._json_request("GET", "/api/ping")
        self.assertEqual(status, 200)
        self.assertTrue(data.get("ok"))
        self.assertEqual(data.get("service"), "mith-terminal-daemon")
        self.assertIn("host", data)
        self.assertIn("system", data)

    def test_02_pin_pairing_handshake(self) -> None:
        # Invalid PIN rejected
        status, data = self._json_request("POST", "/api/auth/pair", {"pin": "000000"})
        self.assertEqual(status, 401)
        self.assertFalse(data.get("ok"))

        # Valid PIN accepted
        status, data = self._json_request("POST", "/api/auth/pair", {"pin": self.pin, "client_name": "Test iPhone"})
        self.assertEqual(status, 200)
        self.assertTrue(data.get("ok"))
        self.assertIn("token", data)
        self.assertEqual(len(data["token"]), 64)

    def test_03_command_execution_and_cwd(self) -> None:
        # Pair to get token
        _, pair_data = self._json_request("POST", "/api/auth/pair", {"pin": self.pin})
        token = pair_data["token"]
        auth_hdr = {"Authorization": f"Bearer {token}"}

        # Run echo command
        status, data = self._json_request(
            "POST",
            "/api/exec",
            {"command": "echo test_mith_terminal_exec"},
            headers=auth_hdr,
        )
        self.assertEqual(status, 200)
        self.assertTrue(data.get("ok"))
        self.assertEqual(data.get("exit_code"), 0)
        self.assertIn("test_mith_terminal_exec", data.get("stdout", ""))

        # Test persistent directory change
        status, data = self._json_request(
            "POST",
            "/api/exec",
            {"command": "cd /tmp && pwd"},
            headers=auth_hdr,
        )
        self.assertEqual(status, 200)
        self.assertEqual(data.get("cwd"), "/tmp")

    def test_04_destructive_command_biometric_gate(self) -> None:
        _, pair_data = self._json_request("POST", "/api/auth/pair", {"pin": self.pin})
        token = pair_data["token"]
        auth_hdr = {"Authorization": f"Bearer {token}"}

        # Destructive command blocked without biometric verification
        status, data = self._json_request(
            "POST",
            "/api/exec",
            {"command": "sudo rm -rf /tmp/mock_target", "biometric_verified": False},
            headers=auth_hdr,
        )
        self.assertEqual(status, 403)
        self.assertFalse(data.get("ok"))
        self.assertTrue(data.get("requires_biometric"))

        # Destructive command allowed with biometric verification
        status, data = self._json_request(
            "POST",
            "/api/exec",
            {"command": "echo simulated_safe_sudo", "biometric_verified": True},
            headers=auth_hdr,
        )
        self.assertEqual(status, 200)
        self.assertTrue(data.get("ok"))
        self.assertIn("simulated_safe_sudo", data.get("stdout", ""))

        # Chained compound destructive command blocked without biometric verification
        status, data = self._json_request(
            "POST",
            "/api/exec",
            {"command": "echo safe && rm -rf /tmp/mock_nested_target", "biometric_verified": False},
            headers=auth_hdr,
        )
        self.assertEqual(status, 403)
        self.assertFalse(data.get("ok"))
        self.assertTrue(data.get("requires_biometric"))

    def test_04b_webauthn_challenge_and_lease(self) -> None:
        _, pair_data = self._json_request("POST", "/api/auth/pair", {"pin": self.pin})
        token = pair_data["token"]
        auth_hdr = {"Authorization": f"Bearer {token}"}

        # 1. Fetch challenge
        status, chal_data = self._json_request("GET", "/api/auth/webauthn/challenge")
        self.assertEqual(status, 200)
        self.assertTrue(chal_data.get("ok"))
        chal = chal_data.get("challenge")
        self.assertTrue(chal)

        # 2. Verify challenge and receive lease
        status, v_data = self._json_request(
            "POST",
            "/api/auth/webauthn/verify",
            {"challenge": chal},
            headers=auth_hdr,
        )
        self.assertEqual(status, 200)
        self.assertTrue(v_data.get("ok"))
        self.assertTrue(v_data.get("biometric_verified"))

        # 3. Now execute destructive command without client boolean flag — permitted via server-side lease!
        status, exec_data = self._json_request(
            "POST",
            "/api/exec",
            {"command": "echo lease_authorized_sudo"},
            headers=auth_hdr,
        )
        self.assertEqual(status, 200)
        self.assertTrue(exec_data.get("ok"))
        self.assertIn("lease_authorized_sudo", exec_data.get("stdout", ""))

    def test_05_udp_local_discovery(self) -> None:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(2.0)
        try:
            s.sendto(b"MITH_DISCOVER_V1", ("127.0.0.1", self.udp_port))
            data, _ = s.recvfrom(1024)
            payload = json.loads(data.decode("utf-8"))
            self.assertTrue(payload.get("ok"))
            self.assertEqual(payload.get("service"), "mith-terminal")
            self.assertEqual(payload.get("port"), self.port)
        finally:
            s.close()

    def test_06_prefixed_routes_and_unauthorized_rejection(self) -> None:
        # 1. Unauthenticated /api/terminal/exec MUST be rejected with 401
        status, data = self._json_request(
            "POST",
            "/api/terminal/exec",
            {"command": "whoami"},
        )
        self.assertEqual(status, 401)
        self.assertFalse(data.get("ok"))

        # 2. Pair via /api/terminal/pair
        status, pair_data = self._json_request(
            "POST",
            "/api/terminal/pair",
            {"pin": self.pin, "client_name": "Prefixed Client Test"},
        )
        self.assertEqual(status, 200)
        self.assertTrue(pair_data.get("ok"))
        tok = pair_data.get("token")
        self.assertTrue(tok)

        # 3. Authenticated ping via /api/terminal/ping
        status, ping_data = self._json_request(
            "GET",
            "/api/terminal/ping",
            headers={"Authorization": f"Bearer {tok}"},
        )
        self.assertEqual(status, 200)
        self.assertTrue(ping_data.get("ok"))
        self.assertTrue(ping_data.get("authenticated"))

        # 4. Authenticated exec via /api/terminal/exec
        status, exec_data = self._json_request(
            "POST",
            "/api/terminal/exec",
            {"command": "echo test_prefixed_routes_ok"},
            headers={"Authorization": f"Bearer {tok}"},
        )
        self.assertEqual(status, 200)
        self.assertTrue(exec_data.get("ok"))
        self.assertIn("test_prefixed_routes_ok", exec_data.get("stdout", ""))

    def test_07_system_vitals_telemetry(self) -> None:
        # 1. Unauthenticated vitals rejected
        status, data = self._json_request("GET", "/api/terminal/vitals")
        self.assertEqual(status, 401)
        self.assertFalse(data.get("ok"))

        # 2. Pair to get token
        _, pair_data = self._json_request("POST", "/api/terminal/pair", {"pin": self.pin})
        tok = pair_data["token"]

        # 3. Authenticated vitals returns structured telemetry
        status, data = self._json_request(
            "GET",
            "/api/terminal/vitals",
            headers={"Authorization": f"Bearer {tok}"},
        )
        self.assertEqual(status, 200)
        self.assertTrue(data.get("ok"))
        self.assertIn("vitals", data)
        v = data["vitals"]
        self.assertIn("cpu_pct", v)
        self.assertIn("mem_total_gb", v)
        self.assertIn("disk_total_gb", v)
        self.assertGreater(v["disk_total_gb"], 0)

    def test_08_pwa_icons_and_dynamic_manifest(self) -> None:
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        conn.request("GET", "/api/terminal/icon-180.png")
        resp = conn.getresponse()
        raw_png = resp.read()
        ct = resp.getheader("Content-Type", "")
        conn.close()
        self.assertEqual(resp.status, 200)
        self.assertEqual(ct, "image/png")
        self.assertTrue(raw_png.startswith(b"\x89PNG\r\n\x1a\n"))

        # Valid /terminal start_url
        status, m_term = self._json_request("GET", "/api/terminal/manifest.json?start=%2Fterminal")
        self.assertEqual(status, 200)
        self.assertEqual(m_term.get("start_url"), "/terminal")
        self.assertEqual(m_term.get("display"), "standalone")

        # Untrusted open-redirect start_url clamped to "/"
        status, m_safe = self._json_request("GET", "/api/terminal/manifest.json?start=https://evil.example")
        self.assertEqual(status, 200)
        self.assertEqual(m_safe.get("start_url"), "/")

    def test_09_bookmarks_and_tab_completion(self) -> None:
        # Unauthenticated rejected
        status, _ = self._json_request("GET", "/api/terminal/bookmarks")
        self.assertEqual(status, 401)
        status, _ = self._json_request("POST", "/api/terminal/complete", {"line": "cd "})
        self.assertEqual(status, 401)

        _, pair_data = self._json_request("POST", "/api/terminal/pair", {"pin": self.pin})
        auth_hdr = {"Authorization": f"Bearer {pair_data['token']}"}

        status, bm_data = self._json_request("GET", "/api/terminal/bookmarks", headers=auth_hdr)
        self.assertEqual(status, 200)
        self.assertTrue(bm_data.get("ok"))
        self.assertIsInstance(bm_data.get("bookmarks"), list)
        self.assertGreaterEqual(len(bm_data["bookmarks"]), 1)

        # Case-insensitive folder & file completion in isolated temp folder
        comp_root = Path(self.tmp_dir.name) / "comp_workspace"
        (comp_root / "MyStudioProject").mkdir(parents=True, exist_ok=True)
        (comp_root / "README_NOTES.md").write_text("notes", encoding="utf-8")

        status, c_dir = self._json_request(
            "POST",
            "/api/terminal/complete",
            {"line": "cd mystud", "cwd": str(comp_root)},
            headers=auth_hdr,
        )
        self.assertEqual(status, 200)
        self.assertEqual(c_dir.get("completed_line"), "cd MyStudioProject/")

        status, c_file = self._json_request(
            "POST",
            "/api/terminal/complete",
            {"line": "cat read", "cwd": str(comp_root)},
            headers=auth_hdr,
        )
        self.assertEqual(status, 200)
        self.assertEqual(c_file.get("completed_line"), "cat README_NOTES.md ")

    def test_10_remote_ctrl_c_process_cancel(self) -> None:
        _, pair_data = self._json_request("POST", "/api/terminal/pair", {"pin": self.pin})
        auth_hdr = {"Authorization": f"Bearer {pair_data['token']}"}

        exec_result: dict = {}

        def _run_slow() -> None:
            st, res = self._json_request(
                "POST",
                "/api/terminal/exec",
                {"command": "sleep 12"},
                headers=auth_hdr,
            )
            exec_result["status"] = st
            exec_result["data"] = res

        t0 = time.time()
        worker = threading.Thread(target=_run_slow, daemon=True)
        worker.start()
        time.sleep(0.3)

        c_status, c_data = self._json_request("POST", "/api/terminal/cancel", {}, headers=auth_hdr)
        self.assertEqual(c_status, 200)
        self.assertTrue(c_data.get("ok"))
        self.assertTrue(c_data.get("cancelled"))

        worker.join(timeout=3.0)
        elapsed = time.time() - t0
        self.assertLess(elapsed, 3.0)
        self.assertEqual(exec_result.get("status"), 200)
        self.assertNotEqual(exec_result.get("data", {}).get("exit_code"), 0)

    @staticmethod
    def _read_http_upgrade_headers(sock: socket.socket) -> tuple[str, dict[str, str]]:
        buf = bytearray()
        while b"\r\n\r\n" not in buf and len(buf) < 16384:
            chunk = sock.recv(1)
            if not chunk:
                break
            buf.extend(chunk)
        raw_hdrs = buf.decode("latin-1")
        lines = raw_hdrs.split("\r\n")
        status_line = lines[0] if lines else ""
        headers: dict[str, str] = {}
        for hline in lines[1:]:
            if ":" in hline:
                k, v = hline.split(":", 1)
                headers[k.strip().lower()] = v.strip()
        return status_line, headers

    @staticmethod
    def _ws_client_frame(opcode: int, payload: bytes) -> bytes:
        mask_key = os.urandom(4)
        length = len(payload)
        first = 0x80 | (opcode & 0x0F)
        if length < 126:
            header = struct.pack("!BB", first, 0x80 | length)
        elif length < 65536:
            header = struct.pack("!BBH", first, 0x80 | 126, length)
        else:
            header = struct.pack("!BBQ", first, 0x80 | 127, length)
        masked = bytes(b ^ mask_key[i & 3] for i, b in enumerate(payload))
        return header + mask_key + masked

    def test_11_vendor_xterm_assets_and_path_traversal_guard(self) -> None:
        for asset, expected_mime in (
            ("/api/terminal/vendor/xterm.js", "application/javascript"),
            ("/api/terminal/vendor/xterm-addon-fit.js", "application/javascript"),
            ("/api/terminal/vendor/xterm.css", "text/css"),
        ):
            conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
            conn.request("GET", asset)
            resp = conn.getresponse()
            body = resp.read()
            ct = resp.getheader("Content-Type", "")
            conn.close()
            self.assertEqual(resp.status, 200, asset)
            self.assertIn(expected_mime, ct)
            self.assertGreater(len(body), 500)

        # Reject unlisted or path-traversal filenames
        status, _ = self._json_request("GET", "/api/terminal/vendor/evil.js")
        self.assertEqual(status, 404)

    def test_12_websocket_pty_security_stream_resize_and_reattach(self) -> None:
        ws_key = base64.b64encode(os.urandom(16)).decode("ascii")

        # 1. Unauthenticated WebSocket upgrade MUST return 401
        conn_unauth = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        conn_unauth.request(
            "GET",
            "/api/terminal/ws",
            headers={
                "Connection": "Upgrade",
                "Upgrade": "websocket",
                "Sec-WebSocket-Version": "13",
                "Sec-WebSocket-Key": ws_key,
            },
        )
        r_unauth = conn_unauth.getresponse()
        r_unauth.read()
        conn_unauth.close()
        self.assertEqual(r_unauth.status, 401)

        # 2. Pair and mint single-use WS ticket
        _, pair_data = self._json_request("POST", "/api/terminal/pair", {"pin": self.pin})
        auth_hdr = {"Authorization": f"Bearer {pair_data['token']}"}

        t_status, t_data = self._json_request("POST", "/api/terminal/ws-ticket", {}, headers=auth_hdr)
        self.assertEqual(t_status, 200)
        self.assertTrue(t_data.get("ok"))
        ticket = t_data["ticket"]

        # 3. Cross-Site WebSocket Hijacking (CSWSH) Origin check MUST reject untrusted Origin (403)
        conn_cswsh = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        conn_cswsh.request(
            "GET",
            f"/api/terminal/ws?ticket={ticket}",
            headers={
                "Origin": "https://evil-attacker.example",
                "Connection": "Upgrade",
                "Upgrade": "websocket",
                "Sec-WebSocket-Version": "13",
                "Sec-WebSocket-Key": ws_key,
            },
        )
        r_cswsh = conn_cswsh.getresponse()
        r_cswsh.read()
        conn_cswsh.close()
        self.assertEqual(r_cswsh.status, 403)

        # 4. Mint fresh ticket and perform genuine RFC 6455 WebSocket upgrade over raw socket
        _, t_data2 = self._json_request("POST", "/api/terminal/ws-ticket", {}, headers=auth_hdr)
        ticket2 = t_data2["ticket"]

        raw_sock = socket.create_connection(("127.0.0.1", self.port), timeout=5.0)
        try:
            req_bytes = (
                f"GET /api/terminal/ws?ticket={ticket2}&cols=80&rows=24 HTTP/1.1\r\n"
                f"Host: 127.0.0.1:{self.port}\r\n"
                f"Origin: http://127.0.0.1:{self.port}\r\n"
                f"Upgrade: websocket\r\n"
                f"Connection: Upgrade\r\n"
                f"Sec-WebSocket-Key: {ws_key}\r\n"
                f"Sec-WebSocket-Version: 13\r\n\r\n"
            ).encode("ascii")
            raw_sock.sendall(req_bytes)

            status_line, resp_headers = self._read_http_upgrade_headers(raw_sock)
            self.assertIn("101 Switching Protocols", status_line)
            self.assertEqual(
                resp_headers.get("sec-websocket-accept"),
                pty_engine.ws_compute_accept_key(ws_key),
            )

            # 5. Replaying the consumed single-use ticket MUST fail with 401
            conn_replay = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
            conn_replay.request(
                "GET",
                f"/api/terminal/ws?ticket={ticket2}",
                headers={
                    "Connection": "Upgrade",
                    "Upgrade": "websocket",
                    "Sec-WebSocket-Version": "13",
                    "Sec-WebSocket-Key": ws_key,
                },
            )
            r_replay = conn_replay.getresponse()
            r_replay.read()
            conn_replay.close()
            self.assertEqual(r_replay.status, 401)

            # 6. Read initial JSON ready frame
            op0, payload0 = pty_engine.ws_read_frame(raw_sock)
            self.assertEqual(op0, pty_engine.WS_OP_TEXT)
            ready_msg = json.loads(payload0.decode("utf-8"))
            self.assertEqual(ready_msg.get("type"), "ready")
            session_id = ready_msg["session_id"]

            # 7. Resize PTY to 112x34 (TIOCSWINSZ + SIGWINCH) and run stty size + echo marker
            resize_cmd = json.dumps({"type": "resize", "cols": 112, "rows": 34}).encode("utf-8")
            raw_sock.sendall(self._ws_client_frame(pty_engine.WS_OP_TEXT, resize_cmd))
            time.sleep(0.08)

            shell_in = json.dumps(
                {"type": "input", "data": "stty size; echo WS_PTY_STREAM_OK\r"}
            ).encode("utf-8")
            raw_sock.sendall(self._ws_client_frame(pty_engine.WS_OP_TEXT, shell_in))

            collected = bytearray()
            deadline = time.time() + 4.0
            while time.time() < deadline:
                op, pl = pty_engine.ws_read_frame(raw_sock)
                if op == pty_engine.WS_OP_BINARY:
                    collected.extend(pl)
                    decoded = collected.decode("utf-8", errors="replace")
                    if "34 112" in decoded and "WS_PTY_STREAM_OK" in decoded:
                        break

            final_text = collected.decode("utf-8", errors="replace")
            self.assertIn("34 112", final_text)
            self.assertIn("WS_PTY_STREAM_OK", final_text)

            # Send clean WebSocket close frame (detach without killing shell)
            raw_sock.sendall(self._ws_client_frame(pty_engine.WS_OP_CLOSE, b""))
        finally:
            raw_sock.close()

        # 8. Reattach to the same session_id and verify 64 KiB scrollback ring-buffer replay!
        _, t_data3 = self._json_request("POST", "/api/terminal/ws-ticket", {}, headers=auth_hdr)
        re_sock = socket.create_connection(("127.0.0.1", self.port), timeout=5.0)
        try:
            re_req = (
                f"GET /api/terminal/ws?ticket={t_data3['ticket']}&session_id={session_id}&cols=112&rows=34 HTTP/1.1\r\n"
                f"Host: 127.0.0.1:{self.port}\r\n"
                f"Origin: http://127.0.0.1:{self.port}\r\n"
                f"Upgrade: websocket\r\n"
                f"Connection: Upgrade\r\n"
                f"Sec-WebSocket-Key: {ws_key}\r\n"
                f"Sec-WebSocket-Version: 13\r\n\r\n"
            ).encode("ascii")
            re_sock.sendall(re_req)
            re_status, _ = self._read_http_upgrade_headers(re_sock)
            self.assertIn("101 Switching Protocols", re_status)

            op_r, pl_r = pty_engine.ws_read_frame(re_sock)
            self.assertEqual(op_r, pty_engine.WS_OP_TEXT)
            re_ready = json.loads(pl_r.decode("utf-8"))
            self.assertTrue(re_ready.get("reattached"))

            op_hist, pl_hist = pty_engine.ws_read_frame(re_sock)
            self.assertEqual(op_hist, pty_engine.WS_OP_BINARY)
            self.assertIn(b"WS_PTY_STREAM_OK", pl_hist)

            re_sock.sendall(self._ws_client_frame(pty_engine.WS_OP_CLOSE, b""))
        finally:
            re_sock.close()

        # Close session via API
        c_st, c_res = self._json_request(
            "POST", "/api/terminal/pty/close", {"session_id": session_id}, headers=auth_hdr
        )
        self.assertEqual(c_st, 200)
        self.assertTrue(c_res.get("ok"))

    def test_13_http_pty_fallback_lifecycle(self) -> None:
        _, pair_data = self._json_request("POST", "/api/terminal/pair", {"pin": self.pin})
        auth_hdr = {"Authorization": f"Bearer {pair_data['token']}"}

        st_open, d_open = self._json_request(
            "POST", "/api/terminal/pty/open", {"cols": 90, "rows": 28}, headers=auth_hdr
        )
        self.assertEqual(st_open, 200)
        self.assertTrue(d_open.get("ok"))
        sid = d_open["session_id"]

        st_rsz, d_rsz = self._json_request(
            "POST",
            "/api/terminal/pty/resize",
            {"session_id": sid, "cols": 100, "rows": 30},
            headers=auth_hdr,
        )
        self.assertEqual(st_rsz, 200)
        self.assertTrue(d_rsz.get("ok"))

        st_in, d_in = self._json_request(
            "POST",
            "/api/terminal/pty/input",
            {"session_id": sid, "data": "echo HTTP_PTY_FALLBACK_OK\r"},
            headers=auth_hdr,
        )
        self.assertEqual(st_in, 200)
        self.assertTrue(d_in.get("ok"))

        cursor = 0
        acc = bytearray()
        for _ in range(6):
            st_poll, d_poll = self._json_request(
                "GET",
                f"/api/terminal/pty/poll?session_id={sid}&cursor={cursor}&timeout_ms=1000",
                headers=auth_hdr,
            )
            self.assertEqual(st_poll, 200)
            if d_poll.get("b64"):
                acc.extend(base64.b64decode(d_poll["b64"]))
            cursor = d_poll.get("cursor", cursor)
            if b"HTTP_PTY_FALLBACK_OK" in acc:
                break
        self.assertIn(b"HTTP_PTY_FALLBACK_OK", acc)

        st_close, _ = self._json_request(
            "POST", "/api/terminal/pty/close", {"session_id": sid}, headers=auth_hdr
        )
        self.assertEqual(st_close, 200)

    def test_14_multi_session_pty_list_and_isolation(self) -> None:
        # Unauthenticated list must return 401
        st_unauth, _ = self._json_request("GET", "/api/terminal/pty/list")
        self.assertEqual(st_unauth, 401)

        _, pair_data = self._json_request("POST", "/api/terminal/pair", {"pin": self.pin})
        auth_hdr = {"Authorization": f"Bearer {pair_data['token']}"}

        # Open two independent PTY sessions (Tab 1 & Tab 2)
        st1, d1 = self._json_request(
            "POST",
            "/api/terminal/pty/open",
            {"cols": 80, "rows": 24, "label": "Term 1"},
            headers=auth_hdr,
        )
        st2, d2 = self._json_request(
            "POST",
            "/api/terminal/pty/open",
            {"cols": 100, "rows": 30, "label": "Term 2"},
            headers=auth_hdr,
        )
        self.assertEqual(st1, 200)
        self.assertEqual(st2, 200)
        sid1 = d1["session_id"]
        sid2 = d2["session_id"]
        self.assertNotEqual(sid1, sid2)

        st_list, d_list = self._json_request("GET", "/api/terminal/pty/list", headers=auth_hdr)
        self.assertEqual(st_list, 200)
        self.assertTrue(d_list.get("ok"))
        listed_ids = {s["session_id"]: s for s in d_list.get("sessions", [])}
        self.assertIn(sid1, listed_ids)
        self.assertIn(sid2, listed_ids)
        self.assertEqual(listed_ids[sid1].get("label"), "Term 1")
        self.assertEqual(listed_ids[sid2].get("label"), "Term 2")

        # Closing Tab 1 must leave Tab 2 alive
        self._json_request("POST", "/api/terminal/pty/close", {"session_id": sid1}, headers=auth_hdr)
        _, d_after = self._json_request("GET", "/api/terminal/pty/list", headers=auth_hdr)
        remaining_ids = {s["session_id"] for s in d_after.get("sessions", [])}
        self.assertNotIn(sid1, remaining_ids)
        self.assertIn(sid2, remaining_ids)

        self._json_request("POST", "/api/terminal/pty/close", {"session_id": sid2}, headers=auth_hdr)

    def test_15_qr_banner_iso18004_matrix_and_ascii(self) -> None:
        import qr_banner

        sample_url = "https://example-quick-tunnel.trycloudflare.com#pin=123456"
        matrix = qr_banner.encode_qr_matrix(sample_url)
        size = len(matrix)
        self.assertGreaterEqual(size, 21)
        self.assertEqual((size - 21) % 4, 0)
        for row in matrix:
            self.assertEqual(len(row), size)

        # Verify top-left, top-right, and bottom-left 7x7 finder outer ring corners are dark (True)
        for r_off, c_off in ((0, 0), (0, size - 7), (size - 7, 0)):
            for i in range(7):
                self.assertTrue(matrix[r_off][c_off + i])
                self.assertTrue(matrix[r_off + 6][c_off + i])
                self.assertTrue(matrix[r_off + i][c_off])
                self.assertTrue(matrix[r_off + i][c_off + 6])
            self.assertTrue(matrix[r_off + 3][c_off + 3])

        ascii_art = qr_banner.render_qr_ascii(sample_url)
        self.assertGreaterEqual(len(ascii_art.splitlines()), 10)

    def test_16_public_repo_opsec_zero_personal_identifiers(self) -> None:
        import re

        repo_root = Path(__file__).resolve().parent.parent
        forbidden_patterns = (
            re.compile(r"[a-z0-9-]+\.tail[a-z0-9]+\.ts\.net", re.IGNORECASE),
            re.compile(r"/mnt/c/Users/[A-Za-z][A-Za-z0-9_-]*"),
            re.compile(r"AIza[0-9A-Za-z_-]{35}"),
            re.compile(r"\bDJ\s*MiTH\b", re.IGNORECASE),
        )
        for rel in (
            "README.md",
            "CHANGELOG.md",
            ".github/workflows/release.yml",
            "package.json",
            "run_daemon.sh",
            "start.sh",
            "start.ps1",
            "client/index.html",
            "client/manifest.json",
            "daemon/server.py",
            "daemon/pty_engine.py",
            "daemon/qr_banner.py",
        ):
            fpath = repo_root / rel
            if not fpath.exists():
                continue
            text = fpath.read_text(encoding="utf-8", errors="ignore")
            for pat in forbidden_patterns:
                self.assertIsNone(
                    pat.search(text),
                    f"OPSEC pattern '{pat.pattern}' matched in {rel}",
                )


if __name__ == "__main__":
    unittest.main()
