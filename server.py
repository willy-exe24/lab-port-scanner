"""Lab Port Scanner - tiny web UI that scans ONE approved lab host.

Run:   python server.py            (then open http://127.0.0.1:8001)
Config (env vars):
    LAB_TARGET   approved lab host IP     (default 192.168.186.128)
    PORT         web UI port              (default 8001)
    SCAN_ENGINE  "python" to force the built-in scanner even if nmap exists

Safety rails:
  * The target is fixed server-side; the browser never sends one.
  * LAB_TARGET must be a private / loopback address or the server won't start.
  * The UI binds to 127.0.0.1 only, and only one scan can run at a time.
"""

from __future__ import annotations

import ipaddress
import json
import os
import sys
import threading
import traceback
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import scanner

LAB_TARGET = os.environ.get("LAB_TARGET", "192.168.186.128").strip()
BIND_HOST = "127.0.0.1"
PORT = int(os.environ.get("PORT", "8001"))

BASE_DIR = Path(__file__).resolve().parent
INDEX_HTML = BASE_DIR / "static" / "index.html"
SCAN_DIR = BASE_DIR / "scans"

_scan_lock = threading.Lock()


def _validate_target(value: str) -> str:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        sys.exit(f"[!] LAB_TARGET must be an IP address, got {value!r}")
    if not (ip.is_private or ip.is_loopback):
        sys.exit(f"[!] LAB_TARGET {ip} is not a private lab address - refusing to start.")
    return str(ip)


class Handler(BaseHTTPRequestHandler):
    server_version = "LabScanner/1.0"

    # --- helpers -------------------------------------------------------------
    def _send(self, code: int, body: bytes, ctype: str, extra: dict | None = None) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _json(self, code: int, payload: dict) -> None:
        self._send(code, json.dumps(payload, indent=2).encode(), "application/json")

    # --- routes --------------------------------------------------------------
    def do_GET(self) -> None:  # noqa: N802
        if self.path in ("/", "/index.html"):
            self._send(200, INDEX_HTML.read_bytes(), "text/html; charset=utf-8")
        elif self.path == "/api/config":
            self._json(200, {
                "target": LAB_TARGET,
                "engine": scanner.engine_name(),
                "ports": scanner.TOP_PORTS,
                "busy": _scan_lock.locked(),
            })
        else:
            self._json(404, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        if self.path != "/api/scan":
            self._json(404, {"error": "not found"})
            return

        # The target is never taken from the client. If one is sent anyway and
        # it isn't the approved host, reject it loudly so misuse is obvious.
        length = int(self.headers.get("Content-Length") or 0)
        if length:
            try:
                body = json.loads(self.rfile.read(min(length, 4096)) or b"{}")
            except ValueError:
                body = {}
            requested = str(body.get("target", LAB_TARGET)).strip()
            if requested != LAB_TARGET:
                self._json(403, {"error": f"target {requested!r} is not the approved lab host"})
                return

        if not _scan_lock.acquire(blocking=False):
            self._json(409, {"error": "a scan is already running"})
            return
        try:
            print(f"[scan] starting {scanner.engine_name()} scan of {LAB_TARGET}")
            result = scanner.run_scan(LAB_TARGET)
            result["saved_as"] = _save(result)
            print(f"[scan] done: {len(result['open_ports'])} open port(s) in {result['duration_s']}s")
            self._json(200, result)
        except Exception as exc:  # noqa: BLE001 - report to UI
            traceback.print_exc()
            self._json(500, {"error": str(exc)})
        finally:
            _scan_lock.release()

    def log_message(self, fmt: str, *args) -> None:
        sys.stderr.write(f"[http] {self.address_string()} {fmt % args}\n")


def _save(result: dict) -> str:
    SCAN_DIR.mkdir(exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    path = SCAN_DIR / f"scan_{result['target'].replace(':', '_')}_{stamp}.json"
    path.write_text(json.dumps(result, indent=2), encoding="utf-8")
    return str(path.relative_to(BASE_DIR))


def main() -> None:
    global LAB_TARGET
    LAB_TARGET = _validate_target(LAB_TARGET)
    httpd = ThreadingHTTPServer((BIND_HOST, PORT), Handler)
    print(f"[*] Lab Port Scanner on http://{BIND_HOST}:{PORT}")
    print(f"[*] Approved target : {LAB_TARGET}")
    print(f"[*] Scan engine     : {scanner.engine_name()}  ({len(scanner.TOP_PORTS)} TCP ports)")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] stopped")


if __name__ == "__main__":
    main()
