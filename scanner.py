"""Light TCP scan of a single, pre-approved lab host.

Two backends, same port list and same output shape:

* nmap   - used automatically when the ``nmap`` binary is installed.
           Safe flags only: TCP connect scan (-sT), light version probing,
           no OS detection, no NSE scripts, no aggressive timing.
* python - pure-stdlib asyncio TCP connect scan + passive banner grab.
           Used when nmap is not available (e.g. a fresh Windows box).
"""

from __future__ import annotations

import asyncio
import os
import re
import shutil
import subprocess
import time
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

# Roughly nmap's "top 100" TCP ports plus a handful of common lab/VulHub ports.
TOP_PORTS = sorted({
    7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111, 113,
    119, 135, 139, 143, 144, 179, 199, 389, 427, 443, 444, 445, 465, 513, 514,
    515, 543, 544, 548, 554, 587, 631, 646, 873, 990, 993, 995, 1025, 1026,
    1027, 1028, 1029, 1110, 1433, 1720, 1723, 1755, 1900, 2000, 2001, 2049,
    2121, 2717, 3000, 3128, 3306, 3389, 3986, 4899, 5000, 5009, 5051, 5060,
    5101, 5190, 5357, 5432, 5631, 5666, 5800, 5900, 6000, 6001, 6646, 7070,
    8000, 8008, 8009, 8080, 8081, 8443, 8888, 9100, 9999, 10000, 32768,
    49152, 49153, 49154, 49155, 49156, 49157,
    # common lab / VulHub service ports
    2222, 5672, 6379, 7001, 8161, 9000, 9090, 9200, 11211, 27017, 61616,
})

SERVICE_NAMES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "domain", 80: "http",
    81: "http", 88: "kerberos", 110: "pop3", 111: "rpcbind", 119: "nntp",
    135: "msrpc", 139: "netbios-ssn", 143: "imap", 389: "ldap", 443: "https",
    445: "microsoft-ds", 465: "smtps", 513: "login", 514: "shell", 548: "afp",
    554: "rtsp", 587: "submission", 631: "ipp", 873: "rsync", 990: "ftps",
    993: "imaps", 995: "pop3s", 1433: "ms-sql", 1723: "pptp", 2049: "nfs",
    2121: "ftp", 2222: "ssh", 3000: "http", 3128: "http-proxy", 3306: "mysql",
    3389: "rdp", 5000: "http", 5060: "sip", 5432: "postgresql", 5672: "amqp",
    5800: "vnc-http", 5900: "vnc", 6000: "x11", 6379: "redis", 7001: "weblogic",
    8000: "http", 8008: "http", 8009: "ajp13", 8080: "http-proxy",
    8081: "http", 8161: "activemq-web", 8443: "https-alt", 8888: "http",
    9000: "http", 9090: "http", 9100: "jetdirect", 9200: "elasticsearch",
    10000: "webmin", 11211: "memcached", 27017: "mongodb", 61616: "activemq",
}

HTTP_PORTS = {80, 81, 3000, 5000, 7001, 8000, 8008, 8080, 8081, 8161, 8888, 9000, 9090, 9200, 10000}

# Short analyst notes surfaced next to each detected service.
NOTES = {
    "ftp": "Check for anonymous login and the exact server version.",
    "ssh": "Remote shell. Note the version (e.g. OpenSSH CVE-2018-15473 user enum).",
    "telnet": "Cleartext remote login - credentials travel unencrypted.",
    "smtp": "Mail server. Check for open relay / VRFY user enumeration.",
    "domain": "DNS. Check whether zone transfers (AXFR) are allowed.",
    "http": "Web service. Browse it and fingerprint the framework/app.",
    "http-proxy": "Web service / proxy. Browse it and fingerprint the app.",
    "https": "TLS web service. Inspect the certificate and the app.",
    "https-alt": "TLS web service on an alternate port.",
    "rpcbind": "RPC portmapper - may expose NFS or other RPC services.",
    "netbios-ssn": "SMB over NetBIOS. Check for null sessions / shares.",
    "microsoft-ds": "SMB. Check signing, shares, and version (e.g. MS17-010).",
    "mysql": "Database exposed on the network. Check for weak/default creds.",
    "postgresql": "Database exposed on the network. Check for weak/default creds.",
    "ms-sql": "Database exposed on the network. Check for weak/default creds.",
    "rdp": "Remote Desktop. Check NLA and patch level.",
    "vnc": "Remote desktop. Check for no-auth or weak password.",
    "redis": "Often unauthenticated by default - high risk if exposed.",
    "mongodb": "Often unauthenticated by default - high risk if exposed.",
    "memcached": "Unauthenticated cache - data exposure risk.",
    "elasticsearch": "REST API often unauthenticated - data exposure risk.",
    "ajp13": "Tomcat AJP connector (Ghostcat CVE-2020-1938 if old).",
    "weblogic": "Oracle WebLogic - historically many deserialization CVEs.",
    "activemq": "ActiveMQ broker (CVE-2023-46604 if old).",
    "activemq-web": "ActiveMQ admin console - check default admin:admin.",
    "webmin": "Web admin panel - check version for known RCEs.",
}

CONNECT_TIMEOUT = 1.0
BANNER_TIMEOUT = 2.0
CONCURRENCY = 50
NMAP_TIMEOUT = 300


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def find_nmap() -> str | None:
    found = shutil.which("nmap")
    if found:
        return found
    for candidate in (r"C:\Program Files (x86)\Nmap\nmap.exe", r"C:\Program Files\Nmap\nmap.exe"):
        if os.path.isfile(candidate):
            return candidate
    return None


def engine_name() -> str:
    if os.environ.get("SCAN_ENGINE", "").lower() == "python":
        return "python"
    return "nmap" if find_nmap() else "python"


# --------------------------------------------------------------------------- #
# Public entry point
# --------------------------------------------------------------------------- #
def run_scan(target: str) -> dict:
    """Scan ``target`` (already validated by the caller) and return a JSON-safe dict."""
    started_at = _now()
    t0 = time.perf_counter()
    engine = engine_name()

    if engine == "nmap":
        command, ports, host_state = _nmap_scan(target)
    else:
        command = (
            f"python asyncio TCP connect scan: {len(TOP_PORTS)} ports, "
            f"timeout {CONNECT_TIMEOUT}s, concurrency {CONCURRENCY}, passive banner grab"
        )
        ports = asyncio.run(_python_scan(target))
        host_state = "up" if ports else "unknown"

    for p in ports:
        p["note"] = NOTES.get(p["service"], "")

    return {
        "target": target,
        "engine": engine,
        "command": command,
        "started_at": started_at,
        "finished_at": _now(),
        "duration_s": round(time.perf_counter() - t0, 2),
        "ports_scanned": len(TOP_PORTS),
        "host_state": host_state,
        "open_ports": sorted(ports, key=lambda p: p["port"]),
    }


# --------------------------------------------------------------------------- #
# nmap backend
# --------------------------------------------------------------------------- #
def _nmap_scan(target: str) -> tuple[str, list[dict], str]:
    cmd = [
        find_nmap(),
        "-sT",                  # TCP connect scan (no raw packets / admin rights)
        "-Pn",                  # single known host - skip ping discovery
        "-T3",                  # normal timing, not aggressive
        "-sV", "--version-light",  # light service/version probing only
        "--max-retries", "1",
        "--host-timeout", "240s",
        "-p", ",".join(map(str, TOP_PORTS)),
        "-oX", "-",
        target,
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=NMAP_TIMEOUT)
    if proc.returncode != 0 and not proc.stdout.strip():
        raise RuntimeError(f"nmap failed: {proc.stderr.strip() or proc.returncode}")

    shown = " ".join(["nmap", *cmd[1:-2]]) + " " + target  # hide long path, keep flags
    shown = shown.replace(" -p " + ",".join(map(str, TOP_PORTS)), f" -p <{len(TOP_PORTS)} top ports>")

    root = ET.fromstring(proc.stdout)
    host = root.find("host")
    if host is None:
        return shown, [], "down"
    status = host.find("status")
    host_state = status.get("state", "unknown") if status is not None else "unknown"

    ports: list[dict] = []
    for port in host.iterfind("ports/port"):
        state = port.find("state")
        if state is None or state.get("state") != "open":
            continue
        svc = port.find("service")
        get = (lambda k: svc.get(k, "") if svc is not None else "")
        ports.append({
            "port": int(port.get("portid")),
            "protocol": port.get("protocol", "tcp"),
            "state": "open",
            "service": get("name") or SERVICE_NAMES.get(int(port.get("portid")), "unknown"),
            "product": get("product"),
            "version": " ".join(x for x in (get("version"), get("extrainfo")) if x),
            "banner": "",
        })
    return shown, ports, host_state


# --------------------------------------------------------------------------- #
# Pure-python backend
# --------------------------------------------------------------------------- #
async def _python_scan(target: str) -> list[dict]:
    sem = asyncio.Semaphore(CONCURRENCY)
    results = await asyncio.gather(*(_probe(target, p, sem) for p in TOP_PORTS))
    return [r for r in results if r]


async def _probe(host: str, port: int, sem: asyncio.Semaphore) -> dict | None:
    async with sem:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), CONNECT_TIMEOUT
            )
        except (OSError, asyncio.TimeoutError):
            return None

        data = b""
        try:
            try:
                data = await asyncio.wait_for(reader.read(1024), BANNER_TIMEOUT)
            except asyncio.TimeoutError:
                data = b""
            if not data and port in HTTP_PORTS:
                writer.write(f"HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n".encode())
                await writer.drain()
                data = await asyncio.wait_for(reader.read(2048), BANNER_TIMEOUT)
        except (OSError, asyncio.TimeoutError):
            pass
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except OSError:
                pass

    return {"port": port, "protocol": "tcp", "state": "open", **_identify(port, data)}


def _identify(port: int, data: bytes) -> dict:
    text = data.decode("latin-1", errors="replace")
    first = text.splitlines()[0].strip() if text.strip() else ""
    service = SERVICE_NAMES.get(port, "unknown")
    product = version = ""

    if first.startswith("SSH-"):
        service = "ssh"
        m = re.match(r"SSH-[\d.]+-([A-Za-z]+)[_-]?(\S*)\s*(.*)", first)
        if m:
            product, version = m.group(1), " ".join(x for x in m.group(2, 3) if x)
    elif first.startswith("HTTP/"):
        if service not in ("https", "https-alt"):
            service = SERVICE_NAMES.get(port, "http") if port in HTTP_PORTS else "http"
        m = re.search(r"^Server:\s*(.+)$", text, re.I | re.M)
        if m:
            product = m.group(1).strip()
    elif first.startswith("220"):
        low = first.lower()
        service = "smtp" if ("smtp" in low or port in (25, 465, 587)) else "ftp"
        product = first[3:].strip(" -()")
    elif first.startswith("+OK"):
        service, product = "pop3", first[3:].strip()
    elif first.startswith("* OK"):
        service, product = "imap", first[4:].strip()
    elif port == 3306 or b"mysql_native_password" in data:
        m = re.search(rb"(\d+\.\d+\.\d+[\w.\-]*)", data)
        service = "mysql"
        if m:
            product, version = "MySQL", m.group(1).decode()

    printable = re.sub(r"[^\x20-\x7e]+", " ", first).strip()[:160]
    return {"service": service, "product": product, "version": version, "banner": printable}
