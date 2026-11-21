# Lab Port Scanner

A small web interface that runs a **light TCP scan against one approved lab host**
and lists the open ports and detected services. No dependencies beyond Python 3.10+.

## Run

```bash
python server.py
```

Open <http://127.0.0.1:8001> and click **Run Scan**.

| Env var       | Default           | Purpose                                         |
|---------------|-------------------|-------------------------------------------------|
| `LAB_TARGET`  | `192.168.186.128` | The approved lab host (must be a private IP)     |
| `PORT`        | `8001`            | Web UI port                                     |
| `SCAN_ENGINE` | auto              | Set to `python` to force the built-in scanner   |

PowerShell example: `$env:LAB_TARGET="192.168.13.132"; python server.py`

## What it scans

- **Target:** fixed server-side from `LAB_TARGET`, shown read-only in the UI.
- **Ports:** ~110 TCP ports (nmap's top 100, plus common lab ports such as 6379, 7001, 8161, 9200, 27017).
- **Engine:**
  - **nmap** (used automatically if installed):
    `nmap -sT -Pn -T3 -sV --version-light --max-retries 1 --host-timeout 240s -p <ports> <target>`
  - **python** fallback: asyncio TCP connect scan (1 s timeout, 50 concurrent) plus a passive
    banner read. HTTP ports also get a single `HEAD /` request.
- **Not used:** OS detection, NSE scripts, SYN or raw-packet scans, aggressive timing, UDP.

## Output

Each open port appears with its service name, product/version (from nmap `-sV` or the banner), the
raw banner, and a short analyst note. Every scan is also saved as JSON in `./scans/`, and the
**↓ JSON** button downloads the result.

## Safety rails

1. The browser never sends a target. `POST /api/scan` always scans `LAB_TARGET`, and any request
   that names a different target gets a `403`.
2. The server refuses to start if `LAB_TARGET` is not a private or loopback IP.
3. The UI binds to `127.0.0.1` only, so other machines can't trigger scans.
4. Only one scan runs at a time (`409` if one is already running).

## Files

```
server.py          stdlib HTTP server + API (/api/config, /api/scan)
scanner.py         nmap backend, python fallback, port list, service notes
static/index.html  single-page UI (no CDN - works offline in the lab)
scans/             saved JSON results (created on first scan)
```
