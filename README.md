# NetRecon 🕵️

> Asynchronous network scanning toolkit for penetration testers and CTF players.

Fast, async port scanning with service detection, network discovery, and SMB/NBT enumeration.

![Python](https://img.shields.io/badge/python-3.12+-blue)
![License](https://img.shields.io/badge/license-MIT-green)

## Features

- ⚡ **Async Port Scanning** — Scan hundreds of ports concurrently
- 🔍 **Service Detection** — Auto-detects SSH, HTTP, SMB, FTP, MySQL, RDP, and more
- 🌐 **Network Discovery** — Find live hosts in a CIDR range
- 📂 **SMB Enumeration** — List shares via `smbclient`
- 📡 **NBT Scan** — NetBIOS-TS info via `nmblookup`
- 💾 **JSON Output** — Results saved automatically

## Installation

```bash
# Clone
git clone https://github.com/razvanwir/NeTRecon.git
cd NeTRecon

# Create venv (recommended)
python3 -m venv .venv
source .venv/bin/activate

# Install deps
pip install -r requirements.txt
```

## Usage

### Port Scan (default)

```bash
python netrecon.py -t 192.168.1.1 -p 22,80,443,3389
```

Output:
```
2026-04-08 11:42:18 - INFO - Scanning ports [22, 80, 443, 3389] on 192.168.1.1
2026-04-08 11:42:18 - INFO -   Port 22: open (SSH)
2026-04-08 11:42:18 - INFO -   Port 443: open (HTTPS)
2026-04-08 11:42:18 - INFO - Scan complete. Found 2 open port(s).
2026-04-08 11:42:18 - INFO - Results saved to scan_results.json
```

### Network Discovery

```bash
python netrecon.py -t 192.168.1.0/24 --scan-type network
```

### SMB Enumeration

```bash
python netrecon.py -t 192.168.1.1 --scan-type smb
```

### NBT Scan

```bash
python netrecon.py -t 192.168.1.1 --scan-type nbt
```

## Options

| Flag | Description | Default |
|------|-------------|---------|
| `-t, --target` | Target IP or CIDR network | (required) |
| `-p, --ports` | Comma-separated ports | `22,80,443` |
| `--scan-type` | `port`, `network`, `nbt`, `smb` | `port` |
| `-c, --concurrency` | Max concurrent connections | `100` |
| `-o, --output` | Output JSON file | `scan_results.json` |

## Output

Results are saved to `scan_results.json`:

```json
{
  "target": "192.168.1.1",
  "scan_type": "port",
  "timestamp": "2026-04-08T11:42:18.431446",
  "findings": [
    {"port": 22, "status": "open", "service": "SSH"},
    {"port": 443, "status": "open", "service": "HTTPS"}
  ]
}
```

## Requirements

- Python 3.12+
- `aiohttp` — async HTTP client
- `netaddr` — IP network handling
- `nmblookup` / `smbclient` — for NBT/SMB scans (optional)

Install all with:
```bash
pip install -r requirements.txt
```

## License

MIT — see [LICENSE](LICENSE)