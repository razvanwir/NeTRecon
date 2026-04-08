# NetRecon 🕵️

> Fast async network scanner for pentesters & bug bounty hunters.

Async port scanning, service detection, network discovery, banner grabbing, SSL analysis, web tech detection, and automated enumeration.

![Python](https://img.shields.io/badge/python-3.12+-blue)
![License](https://img.shields.io/badge/license-MIT-green)

## Features

- ⚡ **Async Port Scanning** — Scan hundreds of ports concurrently
- 🔍 **Service Detection** — Auto-detects SSH, HTTP, SMB, FTP, MySQL, RDP, and more
- 🌐 **Network Discovery** — Find live hosts in a CIDR range
- 📂 **SMB Enumeration** — List shares via `smbclient`
- 📡 **NBT Scan** — NetBIOS-TS info via `nmblookup`
- 💾 **JSON Output** — Results saved automatically
- 🚀 **Auto Mode** — One-command scan + banner grab + SSL info + tech detection
- 🎯 **Banner Grabbing** — Grab service banners automatically
- 🔐 **SSL Info** — Get cert details, ciphers, expiration
- 🕸️ **DNS Enum** — Subdomain brute-force with custom wordlist
- 📦 **Port Presets** — `top20`, `top100`, `top1000` port lists

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
python netrecon.py -t <TARGET> -p 22,80,443,3389
```

### Network Discovery

```bash
python netrecon.py -t <CIDR> --scan-type network
```

### SMB Enumeration

```bash
python netrecon.py -t <TARGET> --scan-type smb
```

### NBT Scan

```bash
python netrecon.py -t <TARGET> --scan-type nbt
```

## Options

| Flag | Description | Default |
|------|-------------|---------|
| `-t, --target` | Target IP, domain, or CIDR | (required) |
| `-p, --ports` | Ports (22,80,443 or top20/top100/top1000) | `top100` |
| `--scan-type` | `port`, `network`, `nbt`, `smb`, `dns`, `auto` | `port` |
| `-c, --concurrency` | Max concurrent connections | `100` |
| `-o, --output` | Output JSON file | `scan_results.json` |
| `--banner` | Grab banners from open ports | false |
| `--ssl-info` | Get SSL certificate info | false |
| `--wordlist` | Wordlist for DNS enum | built-in list |

## Output

Results are saved to `scan_results.json`:

```json
{
  "target": "<TARGET>",
  "scan_type": "<port|network|nbt|smb|dns|auto>",
  "timestamp": "<TIMESTAMP>",
  "findings": [
    {"port": <PORT>, "status": "open", "service": "<SERVICE>"},
    {"port": <PORT>, "status": "open", "service": "<SERVICE>"}
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