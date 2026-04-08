#!/usr/bin/env python3
"""
NetRecon - Async Network Scanner Toolkit

Asynchronous network scanning tool for pentesters and bug bounty hunters.
"""

import argparse
import asyncio
import json
import logging
import socket
import ssl
import sys
import ipaddress
import base64
import os
from datetime import datetime
from pathlib import Path

import aiohttp
from netaddr import IPNetwork

# Setup logging - file only (no console output for privacy)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('netrecon.log')
    ]
)
logger = logging.getLogger(__name__)


# Common ports for pentesting
COMMON_PORTS = {
    'top20': [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080],
    'top100': [20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 81, 110, 111, 119, 123, 135, 139, 143, 161, 162, 389, 443, 445, 465, 514, 515, 587, 993, 995, 1433, 1521, 1723, 2049, 2082, 2083, 2086, 2087, 2095, 2096, 3306, 3389, 5432, 5900, 5901, 5984, 5985, 6000, 6001, 6379, 6443, 8000, 8001, 8008, 8009, 8080, 8081, 8443, 8888, 9090, 9200, 9300, 27017],
    'top1000': list(range(1, 1001)),
}


async def scan_port(target: str, port: int, timeout: float = 2.0) -> dict:
    """Scan a single TCP port."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(target, port),
            timeout=timeout
        )
        writer.close()
        await writer.wait_closed()
        return {"port": port, "status": "open"}
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        return {"port": port, "status": "closed"}
    except Exception as e:
        return {"port": port, "status": "error", "error": str(e)}


async def scan_ports(target: str, ports: list[int], concurrency: int = 100) -> list[dict]:
    """Scan multiple TCP ports asynchronously."""
    semaphore = asyncio.Semaphore(concurrency)
    
    async def limited_scan(port):
        async with semaphore:
            return await scan_port(target, port)
    
    tasks = [limited_scan(p) for p in ports]
    results = await asyncio.gather(*tasks)
    return [r for r in results if r["status"] == "open"]


async def detect_service(target: str, port: int) -> str:
    """Detect the service running on an open port."""
    service_map = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
        80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
        993: "IMAPS", 995: "POP3S", 3306: "MySQL", 3389: "RDP",
        5432: "PostgreSQL", 6379: "Redis", 8080: "HTTP-Proxy",
        8443: "HTTPS-Alt", 9200: "Elasticsearch", 27017: "MongoDB",
    }
    return service_map.get(port, "Unknown")


async def grab_banner(target: str, port: int, timeout: float = 3.0) -> str:
    """Grab banner from open port."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(target, port),
            timeout=timeout
        )
        
        # Send generic probe
        if port in [80, 8080, 8000]:
            writer.write(b"GET / HTTP/1.0\r\n\r\n")
        elif port == 21:
            pass  # FTP banners usually come automatically
        
        try:
            data = await asyncio.wait_for(reader.read(1024), timeout=timeout)
            banner = data.decode('utf-8', errors='ignore').strip()
            writer.close()
            await writer.wait_closed()
            return banner[:200] if banner else ""
        except:
            pass
        
        writer.close()
        await writer.wait_closed()
        return ""
    except Exception as e:
        return ""


async def get_ssl_info(target: str, port: int = 443) -> dict:
    """Get SSL certificate info."""
    try:
        context = ssl.create_default_context()
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(target, port),
            timeout=5.0
        )
        with context.wrap_socket(writer, server_hostname=target) as sock:
            cert = sock.getpeercert()
            cipher = sock.cipher()
            
            return {
                "issuer": dict(x[0] for x in cert.get('issuer', [])),
                "subject": dict(x[0] for x in cert.get('subject', [])),
                "valid_from": cert.get('notBefore', ''),
                "valid_until": cert.get('notAfter', ''),
                "cipher": cipher[0] if cipher else None,
            }
    except Exception as e:
        return {"error": str(e)}


async def detect_web_tech(url: str) -> dict:
    """Detect web technologies."""
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                headers = dict(resp.headers)
                server = headers.get('Server', '')
                powered = headers.get('X-Powered-By', '')
                
                # Check for common tech in body
                body = ""
                async for chunk in session.get(url).content:
                    body += chunk.decode('utf-8', errors='ignore')
                    if len(body) > 50000:
                        break
                
                tech = []
                if 'nginx' in server.lower(): tech.append('nginx')
                if 'apache' in server.lower(): tech.append('apache')
                if 'express' in body.lower(): tech.append('Express')
                if 'django' in body.lower(): tech.append('Django')
                if 'laravel' in body.lower(): tech.append('Laravel')
                if 'wordpress' in body.lower(): tech.append('WordPress')
                if 'react' in body.lower(): tech.append('React')
                if 'vue' in body.lower(): tech.append('Vue.js')
                if 'next' in body.lower(): tech.append('Next.js')
                
                return {
                    "status": resp.status,
                    "server": server,
                    "powered_by": powered,
                    "tech_detected": tech,
                    "headers": headers,
                }
    except Exception as e:
        return {"error": str(e)}


async def dns_enum(domain: str, wordlist: str = None) -> list[dict]:
    """DNS enumeration with subdomain brute-force."""
    subdomains = ["www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "webdisk", "ns2", "cdn", "cloud", "ajax", "api", "dev", "staging", "shop", "admin", "crm", "blog", "vpn", "dmz"]
    
    if wordlist and os.path.exists(wordlist):
        with open(wordlist) as f:
            subdomains = [line.strip() for line in f if line.strip()]
    
    found = []
    for sub in subdomains:
        try:
            host = f"{sub}.{domain}"
            ip = socket.gethostbyname(host)
            found.append({"subdomain": host, "ip": ip})
            logger.info(f"  Found: {host} -> {ip}")
        except socket.gaierror:
            pass
    
    return found


async def network_discovery(network: str) -> list[dict]:
    """Discover devices in an IP range using ping sweep."""
    discovered = []
    try:
        net = IPNetwork(network)
        logger.info(f"Scanning network: {network}")
        
        for ip in net:
            try:
                proc = await asyncio.create_subprocess_exec(
                    'ping', '-c', '1', '-W', '1', str(ip),
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=2.0)
                if proc.returncode == 0:
                    device = {"ip": str(ip), "status": "up"}
                    try:
                        device["hostname"] = socket.gethostbyaddr(str(ip))[0]
                    except socket.herror:
                        pass
                    discovered.append(device)
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                logger.debug(f"Error scanning {ip}: {e}")
                
    except Exception as e:
        logger.error(f"Error during network discovery: {e}")
    
    return discovered


async def nbt_scan(target: str) -> list[dict]:
    """NBT (NetBIOS-TS) scanner using nmblookup."""
    results = []
    try:
        proc = await asyncio.create_subprocess_exec(
            'nmblookup', '-A', target,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=10.0)
        
        if proc.returncode == 0:
            output = stdout.decode()
            for line in output.split('\n'):
                if '<00>' in line or '<20>' in line:
                    results.append({"line": line.strip()})
    except FileNotFoundError:
        logger.warning("nmblookup not found. Install smbclient for NBT scanning.")
    except Exception as e:
        logger.error(f"Error during NBT scan: {e}")
    
    return results


async def smb_enum(target: str) -> list[dict]:
    """Basic SMB enumeration using smbclient."""
    results = []
    try:
        proc = await asyncio.create_subprocess_exec(
            'smbclient', '-L', f'//{target}',
            '-N',
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=10.0)
        
        if proc.returncode == 0:
            output = stdout.decode()
            for line in output.split('\n'):
                if 'Disk' in line or 'Printer' in line:
                    results.append({"share": line.strip()})
    except FileNotFoundError:
        logger.warning("smbclient not found. Install smbclient for SMB enumeration.")
    except Exception as e:
        logger.error(f"Error during SMB enumeration: {e}")
    
    return results


def save_results(results: dict, output_file: str = "scan_results.json"):
    """Save scan results to JSON file."""
    output_path = Path(output_file)
    with open(output_path, 'w') as f:
        json.dump(results, f, indent=2)
    logger.info(f"Results saved to {output_path}")


async def auto_scan(target: str, concurrency: int = 100) -> dict:
    """Auto-detect open ports and run appropriate enumeration."""
    logger.info(f"🎯 Auto-scanning {target}...")
    
    # Phase 1: Quick port scan (top 100)
    quick_ports = COMMON_PORTS['top100']
    open_ports = await scan_ports(target, quick_ports, concurrency)
    
    logger.info(f"Found {len(open_ports)} open port(s): {[p['port'] for p in open_ports]}")
    
    findings = []
    
    for port_info in open_ports:
        port = port_info["port"]
        service = await detect_service(target, port)
        logger.info(f"  📡 Port {port}: {service}")
        
        port_result = {"port": port, "service": service}
        
        # Grab banner
        banner = await grab_banner(target, port)
        if banner:
            port_result["banner"] = banner[:200]
            logger.info(f"     Banner: {banner[:80]}...")
        
        # Service-specific enumeration
        if service in ["HTTP", "HTTP-Proxy"]:
            url = f"http://{target}:{port}" if port not in [80, 443] else f"http://{target}"
            if port == 443 or port == 8443:
                url = f"https://{target}:{port}" if port != 443 else f"https://{target}"
            
            web_info = await detect_web_tech(url)
            port_result["web"] = web_info
            if web_info.get("tech_detected"):
                logger.info(f"     Tech: {', '.join(web_info['tech_detected'])}")
        
        elif service == "HTTPS" or port == 443:
            ssl_info = await get_ssl_info(target, port)
            port_result["ssl"] = ssl_info
            if ssl_info.get("subject"):
                logger.info(f"     SSL: {ssl_info['subject'].get('commonName', 'N/A')}")
        
        findings.append(port_result)
    
    return {
        "target": target,
        "scan_type": "auto",
        "timestamp": datetime.now().isoformat(),
        "open_ports_count": len(open_ports),
        "findings": findings,
    }


async def main():
    parser = argparse.ArgumentParser(
        prog='netrecon',
        description='⚡ Fast async network scanner for pentesters & bug bounty hunters'
    )
    parser.add_argument('-t', '--target', help='Target IP, domain, or network (CIDR)')
    parser.add_argument('-p', '--ports', help='Comma-separated ports or preset (top20/top100/top1000)')
    parser.add_argument('--scan-type', choices=['port', 'network', 'nbt', 'smb', 'dns', 'auto'], default='port', help='Scan type')
    parser.add_argument('-c', '--concurrency', type=int, default=100, help='Max concurrent connections')
    parser.add_argument('-o', '--output', default='scan_results.json', help='Output JSON file')
    parser.add_argument('--banner', action='store_true', help='Grab banners from open ports')
    parser.add_argument('--ssl-info', action='store_true', help='Get SSL certificate info')
    parser.add_argument('--wordlist', help='Wordlist for DNS subdomain brute-force')
    
    args = parser.parse_args()
    
    if not args.target:
        parser.print_help()
        sys.exit(1)
    
    results = {
        "target": args.target,
        "scan_type": args.scan_type,
        "timestamp": datetime.now().isoformat(),
        "findings": []
    }
    
    # Auto mode
    if args.scan_type == 'auto':
        results = await auto_scan(args.target, args.concurrency)
        save_results(results, args.output)
        return
    
    # Parse ports
    ports = []
    if args.ports:
        if args.ports in COMMON_PORTS:
            ports = COMMON_PORTS[args.ports]
        else:
            try:
                ports = [int(p.strip()) for p in args.ports.split(',')]
            except ValueError:
                logger.error("Invalid port list. Use: 22,80,443 or top20/top100/top1000")
                sys.exit(1)
    
    # Port scan
    if args.scan_type == 'port':
        if not ports:
            ports = COMMON_PORTS['top100']
        
        logger.info(f"Scanning ports {ports[:10]}... on {args.target}")
        open_ports = await scan_ports(args.target, ports, args.concurrency)
        
        for port_info in open_ports:
            service = await detect_service(args.target, port_info["port"])
            result = {"port": port_info["port"], "status": port_info["status"], "service": service}
            
            # Banner grab
            if args.banner:
                banner = await grab_banner(args.target, port_info["port"])
                if banner:
                    result["banner"] = banner[:200]
            
            # SSL info
            if args.ssl_info and port_info["port"] in [443, 8443]:
                result["ssl"] = await get_ssl_info(args.target, port_info["port"])
            
            results["findings"].append(result)
            logger.info(f"  Port {port_info['port']}: {port_info['status']} ({service})")
        
        logger.info(f"Scan complete. Found {len(open_ports)} open port(s).")
    
    # Network discovery
    elif args.scan_type == 'network':
        devices = await network_discovery(args.target)
        results["findings"] = devices
        for device in devices:
            logger.info(f"  {device['ip']} - {device.get('hostname', 'N/A')}")
    
    # NBT scan
    elif args.scan_type == 'nbt':
        nbt_results = await nbt_scan(args.target)
        results["findings"] = nbt_results
        for r in nbt_results:
            logger.info(f"  {r.get('line', 'N/A')}")
    
    # SMB enum
    elif args.scan_type == 'smb':
        smb_results = await smb_enum(args.target)
        results["findings"] = smb_results
        for r in smb_results:
            logger.info(f"  {r.get('share', 'N/A')}")
    
    # DNS enum
    elif args.scan_type == 'dns':
        dns_results = await dns_enum(args.target, args.wordlist)
        results["findings"] = dns_results
        logger.info(f"DNS enum complete. Found {len(dns_results)} subdomain(s).")
    
    save_results(results, args.output)


if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Scan interrupted by user")
        sys.exit(130)