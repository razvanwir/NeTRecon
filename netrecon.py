#!/usr/bin/env python3
"""
NetRecon - Async Network Scanner Toolkit

Asynchronous network scanning tool for port scanning, network discovery,
and basic SMB/NBT enumeration operations.
"""

import argparse
import asyncio
import json
import logging
import socket
import sys
import ipaddress
from datetime import datetime
from pathlib import Path

import aiohttp
from netaddr import IPNetwork

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('netrecon.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


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
    # Common port to service mapping
    service_map = {
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        143: "IMAP",
        443: "HTTPS",
        445: "SMB",
        993: "IMAPS",
        995: "POP3S",
        3306: "MySQL",
        3389: "RDP",
        5432: "PostgreSQL",
        8080: "HTTP-Proxy",
        8443: "HTTPS-Alt",
    }
    return service_map.get(port, "Unknown")


async def network_discovery(network: str) -> list[dict]:
    """Discover devices in an IP range using ARP."""
    discovered = []
    try:
        net = IPNetwork(network)
        logger.info(f"Scanning network: {network}")
        
        for ip in net:
            try:
                # Simple ping sweep as fallback if ARP not available
                proc = await asyncio.create_subprocess_exec(
                    'ping', '-c', '1', '-W', '1', str(ip),
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=2.0)
                if proc.returncode == 0:
                    discovered.append({
                        "ip": str(ip),
                        "status": "up",
                        "hostname": None
                    })
                    # Try reverse DNS
                    try:
                        hostname = socket.gethostbyaddr(str(ip))[0]
                        discovered[-1]["hostname"] = hostname
                    except socket.herror:
                        pass
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


async def main():
    parser = argparse.ArgumentParser(
        prog='netrecon',
        description='⚡ Fast async network scanner - port scanning, service detection, network discovery'
    )
    parser.add_argument(
        '--target', '-t',
        help='Target IP address or network (CIDR notation for network scan)'
    )
    parser.add_argument(
        '--ports', '-p',
        default='22,80,443',
        help='Comma-separated list of ports to scan (default: 22,80,443)'
    )
    parser.add_argument(
        '--scan-type',
        choices=['port', 'network', 'nbt', 'smb'],
        default='port',
        help='Type of scan to perform'
    )
    parser.add_argument(
        '--concurrency', '-c',
        type=int,
        default=100,
        help='Maximum concurrent connections (default: 100)'
    )
    parser.add_argument(
        '--output', '-o',
        default='scan_results.json',
        help='Output JSON file (default: scan_results.json)'
    )
    
    args = parser.parse_args()
    
    if not args.target:
        parser.print_help()
        print("\nError: --target is required")
        sys.exit(1)
    
    results = {
        "target": args.target,
        "scan_type": args.scan_type,
        "timestamp": datetime.now().isoformat(),
        "findings": []
    }
    
    if args.scan_type == 'port':
        # Port scanning
        try:
            ports = [int(p.strip()) for p in args.ports.split(',')]
        except ValueError:
            logger.error("Invalid port list. Use: 22,80,443")
            sys.exit(1)
        
        logger.info(f"Scanning ports {ports} on {args.target}")
        open_ports = await scan_ports(args.target, ports, args.concurrency)
        
        for port_info in open_ports:
            service = await detect_service(args.target, port_info["port"])
            results["findings"].append({
                "port": port_info["port"],
                "status": port_info["status"],
                "service": service
            })
            logger.info(f"  Port {port_info['port']}: {port_info['status']} ({service})")
        
        logger.info(f"Scan complete. Found {len(open_ports)} open port(s).")
        
    elif args.scan_type == 'network':
        # Network discovery
        logger.info(f"Discovering devices in {args.target}")
        devices = await network_discovery(args.target)
        
        for device in devices:
            results["findings"].append(device)
            logger.info(f"  {device['ip']} - {device.get('hostname', 'N/A')}")
        
        logger.info(f"Network scan complete. Found {len(devices)} device(s).")
        
    elif args.scan_type == 'nbt':
        # NBT scan
        logger.info(f"Performing NBT scan on {args.target}")
        nbt_results = await nbt_scan(args.target)
        
        for result in nbt_results:
            results["findings"].append(result)
            logger.info(f"  {result.get('line', 'N/A')}")
        
        logger.info(f"NBT scan complete. Found {len(nbt_results)} result(s).")
        
    elif args.scan_type == 'smb':
        # SMB enumeration
        logger.info(f"Performing SMB enumeration on {args.target}")
        smb_results = await smb_enum(args.target)
        
        for result in smb_results:
            results["findings"].append(result)
            logger.info(f"  {result.get('share', 'N/A')}")
        
        logger.info(f"SMB enumeration complete. Found {len(smb_results)} share(s).")
    
    save_results(results, args.output)


if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Scan interrupted by user")
        sys.exit(130)