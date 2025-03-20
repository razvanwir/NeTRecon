import asyncio
import argparse
import json
from aiohttp import ClientSession
from scapy.all import sr1, srp, IP, TCP, Ether, ARP
import logging
import socket
import uuid
import subprocess
from smbprotocol.connection import Connection
from smbprotocol.session import Session
from smbprotocol.tree import TreeConnect
from smbprotocol.open import Open

# Setup logging
logging.basicConfig(filename='netrecon.log', level=logging.INFO, format='%(asctime)s - %(message)s')

def is_valid_ip(ip):
    parts = ip.split('.')
    return len(parts) == 4 and all(part.isdigit() and 0 <= int(part) <= 255 for part in parts)

async def fetch_url(url, session):
    try:
        async with session.get(url) as response:
            return await response.text()
    except Exception as e:
        print(f"Failed to fetch {url}: {e}")
        return None

async def scan_ports(ip, ports):
    open_ports = []
    for port in ports:
        pkt = IP(dst=ip)/TCP(dport=port, flags='S')
        resp = sr1(pkt, timeout=1, verbose=0)
        if resp is not None and resp.haslayer(TCP) and resp.getlayer(TCP).flags == 0x12:
            open_ports.append(port)
            sr1(IP(dst=ip)/TCP(dport=port, flags='R'), timeout=1, verbose=0)  # Send RST to close the connection
    return open_ports

async def network_discovery(ip_range):
    print(f"Performing network discovery on {ip_range}")
    devices = []
    ans, _ = srp(Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst=ip_range), timeout=2, verbose=0)
    for _, rcv in ans:
        devices.append({'IP': rcv.psrc, 'MAC': rcv.hwsrc})
    return devices

def nbt_scan(ip):
    print(f"Performing NBT scan on {ip}")
    try:
        result = subprocess.run(['nmblookup', '-A', ip], capture_output=True, text=True)
        print(result.stdout)
    except Exception as e:
        print(f"NBT scan failed: {e}")

def smb_enum(ip):
    print(f"Performing SMB enumeration on {ip}")
    try:
        connection = Connection(uuid.uuid4(), ip, 445)
        connection.connect()
        session = Session(connection, "guest", "")
        session.connect()
        tree = TreeConnect(session, f"\\\\{ip}\\IPC$")
        tree.connect()
        root_dir = Open(tree, "")
        root_dir.create()
        for share in root_dir.list_directories():
            print(f"Found share: {share['file_name']}")
        root_dir.close()
        tree.disconnect()
        session.disconnect()
        connection.disconnect()
    except Exception as e:
        print(f"SMB enumeration failed: {e}")

async def detect_service(ip, port):
    try:
        with socket.create_connection((ip, port), timeout=2) as sock:
            sock.sendall(b"\n")
            banner = sock.recv(1024).decode().strip()
            return f"{port}/tcp open - {banner}"
    except Exception:
        return f"{port}/tcp open - Service detection failed"

parser = argparse.ArgumentParser(description='NetRecon - Async Network Scanner Toolkit')
parser.add_argument('--target', type=str, required=True, help='Target IP address to scan')
parser.add_argument('--ports', type=str, default='22,80,443', help='Comma-separated list of ports to scan')

async def main():
    args = parser.parse_args()
    if not is_connected():
        print("No network connection detected.")
        return

    target_ip = args.target
    if not is_valid_ip(target_ip):
        print("Invalid IP address format.")
        return

    try:
        ports_to_scan = list(map(int, args.ports.split(',')))
    except ValueError:
        print("Invalid port format. Use comma-separated integers.")
        return

    async with ClientSession() as session:
        html = await fetch_url('http://example.com', session)
        if html:
            print(html)

        open_ports = await scan_ports(target_ip, ports_to_scan)
        print(f"Open ports on {target_ip}: {open_ports}")
        logging.info(f"Open ports on {target_ip}: {open_ports}")

        services = await asyncio.gather(*(detect_service(target_ip, port) for port in open_ports))
        for service in services:
            print(service)
            logging.info(service)

        ip_range = '.'.join(target_ip.split('.')[:-1]) + '.0/24'
        devices = await network_discovery(ip_range)
        print(f"Discovered devices: {devices}")
        logging.info(f"Discovered devices: {devices}")

        nbt_scan(target_ip)
        smb_enum(target_ip)

    results = {
        'target_ip': target_ip,
        'open_ports': open_ports,
        'services': services,
        'discovered_devices': devices
    }
    with open('scan_results.json', 'w') as f:
        json.dump(results, f, indent=4)
    print("Results saved to scan_results.json")
    logging.info("Results saved to scan_results.json")

def is_connected():
    try:
        # Connect to a public DNS server to check for internet connectivity
        socket.create_connection(("8.8.8.8", 53), timeout=2)
        return True
    except OSError:
        return False

if __name__ == '__main__':
    asyncio.run(main())
