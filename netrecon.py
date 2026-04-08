import asyncio
import aiohttp
import socket
import ssl
import dns.asyncresolver

async def scan_port(ip, port):
    try:
        reader, writer = await asyncio.open_connection(ip, port)
        writer.close()
        return True
    except:
        return False

async def async_port_scan(ip, ports):
    tasks = []
    for port in ports:
        tasks.append(scan_port(ip, port))
    return await asyncio.gather(*tasks)

async def dns_enumeration(domain):
    try:
        answers = await dns.asyncresolver.Resolver().resolve(domain, 'A')
        return [str(answer) for answer in answers]
    except Exception as e:
        print(f"DNS enumeration error: {e}")
        return []

async def grab_ssl_cert(ip, port=443):
    context = ssl.create_default_context()
    with socket.create_connection((ip, port)) as sock:
        with context.wrap_socket(sock, server_hostname=ip) as ssock:
            return ssock.getpeercert()

async def http_analysis(url):
    async with aiohttp.ClientSession() as session:
        try:
            async with session.get(url) as response:
                return await response.text()
        except Exception as e:
            print(f"HTTP analysis error: {e}")
            return None

async def main():
    # Example usage
    ip = '192.168.1.1'
    ports = [22, 80, 443]
    print(await async_port_scan(ip, ports))
    print(await dns_enumeration('example.com'))
    print(await grab_ssl_cert(ip))
    print(await http_analysis('http://example.com'))

if __name__ == '__main__':
    asyncio.run(main())