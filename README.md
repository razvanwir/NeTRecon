# NetRecon - Async Network Scanner Toolkit

NetRecon is an asynchronous network scanning tool written in Python that allows for port scanning, network discovery, and basic SMB and NBT enumeration operations. It is built using asyncio for parallel task execution, improving performance and efficiency.

## Features
- **Asynchronous Port Scanning**: Scans TCP ports on a target IP to check for open ports.
- **Service Detection**: Provides a placeholder for implementing service detection on open ports.
- **Network Discovery**: Identifies devices in an IP range using ARP.
- **Results Saving**: Saves results to a JSON file for further analysis, along with a log file.

## Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/NetRecon.git
   cd NetRecon
   ```
2. Install the required packages:
   ```bash
   pip install -r requirements.txt
   ```

## Usage
Run the script with the required arguments:
```bash
python netrecon.py --target <target_ip> [--ports <ports>]
```

- `--target`: Target IP address to scan.
- `--ports`: Comma-separated list of ports to scan (default: 22,80,443).

## Extending Functionality

- **NBT Scan**: The `nbt_scan` function is a placeholder. Users can implement their own logic using tools like `nmblookup`.
- **SMB Enumeration**: The `smb_enum` function is a placeholder. Users can extend this using `smbclient` or similar tools.



## Contribution
Contributions are welcome! Please open a pull request or submit an issue on GitHub.

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
