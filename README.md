# Hacking Multitool

A powerful and versatile hacking multitool that combines various penetration testing features, including port scanning, OS detection, geo-IP lookups, brute force attacks, and more.

## Features

- **Port Scanner**: Scan for open ports and grab banners.
- **OS Detection**: Detect the operating system of a target using Nmap.
- **GeoIP Lookup**: Retrieve geographical location of an IP address.
- **SQL Injection Check**: Use SQLmap to check for SQL injection vulnerabilities.
- **Password Strength Checker**: Assess the strength of a password.
- **DNS Enumeration**: Enumerate DNS records for a domain.
- **Enum4Linux**: Run Enum4Linux to gather information from Windows systems.
- **Reverse Shell Generation**: Generate reverse shell commands for various platforms.
- **Stealth Mode**: Activate stealth mode to minimize logging.
- **Brute Forcing**: Perform brute force login attempts on SSH, HTTP, and FTP.
- **File Encryption/Decryption**: Secure files using AES encryption.
- **URL Scanner**: Analyze URLs and fetch HTTP headers.
- **Scapy Integration**: Advanced packet manipulation and analysis.
- **Searchsploit Lookup**: Quickly search for exploits using Searchsploit.
- **Auto Reporting**: Generate reports based on scan results.
- **FTP and SCP Support**: Include functionalities for FTP and SCP operations.
- **API Integrations**: Enhance tool capabilities with external APIs.
- **Hash Cracking**: Crack hashes using various algorithms.

## Requirements

- Python 3.x
- Required libraries


## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/SaadSaid158/Python-Multi-Tool
   cd Python-Multi-Tool
   ```

2. Install the required libraries:
   ```bash
   pip install [library name, for eaxmple, Scapy]
   ```

## Usage

Run the tool with various options:

```bash
python multitool.py --scan <IP> <PORT_RANGE>
python multitool.py --os <IP>
python multitool.py --geoip <IP>
python multitool.py --sql <URL>
python multitool.py --passwd <PASSWORD>
python multitool.py --dns <DOMAIN>
python multitool.py --enum4linux <IP>
python multitool.py --reverse-shell <IP> <PORT>
python multitool.py --stealth
python multitool.py --brute <TARGET> <USERNAME> <PASSWORD_FILE>
python multitool.py --encrypt <FILENAME>
python multitool.py --decrypt <FILENAME>
python multitool.py --url <URL>
python multitool.py --searchsploit <SEARCH>
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Disclaimer

This tool is intended for educational purposes only. Please use it responsibly and ensure you have permission to test any systems you target. The author of this program will not be held responsible for misuse of this program. 

**"With great power comes great responsibilty."**

**- Stan Lee**
