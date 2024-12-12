#!/bin/python3
import argparse
import os
import socket
import ssl
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse
import dns.resolver
import pyfiglet
import requests
from termcolor import colored

from . import checklist as oc
from . import logincrawler as lc


# Colored logo
def print_colored_logo():
    ascii_logo = pyfiglet.figlet_format("\nCHECKER")
    print("\033[1;36m" + ascii_logo + "\033[0m")


def remove_https(url):
    # Remove 'https://' or 'http://' from the beginning of the URL
    if url.startswith('https://'):
        url = url[8:]  # Remove 'https://', which is 8 characters long
    elif url.startswith('http://'):
        url = url[7:]  # Remove 'http://', which is 7 characters long

    # Remove trailing '/' if it exists
    if url.endswith('/'):
        url = url[:-1]  # Remove the last character (the '/')

    return url


# URL to IP
def get_ip_from_url(url):
    try:
        parsed_url = urlparse(url)
        d = parsed_url.netloc if parsed_url.netloc else parsed_url.path
        ipadd = socket.gethostbyname(d)
        return ipadd
    except socket.gaierror:
        print(f"Could not resolve the URL {url}")
        return None


# Get HTTP Headers using requests
def get_http_headers(t):
    print(f"\n[+] Running HTTP Headers check on {t}")
    try:
        response = requests.head(t)
        for header, value in response.headers.items():
            print(f"\n%%%%%%%%%%%%%%%%%%%%%%%%HTTP RESULTS%%%%%%%%%%%%%%%%%%%%%%%%%%%\n{header}: {value}")
    except requests.exceptions.RequestException as e:
        print(f"\n%%%%%%%%%%%%%%%%%%%%%%%%HTTP RESULTS%%%%%%%%%%%%%%%%%%%%%%%%%%%\nError with HTTP request: {e}")


# Get SSL/TLS certificate info
def get_ssl_info(t):
    print(f"\n[+] Running SSL/TLS certificate check on {t}")
    try:
        conn = ssl.create_default_context().wrap_socket(socket.socket(), server_hostname=t)
        conn.connect((t, 443))
        cert = conn.getpeercert()
        print(f"\n%%%%%%%%%%%%%%%%%%%%%%%%SSL RESULTS%%%%%%%%%%%%%%%%%%%%%%%%%%%\nCertificate details for {t}:")
        for field in cert:
            print(f"{field}: {cert[field]}")
    except Exception as e:
        print(
            f"\n%%%%%%%%%%%%%%%%%%%%%%%%SSL RESULTS%%%%%%%%%%%%%%%%%%%%%%%%%%%\nError with SSL/TLS certificate check: {e}")


# Get DNS information using dns.resolver
def get_dns_info(t):
    print(f"\n[+] Running DNS resolution on {t}")
    try:
        result = dns.resolver.resolve(t, 'A')
        for ip in result:
            print(f"\n%%%%%%%%%%%%%%%%%%%%%%%%DNS RESULTS%%%%%%%%%%%%%%%%%%%%%%%%%%%\nIP Address: {ip}")
    except dns.resolver.NoAnswer as e:
        print(f"No A record found for {t}")
    except Exception as e:
        print(f"Error with DNS resolution: {e}")


# Get IP Geolocation info via IP-API
def get_ip_geolocation(ip):
    print(f"\n[+] Running IP geolocation check on {ip}")
    try:
        url = f"http://ip-api.com/json/{ip}"
        response = requests.get(url)
        data = response.json()
        if data['status'] == 'fail':
            print("Could not retrieve geolocation data.")
        else:
            func_name = "GEO-LOCATION"
            print(
                f"{identifier(func_name)}Location: {data['city']}, {data['regionName']}, {data['country']}")
            print(f"ISP: {data['isp']}")
    except Exception as e:
        print(f"Error with IP geolocation: {e}")


# Run curl for basic HTTP information
def run_curl(t):
    print(f"\n[+] Running curl on {t}")
    try:
        result = subprocess.run(["curl", "-I", t], text=True, capture_output=True)
        func_name = "CURL"
        print(f"{identifier(func_name)}" + result.stdout)
    except Exception as e:
        print(f"Error with curl: {e}")


# Run whois for domain registration details
def run_whois(t):
    print(f"\n[+] Running whois on {t}")
    try:
        result = subprocess.run(["whois", t], text=True, capture_output=True)
        func_name = "WHO-IS"
        print(f"{identifier(func_name)}" + result.stdout)
    except Exception as e:
        print(f"Error with whois: {e}")


# Run nslookup for DNS resolution
def run_nslookup(t):
    print(f"\n[+] Running nslookup on {t}")
    try:
        result = subprocess.run(["nslookup", t], text=True, capture_output=True)
        func_name = "NS-LOOKUP"
        print(f"{identifier(func_name)}" + result.stdout)
    except Exception as e:
        print(f"Error with nslookup: {e}")


# Run basic nmap scan
def run_nmap(t):
    print(f"\n[+] Running nmap scan on {t}")
    try:
        result = subprocess.run(["nmap", "-T4", t], text=True, capture_output=True)
        func_name = "BASIC-NMAP"
        print(f"{identifier(func_name)}" + result.stdout)
    except Exception as e:
        print(f"Error with nmap: {e}")


# Run Nikto for web application vulnerabilities
def run_nikto(t):
    print(f"\n[+] Running Nikto scan on {t}")
    try:
        result = subprocess.run(["nikto", "-h", t], text=True, capture_output=True)
        func_name = "NIKTO"
        print(f"{identifier(func_name)}" + result.stdout)
    except Exception as e:
        print(f"Error with Nikto: {e}")


# Run subdomain enumeration using Subfinder
def run_subfinder(t):
    print(f"\n[+] Running Subfinder for subdomain enumeration on {t}")
    try:
        result = subprocess.run(["subfinder", "-d", t], text=True, capture_output=True)
        func_name = "SUBFINDER"
        text = identifier(func_name)
        print(f"{text}" + result.stdout)
    except Exception as e:
        print(f"Error with SUBFINDER: {e}")


# Run ffuf for directory brute-forcing
def run_ffuf(t, w):
    print(f"\n[+] Running ffuf for directory brute-forcing on {t}")
    try:
        result = subprocess.run(
            ["ffuf", "-u", f"{t}FUZZ", "-w", w, "-mc", "200", "-t", "50"],
            text=True, capture_output=True
        )
        func_name = "FFUF"
        print(f"{identifier(func_name)}" + result.stdout)
    except Exception as e:
        print(f"Error with ffuf: {e}")


# Run advanced nmap scan with NSE scripts
def run_nmap_advanced(t):
    print(f"\n[+] Running advanced nmap scan on {t}")
    try:
        result = subprocess.run(["nmap", "-sSVC", "--script", "vuln", t], text=True, capture_output=True)
        func_name = "NMAP-ADVANCED"
        print(f"{identifier(func_name)}" + result.stdout)
    except Exception as e:
        print(f"Error with advanced nmap scan: {e}")


# Run advanced Nikto scan
def run_nikto_advanced(t):
    print(f"\n[+] Running advanced Nikto scan on {t}")
    try:
        result = subprocess.run(["nikto", "-h", t, "-Tuning", "4"], text=True, capture_output=True)
        func_name = "NIKTO-ADVANCED"
        print(f"{identifier(func_name)}" + result.stdout)
    except Exception as e:
        print(f"Error with advanced Nikto scan: {e}")


def run_ssl_scan(t):
    print(f"\n[+] Running ssl-scan on {t}")
    try:
        result = subprocess.run(["sslscan", t], text=True, capture_output=True)
        func_name = "SSL-SCAN"
        print(f"{identifier(func_name)}" + result.stdout)
    except Exception as e:
        print(f"Error with SSL-SCAN:{e}")


def identifier(name):
    if name:
        return f"\n%%%%%%%%%%%%%%%%%%%%%%%%-{name} RESULTS-%%%%%%%%%%%%%%%%%%%%%%%%%%%\n"


# Level 1: Basic Info Gathering
def run_level_1(t, ip):
    print("\nRunning Level 1: Basic Information Gathering")
    run_curl(t)
    run_whois(t)
    run_nslookup(t)
    get_http_headers(t)
    get_ssl_info(t)
    get_ip_geolocation(ip)


# Level 2: Intermediate Scanning
def run_level_2(t, ip):
    print("\nRunning Level 2: Intermediate Scanning")
    run_nmap(t)
    run_nikto(t)
    get_dns_info(t)


# Level 3: Comprehensive Scanning (Runs all tools)
def run_level_3(t, ip, d, w):
    print("\nRunning Level 3: Comprehensive Scanning")
    with ThreadPoolExecutor() as executor:
        executor.submit(run_curl, t)
        executor.submit(run_whois, ip)
        executor.submit(run_nslookup, t)
        executor.submit(get_http_headers, t)
        executor.submit(get_ssl_info, ip)
        executor.submit(get_ip_geolocation, ip)
        # executor.submit(run_nikto, t)
        executor.submit(run_subfinder, d)
        executor.submit(run_ffuf, t, w)
        executor.submit(run_nmap_advanced, ip)
        executor.submit(run_nikto_advanced, t)
        executor.submit(run_ssl_scan, t)
        executor.submit(lc.run_crawler, t)


# Main logic
def main():
    # Argument parsing
    parser = argparse.ArgumentParser(description="Run a set of tools for network reconnaissance and scanning.")
    parser.add_argument("-url", type=str, required=True, help="Target URL (including http:// or https://)")
    parser.add_argument("-level", type=int, required=True, choices=[1, 2, 3], help="Scan level (1, 2, or 3)")
    parser.add_argument('-w', '--wordlist', type=str, default="/home/kali/tools/SecLists/Discovery/Web-Content/big.txt",
                        help="Path to the wordlist (default: /home/kali/tools/SecLists/Discovery/Web-Content/big.txt)")
    args = parser.parse_args()

    target = args.url
    level = str(args.level)
    wordlist = args.wordlist  # Specify the wordlist path

    if not os.path.isfile(wordlist):
        print(colored(f"[ERROR] The specified wordlist path does not exist: {wordlist}", 'red'))
        sys.exit(1)
    print_colored_logo()
    print("WELCOME DADDY, Started scanning on: " + target + "\n")
    ip = get_ip_from_url(target)
    domain = remove_https(target)
    print(f"Target: {target}")
    print(f"Level assigned: {level}")
    print(f"Domain: {domain}")
    print(f"Found IP: {ip}")
    print(f"Using wordlist: {wordlist}")
    if not target.startswith("http://") and not target.startswith("https://"):
        print(colored("[ERROR] The URL must start with 'http://' or 'https://'.", 'red'))
    else:
        oc.run_owasp_tests(target)
        if level == "1":
            run_level_1(target, ip)
        elif level == "2":
            run_level_2(target, ip)
        elif level == "3":
            run_level_3(target, ip, domain, wordlist)
        else:
            print("Invalid level. Please choose level 1, 2, or 3.")
            sys.exit(1)


if __name__ == "__main__":
    main()
