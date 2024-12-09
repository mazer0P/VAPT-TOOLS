#!/bin/python3

import sys
import subprocess
import socket
import urllib
from datetime import datetime as dt
from termcolor import colored
import re
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor
import pyfiglet
# Colored logo

def print_colored_logo():
    ascii_logo = pyfiglet.figlet_format("\nCHECKER")
    print("\033[1;36m" + ascii_logo + "\033[0m")

    # logo = """
    #   CCCC   H   H   EEEEE   CCCC   K   K   EEEEE   RRRR
    #  C       H   H   E       C       K  K    E       R   R
    #  C       HHHHH   EEEE    C       KKK     EEEE    RRRR
    #  C       H   H   E       C       K  K    E       R  R
    #   CCCC   H   H   EEEEE   CCCC   K   K   EEEEE   R   R
    # """
    # for line in logo.splitlines():
    #     print(colored(line, 'yellow'))  # Print logo in yellow


#URL to IP;
def get_ip_from_url(url):
    try:
        # Parse the URL to get the domain name
        parsed_url = urlparse(url)
        d = parsed_url.netloc if parsed_url.netloc else parsed_url.path

        # Resolve the domain to an IP address
        ipadd = socket.gethostbyname(d)
        return ipadd
    except socket.gaierror:
        print(f"Could not resolve the URL {target}")
        return None


# Level 1: Basic Info Gathering
def lvl1(t, ipa):
    print("\nRunning Level 1: Basic Information Gathering")
    # Basic checks
    run_curl(t)
    run_whois(t)
    run_nslookup(ipa)


# Level 2: Intermediate Scanning
def lvl2(t, ipa):
    print("\nRunning Level 2: Intermediate Scanning")
    run_nmap(ipa)  # Scan open ports and services
    run_nikto(t)  # Web application vulnerabilities


# Level 3: Advanced Scanning
def lvl3(t, ipa):
    print("\nRunning Level 3: Advanced Scanning")
    # run_nmap_advanced(ipa)  # Run nmap with scripts
    # run_ffuf(t)  # Directory brute-forcing using "ffuf"
    # run_sublist3r(t)  # Subdomain enumeration
    # run_nikto_advanced(t)  # Run Nikto with advanced options
    with ThreadPoolExecutor() as executor:
        executor.submit(run_nmap_advanced, ipa)
        executor.submit(run_ffuf, t)
        executor.submit(run_sublist3r, t)
        executor.submit(run_nikto_advanced, t)

def remove_https(url):
    if url.startswith('https://'):
        return url[8:]  # Remove 'https://', which is 8 characters long
    elif url.startswith('http://'):
        return url[7:]  # Remove 'http://', which is 7 characters long
    return url  # Return the URL as is if neither prefix is found


# Run curl for basic HTTP information
def run_curl(t):
    print(f"\n[+] Running curl on {t}")
    try:
        result = subprocess.run(["curl", "-I", t], text=True, capture_output=True)
        print(result.stdout)
    except Exception as e:
        print(f"Error with curl: {e}")


# Run whois for domain registration details
def run_whois(t):
    print(f"\n[+] Running whois on {t}")
    try:
        result = subprocess.run(["whois", t], text=True, capture_output=True)
        print(result.stdout)
    except Exception as e:
        print(f"Error with whois: {e}")


# Run nslookup for DNS resolution
def run_nslookup(t):
    print(f"\n[+] Running nslookup on {t}")
    try:
        result = subprocess.run(["nslookup", t], text=True, capture_output=True)
        print(result.stdout)
    except Exception as e:
        print(f"Error with nslookup: {e}")


# Run basic nmap scan
def run_nmap(t):
    print(f"\n[+] Running nmap scan on {t}")
    try:
        result = subprocess.run(["nmap", " -T4 ", t], text=True, capture_output=True)
        print(result.stdout)
    except Exception as e:
        print(f"Error with nmap: {e}")


# Run Nikto for web application vulnerabilities
def run_nikto(t):
    print(f"\n[+] Running Nikto scan on {t}")
    try:
        result = subprocess.run(["nikto", " -h ", t], text=True, capture_output=True)
        print(result.stdout)
    except Exception as e:
        print(f"Error with Nikto: {e}")


# Advanced nmap scan with NSE scripts
def run_nmap_advanced(t):
    print(f"\n[+] Running advanced nmap scan on {t}")
    try:
        result = subprocess.run(["nmap", "-p", "1-65535", "--script", "vuln", t], text=True, capture_output=True)
        print(result.stdout)
    except Exception as e:
        print(f"Error with advanced nmap scan: {e}")


# Run directory brute-forcing using ffuf
# Run directory brute-forcing using ffuf
def run_ffuf(t):
    print(f"\n[+] Running ffuf for directory brute-forcing on {t}")

    # Check if the target URL ends with a slash, as it's required for directory brute-forcing

    # Run ffuf with the correct options
    try:
        # Fixed: Added commas between options and added the `-mc` argument properly
        print("ran ffuf")
        result = subprocess.run(
            ["ffuf", "-u", f"{t}FUZZ", "-w", wordlist, "-mc", "200"],
            text=True, capture_output=True
        )

        # Check if ffuf produced any results or if there was an error
        if result.returncode == 0:
            print("[+] ffuf scan completed successfully.")
            print(result.stdout)
            # print("running subdomain enumeration with FFUF")
            # try:
            #     # Example usage:
            #     url = t
            #     http = remove_https(url)
            #     result = subprocess.run(["ffuf", "-u", f"{t}", "-w", wordlist, "-H", f"Host: FUZZ.{http}"],
            #                             text=True, capture_output=True
            #                             )
            #     print(result.stdout)
            # except Exception as e:
            #     print(f"Error with ffuf: {e}")

        else:
            print(f"[-] ffuf failed: {result.stderr}")

    except Exception as e:
        print(f"Error with ffuf: {e}")


# Run subdomain enumeration using Sublist3r
def run_sublist3r(t):
    print(f"\n[+] Running Sublist3r for subdomain enumeration on {t}")
    try:
        result = subprocess.run(["sublist3r", "-d", t], text=True, capture_output=True)
        print(result.stdout)
    except Exception as e:
        print(f"Error with Sublist3r: {e}")


# Run Nikto with advanced options
def run_nikto_advanced(t):
    print(f"\n[+] Running advanced Nikto scan on {t}")
    try:
        result = subprocess.run(["nikto", "-h", t, "-Tuning", "4", "-Plugins", "all"], text=True,
                                capture_output=True)
        print(result.stdout)
    except Exception as e:
        print(f"Error with advanced Nikto scan: {e}")


# Main logic
if __name__ == "__main__":
    if len(sys.argv) == 3:
        target = sys.argv[1]
        level = sys.argv[2]
        if not target.endswith('/'):
            target += '/'

            # Specify the wordlist path
        wordlist = "/home/kali/tools/SecLists/Discovery/Web-Content/big.txt"  # Update to your wordlist path
        if not wordlist:
            print("[-] Wordlist is missing or invalid. Please provide a valid wordlist.")
            sys.exit(1)
        print_colored_logo()
        print("WELCOME DADDY, Started scanning on: " + target+"\n")
        ip = get_ip_from_url(target)
        domain = remove_https(target)
        print(f"Target: {target}")
        print(f"Level assigned: {level}")
        print(f"Domain: {domain}")
        print(f"Found IP: {ip}")

        if level == "1":
            lvl1(target, ip)
        elif level == "2":
            lvl2(target, ip)
        elif level == "3":
            lvl3(target, ip)
        else:
            print("Invalid level. Please choose level 1, 2, or 3.")
            sys.exit(1)
    else:
        print("Host is down. Aborting the scan.")
        sys.exit(1)
else:
    print("Usage: python3 script.py <url> <level>")
    sys.exit(1)
