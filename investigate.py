#!/usr/bin/env python3

# This file was generated with ChatGPT

import re
import subprocess

def is_private_ip(ip):
    """Check if an IP is in the 192.168.0.0/16 subnet"""
    return ip.startswith("192.168.")

def extract_ips(line):
    """Extract IP addresses from a line, ignoring 192.168.x.x"""
    ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    ips = ip_pattern.findall(line)
    return [ip for ip in ips if not is_private_ip(ip)]

def whois_lookup(ip):
    """Perform a WHOIS lookup"""
    try:
        result = subprocess.run(["whois", ip], capture_output=True, text=True, timeout=5)
        return result.stdout.strip() if result.stdout else "WHOIS lookup returned no data"
    except subprocess.TimeoutExpired:
        return f"WHOIS lookup for {ip} timed out."
    except Exception as e:
        return f"Error in WHOIS lookup for {ip}: {e}"

def process_file(filename):
    """Read a file, extract public IPs, and perform WHOIS lookups"""
    checked_ips = set()

    with open(filename, "r") as file:
        for line in file:
            public_ips = extract_ips(line)
            for ip in public_ips:
                if ip in checked_ips:
                    continue  # Skip duplicate lookups

                checked_ips.add(ip)
                print("=" * 50)
                print(f"🔍 Investigating IP: {ip}")

                # WHOIS lookup
                whois_info = whois_lookup(ip)
                print("\n🌐 WHOIS Information:")
                print(whois_info)
                print("=" * 50 + "\n")

# Run
process_file("filtered_files/unsorted.txt")
