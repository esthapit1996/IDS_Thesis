from scapy.all import *
import re
import os
import time

ANOMALY_TYPE = ""
ANOMALY_DETECTED = False
ANOMALY_LOG = {}

NOTIFICATION_TIMEOUT = 600 #in seconds

WHITELIST_FOLDER = "filtered_files"
WHITELIST_FILE = os.path.join(WHITELIST_FOLDER, "whitelist.txt")

def load_whitelist():
    whitelist = set()
    try:
        with open(WHITELIST_FILE, "r") as file:
            for line in file:
                line = line.strip()
                # Parse lines of the format "src_ip : port --> dst_ip : port"
                match = re.match(r"(\S+)\s*:\s*(\d+)\s*-->\s*(\S+)\s*:\s*(\d+)", line)
                if match:
                    src, src_port, dst, dst_port = match.groups()
                    # Treat ports above 1024 as 1024
                    src_port = int(src_port)
                    dst_port = int(dst_port)
                    if src_port > 1024:
                        src_port = 1024
                    if dst_port > 1024:
                        dst_port = 1024
                    # Add the tuple of IPs and ports to the whitelist
                    whitelist.add((src, src_port, dst, dst_port))

    except FileNotFoundError:
        print(f"Error: Whitelist file not found at {WHITELIST_FILE}.")
        exit(1)

    except Exception as e:
        print(f"Error while reading whitelist file: {e}")
        exit(1)

    return whitelist

def is_packet_allowed(packet, whitelist):
    global ANOMALY_TYPE, ANOMALY_DETECTED

    if 'IP' in packet:
        src_ip = packet['IP'].src
        dst_ip = packet['IP'].dst
        
        if 'TCP' in packet or 'UDP' in packet:
            if 'TCP' in packet:
                src_port = packet['TCP'].sport
                dst_port = packet['TCP'].dport
            else:
                src_port = packet['UDP'].sport
                dst_port = packet['UDP'].dport
                
            real_dst_port = dst_port
            real_src_port = src_port
            
            # Treat ports above 1024 as 1024
            if dst_port > 1024:
                dst_port = 1024

            if src_port > 1024:
                src_port = 1024

            src_network = '.'.join(src_ip.split('.')[:3])  # First 3 octets of source IP
            dst_network = '.'.join(dst_ip.split('.')[:3])  # First 3 octets of destination IP

            for (whitelist_src, whitelist_src_port, whitelist_dst, whitelist_dst_port) in whitelist:
                whitelist_src_network = '.'.join(whitelist_src.split('.')[:3])  # First 3 octets of whitelist source IP
                whitelist_dst_network = '.'.join(whitelist_dst.split('.')[:3])  # First 3 octets of whitelist destination IP

                if (src_network == whitelist_src_network and dst_network == whitelist_dst_network and \
                    src_port == whitelist_src_port and dst_port == whitelist_dst_port) or \
                   (src_network == whitelist_dst_network and dst_network == whitelist_src_network and \
                    src_port == whitelist_dst_port and dst_port == whitelist_src_port):
                    return True

            # If no conditions matched, it is an anomaly
            ANOMALY_TYPE = f"Unknown IP/Port pair: {src_ip}:{real_src_port} --> {dst_ip}:{real_dst_port}"
            ANOMALY_DETECTED = True
            return False
            
    return True

def log_anomaly(anomaly):
    current_time = time.time()
    if anomaly in ANOMALY_LOG:
        last_notified = ANOMALY_LOG[anomaly]
        if current_time - last_notified < NOTIFICATION_TIMEOUT:
            return false  #donot notidy if within timeout
        ANOMALY_LOG[anomaly] = current_time
        print("DEBUG[log_anomaly]: ANOMALY_LOG[anomaly]")
        return True

def process_packet(packet):
    global ANOMALY_TYPE, ANOMALY_DETECTED

    if not is_packet_allowed(packet, WHITELIST):
        if log_anomaly(ANOMALY_TYPE):
            print("IP-Anomaly found")
            print(f"Anomaly Details: {ANOMALY_TYPE}")
        
    ANOMALY_TYPE = ""
    ANOMALY_DETECTED = False

def main():
    global WHITELIST

    WHITELIST = load_whitelist()
    print(f"Whitelist loaded from {WHITELIST_FILE}.")

    interface = "enx207bd2471872"  # Ethernet
    # interface = "wlp0s20f3"  # Wireless interface

    print(f"Monitoring packets through interface {interface}...")

    try:
        sniff(iface=interface, filter="ip", prn=process_packet, store=0)

    except KeyboardInterrupt:
        print("Packet monitoring stopped by user.")

if __name__ == "__main__":
    main()
