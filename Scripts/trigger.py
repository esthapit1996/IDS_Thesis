#!/usr/bin/env python3

from scapy.all import *
import re
import os
import time
import syslog
from alert_system import send_alert
from dotenv import load_dotenv
from packet_handler import set_promiscuous_mode

load_dotenv()

ANOMALY_TYPE = ""
ANOMALY_DETECTED = False
ANOMALY_LOG = {}
ANOMALY_STATUS = "NEW"

NOTIFICATION_TIMEOUT = 600 #in seconds

OUTPUT_FOLDER = os.getenv('OUTPUT_FOLDER')
WHITELIST_FILE = os.path.join(OUTPUT_FOLDER, os.getenv('WHITELIST'))
UNSORTED_FILE = os.path.join(OUTPUT_FOLDER, os.getenv('UNSORTED_FILE'))

def load_whitelist():
    whitelist = set()
    try:
        with open(WHITELIST_FILE, "r") as file:
            for line in file:
                line = line.strip()
                # Regex: Parse lines of the format "src_ip : port --> dst_ip : port"
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
        print(f"Error: Whitelist file not found at {WHITELIST_FILE}")
        syslog.syslog(syslog.LOG_ERR, f"[Trigger] Error: Whitelist file not found at {WHITELIST_FILE}.")
        exit(1)

    except Exception as e:
        print(f"Error while reading whitelist file: {e}")
        syslog.syslog(syslog.LOG_ERR, f"[Trigger] Error while reading whitelist file: {e}")
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

            # First 3 octets of source and destination IP
            src_network = '.'.join(src_ip.split('.')[:3])
            dst_network = '.'.join(dst_ip.split('.')[:3])

            for (whitelist_src, whitelist_src_port, whitelist_dst, whitelist_dst_port) in whitelist:
                # First 3 octets of whitelist source & destination IP
                whitelist_src_network = '.'.join(whitelist_src.split('.')[:3])  
                whitelist_dst_network = '.'.join(whitelist_dst.split('.')[:3])

                if (src_network == whitelist_src_network and dst_network == whitelist_dst_network and \
                    src_port == whitelist_src_port and dst_port == whitelist_dst_port) or \
                   (src_network == whitelist_dst_network and dst_network == whitelist_src_network and \
                    src_port == whitelist_dst_port and dst_port == whitelist_src_port):
                    return True

            # If no conditions matched, it is an anomaly
            ANOMALY_TYPE = f"Unknown IP/Port pair: {src_ip} : {src_port} --> {dst_ip} : {dst_port}"
            ANOMALY_DETECTED = True
            unsorted_file(src_ip, src_port, dst_ip, dst_port)
            # print(f"DEBUG[unsorted]:::  {src_ip} : {src_port} --> {dst_ip} : {dst_port}")
            return False
            
    return True

def log_anomaly(anomaly, anomaly_status):
    global ANOMALY_LOG, ANOMALY_STATUS
    current_time = time.time()
    
    if anomaly in ANOMALY_LOG:
        last_notified = ANOMALY_LOG[anomaly]
        if current_time - last_notified < NOTIFICATION_TIMEOUT:
            return False  #do not tidy if within timeout
        ANOMALY_STATUS = "OLD"
    else:
        ANOMALY_STATUS = "NEW"
    ANOMALY_LOG[anomaly] = current_time
    
    syslog.syslog(syslog.LOG_WARNING, f"[Trigger] Anomaly detected: {anomaly}, Time: {time.ctime()}, Status: {ANOMALY_STATUS}")
    print(f"Anomaly: {anomaly} logged at {time.ctime()} as {ANOMALY_STATUS}")
    
    # Notify user
    send_alert(anomaly, ANOMALY_STATUS)
    
    return True

def process_packet(packet):
    global ANOMALY_TYPE, ANOMALY_DETECTED, ANOMALY_STATUS

    if not is_packet_allowed(packet, WHITELIST):
        if log_anomaly(ANOMALY_TYPE, ANOMALY_STATUS):
            print("Anomaly found & protocolled. Monitoring continued.")
        
    ANOMALY_TYPE = ""
    ANOMALY_DETECTED = False
    ANOMALY_STATUS = "NEW"
    
def unsorted_file(src_ip, src_port, dst_ip, dst_port):
    pattern = f"{src_ip} : {src_port} --> {dst_ip} : {dst_port}"
    reverse_pattern = f"{dst_ip} : {dst_port} --> {src_ip} : {src_port}" 

    if not os.path.exists(UNSORTED_FILE):
        with open(UNSORTED_FILE, "w") as file:
            print(f"Created {UNSORTED_FILE}.")
            
    with open(UNSORTED_FILE, "r") as file:
        existing_unsorted = file.read()
        
    if pattern in existing_unsorted or reverse_pattern in existing_unsorted:
        return
    
    with open(UNSORTED_FILE, "a") as file:
        file.write(pattern + "\n")

if __name__ == "__main__":
    global WHITELIST
    
    interface = os.getenv('INTERFACE')
    set_promiscuous_mode(interface, enable=True)
    
    syslog.openlog(ident="IDS_Mailer", logoption=syslog.LOG_PID)
    syslog.syslog(syslog.LOG_INFO, "[Trigger] Starting IDS with mail-related logging.")

    WHITELIST = load_whitelist()
    syslog.syslog(syslog.LOG_INFO, f"[Trigger] Whitelist loaded from {WHITELIST_FILE}.")

    l = len(WHITELIST)
    print(f"Length of whitelist after port normalisation: {l}")

    print(f"Monitoring packets through interface {interface}...")
    syslog.syslog(syslog.LOG_INFO, f"[Trigger] Monitoring packets on interface {interface}.")

    try:
        sniff(iface=interface, filter="ip", prn=process_packet, store=0)
        
    except Exception as e:
        syslog.syslog(syslog.LOG_ERR, f"[Trigger] Unexpected error: {e}")
        print(f"Unexpected error: {e}")
        
    finally:
        syslog.closelog()
