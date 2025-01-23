#!/usr/bin/env python3

from scapy.all import *
from dotenv import load_dotenv
import os

load_dotenv()

CAPTURE_FILE = os.getenv('CAPTURE_FILE')
CAPTURE_WRITER = None

def set_promiscuous_mode(interface, enable=True):
    
    mode = "on" if enable else "off"
    try:
        subprocess.run(["ip", "link", "set", interface, "promisc", mode], check=True)
        print(f"Promiscuous mode {mode} for {interface}")
    except subprocess.CalledProcessError as e:
        print(f"Failed to set promiscuous mode: {e}")

def initialize_capture_file():
    global CAPTURE_WRITER
    CAPTURE_WRITER = PcapWriter(CAPTURE_FILE, append=True, sync=True)

def process_packet(packet):
    global CAPTURE_WRITER
    if CAPTURE_WRITER:
        CAPTURE_WRITER.write(packet)
    print(f"Captured: {packet.summary()}")

def main():
    global CAPTURE_WRITER
    
    interface = os.getenv('INTERFACE')
    set_promiscuous_mode(interface, enable=True)
    
    ## Initialize capture file
    initialize_capture_file()
    print(f"Sniffing TCP and UDP packets on interface {interface}...")

    try:
        sniff(iface=interface,
              filter="tcp or udp",
              prn=process_packet, 
              store=0)

    except Exception as e:
        print(f"An error occurred: {e}")

    finally:
        ## Close capture file
        if CAPTURE_WRITER:
            CAPTURE_WRITER.close()
            print(f"Capture file saved: {CAPTURE_FILE}")

if __name__ == "__main__":
    main()