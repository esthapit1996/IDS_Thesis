from scapy.all import *
import subprocess

CAPTURE_FILE = "captured_packets.pcap"
CAPTURE_WRITER = None


def initialize_capture_file():
    global CAPTURE_WRITER
    CAPTURE_WRITER = PcapWriter(CAPTURE_FILE, append=True, sync=True)
    print(f"Initialized capture file: {CAPTURE_FILE}")

def process_packet(packet):
    global CAPTURE_WRITER
    if CAPTURE_WRITER:
        CAPTURE_WRITER.write(packet)
    print(f"Captured: {packet.summary()}")

def main():
    global CAPTURE_WRITER

    ## Initialize capture file
    initialize_capture_file()

    ## Interface name
    # interface = "wlp0s20f3"
    interface = "enx207bd2471872"

    print(f"Sniffing TCP and UDP packets on interface {interface}...")

    try:
        sniff(iface=interface, filter="tcp or udp",prn=process_packet, store=0)

    except KeyboardInterrupt:
        print("Packet capture stopped by user.")

    finally:
        ## Close capture file
        if CAPTURE_WRITER:
            CAPTURE_WRITER.close()
            print(f"Capture file saved: {CAPTURE_FILE}")

if __name__ == "__main__":
    main()