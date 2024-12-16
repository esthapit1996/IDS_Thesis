from scapy.all import *

# Read packet from a PCAP file
packets = PcapReader('captured_packets.pcap')

# Iterate through packets and print summary
for packet in packets:
    # if packet.haslayer(DNS):
        print(packet.show())