import os
from scapy.all import rdpcap

PCAP_FILE = "captured_packets.pcap"
OUTPUT_FOLDER = "filtered_files"

def create_whitelist(pcap_file, output_folder):
    try:
        packets = rdpcap(pcap_file)
        
        whitelist_entries = set()
        
        for pkt in packets:
            if 'IP' in pkt:
                dest_ip = pkt['IP'].dst
                source_ip = pkt['IP'].src
                # protocol = pkt['IP'].proto
                
                if 'TCP' in pkt or 'UDP' in pkt:
                    destination_port = pkt.dport
                    source_port = pkt.sport
                else:
                    print("Packet ist weder TCP noch UDP")
                    continue
                    
                entry = f"{dest_ip} : {destination_port} --> {source_ip} : {source_port}"
                reverse_entry = f"{source_ip} : {source_port} --> {dest_ip} : {destination_port}"
                
                whitelist_entries.add(entry)
                whitelist_entries.add(reverse_entry)
                
        os.makedirs(os.path.dirname(whitelist_file), exist_ok=True)
        
        with open(whitelist_file, 'a') as whitelist:
            whitelist.write("\n".join(whitelist_entries) + "\n")
        
    except FileNotFoundError as e:
        print(f"Error: {e}")
    except Exception as e:
        print(f"An unexpected error occured while processing the PCAP file: {e}")
        
if __name__ == "__main__":
    whitelist_file = os.path.join(OUTPUT_FOLDER, 'whitelist.txt')
    
    create_whitelist(PCAP_FILE, whitelist_file)

        