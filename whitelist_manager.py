import os
import time
from scapy.all import rdpcap
from dotenv import load_dotenv
import stat

load_dotenv()

PCAP_FILE = os.getenv('CAPTURE_FILE')
OUTPUT_FOLDER = os.getenv('OUTPUT_FOLDER')

def create_whitelist(pcap_file, output_file):
    try:
        existing_entries = set()
        if os.path.exists(output_file):
            with open(output_file, 'r') as whitelist:
                existing_entries = set(line.strip() for line in whitelist)
        
        # Parse PCAP file
        packets = rdpcap(pcap_file)
        new_entries = set()
        
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
                
                new_entries.add(entry)
                new_entries.add(reverse_entry)
                
        unique_new_entries = new_entries - existing_entries
                
        os.makedirs(os.path.dirname(whitelist_file), exist_ok=True)
        
        if unique_new_entries:
            with open(output_file, 'a') as whitelist:
                whitelist.write("\n".join(unique_new_entries) + "\n")
            print(f"Added {len(unique_new_entries)} new entries to the whitelist.")
        else:
            print("No new entries to add to the whitelist.")

        # Change file permissions to 600            
        os.chmod(output_file, stat.S_IRUSR | stat.S_IWUSR)
        print(f"Permissions for {output_file} changed to 600")
        
    except FileNotFoundError as e:
        print(f"Error: {e}")
    except Exception as e:
        print(f"An unexpected error occured while processing the PCAP file: {e}")

if __name__ == "__main__":
    start_time = time.time()
    
    whitelist_file = os.path.join(OUTPUT_FOLDER, os.getenv('WHITELIST'))
    create_whitelist(PCAP_FILE, whitelist_file)
    
    total_time = time.time() - start_time
    print(f"Program completed in {total_time:.2f} seconds.")

        