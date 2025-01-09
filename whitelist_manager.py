#!/usr/bin/env python3

import os
import time
import argparse
import subprocess
from scapy.all import rdpcap
from dotenv import load_dotenv

load_dotenv()

PCAP_FILE = os.getenv('CAPTURE_FILE')
OUTPUT_FOLDER = os.getenv('OUTPUT_FOLDER')
UNSORTED_FILE = os.path.join(OUTPUT_FOLDER, os.getenv('UNSORTED_FILE'))
BLACKLIST = os.getenv('BLACKLIST')
WHITELIST = os.getenv('WHITELIST')

def create_whitelist(pcap_file, output_file):
    try:
        existing_entries_whitelist = set()
        if os.path.exists(output_file):
            with open(output_file, 'r') as whitelist:
                existing_entries_whitelist = set(line.strip() for line in whitelist)
        
        # Parse PCAP file
        packets = rdpcap(pcap_file)
        new_entries = set()
        whitelist_file
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
                
        unique_new_entries = new_entries - existing_entries_whitelist
                
        os.makedirs(os.path.dirname(whitelist_file), exist_ok=True)
        
        if unique_new_entries:
            with open(output_file, 'a') as whitelist:
                whitelist.write("\n".join(unique_new_entries) + "\n")
            print(f"Added {len(unique_new_entries)} new entries to the whitelist.")
        else:
            print("No new entries to add to the whitelist.")
          
        os.chmod(output_file, 0o600)
        print(f"Permissions for {output_file} changed to 600")
        
    except FileNotFoundError as e:
        print(f"Error: {e}")
    except Exception as e:
        print(f"An unexpected error occured while processing the PCAP file: {e}")
        

def update_from_unsorted(unsorted_file):
    global WHITELIST, BLACKLIST, OUTPUT_FOLDER
    
    whitelist_file = os.path.join(OUTPUT_FOLDER, WHITELIST)
    blacklist_file = os.path.join(OUTPUT_FOLDER, BLACKLIST)
    
    try:
        if not os.path.exists(unsorted_file):
            print(f"Unsorted file {unsorted_file} not found.")
            return

        with open(unsorted_file, 'r') as unsorted:
            lines_us = unsorted.readlines()
            
        lines_count = len(lines_us)
        print(f"Total lines in unsorted file: {lines_count}")
        
        existing_entries_whitelist = set()
        existing_entries_blacklist = set()
        remaining_lines = []
        new_entries_added_whitelist = 0
        new_entries_added_blacklist = 0
        
        if os.path.exists(whitelist_file):
            with open(whitelist_file, 'r') as whitelist:
                existing_entries_whitelist = set(line.strip() for line in whitelist)
                # print("#########EXISTING_WHITELIST#######")
                # print(existing_entries_whitelist)
                # print("###################################################")
                
        if os.path.exists(blacklist_file):
            with open(blacklist_file, 'r') as blacklist:
                existing_entries_blacklist = set(line.strip() for line in blacklist)
                # print("#########EXISTING_BLACKLIST#######")
                # print(existing_entries_blacklist)
                # print("###################################################")
                
        for line in lines_us:
            line = line.strip()
            # check for enpty or existing line
            if (not line or line in existing_entries_whitelist) or (not line or line in existing_entries_blacklist):
                continue
            
            print(f"Entry: {line}")
            choice = input("Add to Whitelist/Blacklist? ('w' to whitelist, 'b' to blacklist,  's' to skip): ".strip().lower())
            parts = line.split(' --> ')
            
            if choice == 'w':
                if len(parts) != 2:
                    print(f"Invalid line format: {line}")
                    continue
                
                forward_entry = line
                reverse_entry = f"{parts[1]} --> {parts[0]}"
                                                 
                with open(whitelist_file, 'a') as whitelist:
                    if forward_entry not in existing_entries_whitelist:
                        whitelist.write(forward_entry + "\n")
                        existing_entries_whitelist.add(forward_entry)
                        new_entries_added_whitelist += 1
                    if reverse_entry not in existing_entries_whitelist:
                        whitelist.write(reverse_entry + "\n")
                        existing_entries_whitelist.add(reverse_entry)
                        new_entries_added_whitelist += 1
                        
                print(f"\nAdded bidirectional entries to WHITELIST for: {line}\n")
                os.chmod(whitelist_file, 0o600)
                
            elif choice == 'b':
                if len(parts) != 2:
                    print(f"Invalid line format: {line}")
                    continue
                
                forward_entry = line
                reverse_entry = f"{parts[1]} --> {parts[0]}"
                                                 
                with open(blacklist_file, 'a') as blacklist:
                    if forward_entry not in existing_entries_blacklist:
                        blacklist.write(forward_entry + "\n")
                        existing_entries_blacklist.add(forward_entry)
                        new_entries_added_blacklist += 1

                    if reverse_entry not in existing_entries_whitelist:
                        blacklist.write(reverse_entry + "\n")
                        existing_entries_blacklist.add(reverse_entry)
                        new_entries_added_blacklist += 1
                        
                print(f"\nAdded bidirectional entries to BLACKLIST for: {line}\n")
                os.chmod(blacklist_file, 0o640)
            
            elif choice == 's':
                print(f"\nSkipped: {line}\n")
                remaining_lines.append(line)
            
            else:
                print("\nInvalid Input. Skipping by default.\n")
                remaining_lines.append(line)
                
        with open(unsorted_file, 'w') as unsorted:
            unsorted.write("\n".join(remaining_lines) + "\n")
            
        remaining_count = len(remaining_lines)
        print(f"\nUnsorted file updated with remaining entries. Remaining number of lines to be sorted: {remaining_count}")
        
        if new_entries_added_blacklist > 0 and new_entries_added_whitelist > 0:
            print(f"New {new_entries_added_whitelist} line(s) in WHITELIST and new {new_entries_added_blacklist} line(s)BLACKLIST detected. Please restart your Trigger.")
  
        elif new_entries_added_whitelist > 0:
            print(f"New {new_entries_added_whitelist} line(s) in WHITELIST detected. Please restart your Trigger.")
            
        elif new_entries_added_blacklist > 0:
            print(f"New {new_entries_added_blacklist} line(s) in BLACKLIST detected. Please restart your Trigger.")
        
        else:
            print("No new lines added to the whitelist.")
                
    except Exception as e:
        print(f"An unexpected error occured: {e}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Manage the whitelist from PCAP or unsorted files.")
    parser.add_argument("mode", type=int, choices=[1, 2], help="1 -> To create/Update Whitelist from PCAP, 2 -> To Sorting the Unsorted-list.")
    args = parser.parse_args()

    if args.mode == 1:
        start_time = time.time()
    
        whitelist_file = os.path.join(OUTPUT_FOLDER, os.getenv('WHITELIST'))
        create_whitelist(PCAP_FILE, whitelist_file)
    
        d = time.time() - time.time()
        print (f"d is {d * 1000:.8f} ms.")
        total_time = time.time() - start_time - d

        print(f"Program completed in {total_time:.2f} seconds.")

    elif args.mode == 2:
        update_from_unsorted(UNSORTED_FILE)

    
