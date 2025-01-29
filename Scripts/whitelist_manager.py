#!/usr/bin/env python3

import os
import time
import argparse
import syslog
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
        start_time = time.time()
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
                    print("Packet is neither TCP nor UDP")
                    continue
                    
                entry = f"{dest_ip} : {destination_port} --> {source_ip} : {source_port}"
                reverse_entry = f"{source_ip} : {source_port} --> {dest_ip} : {destination_port}"
                
                new_entries.add(entry)
                new_entries.add(reverse_entry)
                
        unique_new_entries = new_entries - existing_entries_whitelist
                
        os.makedirs(os.path.dirname(output_file), exist_ok=True)
        
        if unique_new_entries:
            with open(output_file, 'a') as whitelist:
                whitelist.write("\n".join(unique_new_entries) + "\n")
            print(f"Added {len(unique_new_entries)} new entries to the whitelist.")
        else:
            print("No new entries to add to the whitelist.")
          
        os.chmod(output_file, 0o600)
        print(f"Permissions for {output_file} changed to 600")
        
        end_time = time.time()
        total_time = end_time - start_time 
        print(f"Program completed in {total_time:.2f} seconds.")
        
        while True:
            delete_choice = input(f"Do you want to delete {pcap_file}? (y/n): ").strip().lower()
            if delete_choice == 'y':
                os.remove(pcap_file)
                print(f"PCAP file {pcap_file} has been deleted.")
                break
            elif delete_choice == 'n':
                print(f"PCAP file {pcap_file} has not been deleted.")
                break
            else:
                print("Invalid input. Please enter 'y' or 'n'.")
                
    except FileNotFoundError as e:
        print(f"Error: {e}")
    except Exception as e:
        print(f"An unexpected error occured while processing the PCAP file: {e}")


def add_to_whitelist(line, whitelist_file, existing_entries_whitelist):
    parts = line.split(' --> ')
    if len(parts) != 2:
        print(f"Invalid line format: {line}")
        return 0

    forward_entry = line
    reverse_entry = f"{parts[1]} --> {parts[0]}"
    new_entries = 0

    with open(whitelist_file, 'a') as whitelist:
        if forward_entry not in existing_entries_whitelist:
            whitelist.write(forward_entry + "\n")
            existing_entries_whitelist.add(forward_entry)
            syslog.syslog(syslog.LOG_INFO, f"[Whitelist] Added entry: {forward_entry}, Time: {time.ctime()}")
            new_entries += 1

        if reverse_entry not in existing_entries_whitelist:
            whitelist.write(reverse_entry + "\n")
            existing_entries_whitelist.add(reverse_entry)
            syslog.syslog(syslog.LOG_INFO, f"[Whitelist] Added entry: {reverse_entry}, Time: {time.ctime()}")
            new_entries += 1

    os.chmod(whitelist_file, 0o600)
    print(f"Permissions for {whitelist_file} changed to 600")
    print(f"\nAdded bidirectional entries to WHITELIST for: {line}\n")
    return new_entries


def add_to_blacklist(line, blacklist_file, existing_entries_blacklist):
    parts = line.split(' --> ')
    if len(parts) != 2:
        print(f"Invalid line format: {line}")
        return 0

    forward_entry = line
    reverse_entry = f"{parts[1]} --> {parts[0]}"
    new_entries = 0

    with open(blacklist_file, 'a') as blacklist:
        if forward_entry not in existing_entries_blacklist:
            blacklist.write(forward_entry + "\n")
            existing_entries_blacklist.add(forward_entry)
            syslog.syslog(syslog.LOG_INFO, f"[Blacklist] Added entry: {forward_entry}, Time: {time.ctime()}")
            new_entries += 1

        if reverse_entry not in existing_entries_blacklist:
            blacklist.write(reverse_entry + "\n")
            existing_entries_blacklist.add(reverse_entry)
            syslog.syslog(syslog.LOG_INFO, f"[Blacklist] Added entry: {reverse_entry}, Time: {time.ctime()}")
            new_entries += 1

    os.chmod(blacklist_file, 0o600)
    print(f"\nAdded bidirectional entries to BLACKLIST for: {line}\n")
    return new_entries


def update_from_unsorted(unsorted_file):

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

        if os.path.exists(blacklist_file):
            with open(blacklist_file, 'r') as blacklist:
                existing_entries_blacklist = set(line.strip() for line in blacklist)
                
        skip_all = False

        for line in lines_us:
            line = line.strip()
            if not line or line in existing_entries_whitelist or line in existing_entries_blacklist:
                continue
            
            if skip_all:
                remaining_lines.append(line)
                continue

            while True:
                print(line)
                choice = input("Add to Whitelist/Blacklist? ('w' to whitelist, 'b' to blacklist,  's' to skip, 'sa' to skip all): ").strip().lower()
                if choice in ['w', 'b', 's', 'sa']:
                    break
                print("\nInvalid Input. Please enter 'w' to whitelist, 'b' to blacklist,  's' to skip, 'sa' to skip all).\n")

            if choice == 'w':
                new_entries_added_whitelist += add_to_whitelist(line, whitelist_file, existing_entries_whitelist)
            elif choice == 'b':
                new_entries_added_blacklist += add_to_blacklist(line, blacklist_file, existing_entries_blacklist)
            elif choice == 's':
                print(f"\nSkipped: {line}\n")
                remaining_lines.append(line)
            elif choice == 'sa':
                print("\n Skipping all remaining entires.")
                skip_all = True
                remaining_lines.append(line)

        with open(unsorted_file, 'w') as unsorted:
            unsorted.write("\n".join(remaining_lines) + "\n")

        remaining_count = len(remaining_lines)
        print(f"\nUnsorted file updated with remaining entries. Remaining number of lines to be sorted: {remaining_count}")

        if new_entries_added_blacklist > 0 and new_entries_added_whitelist > 0:
            print(f"New {new_entries_added_whitelist} line(s) in WHITELIST and new {new_entries_added_blacklist} line(s) in BLACKLIST detected. Please restart your Trigger.")
        elif new_entries_added_whitelist > 0:
            print(f"New {new_entries_added_whitelist} line(s) in WHITELIST detected. Please restart your Trigger.")
        elif new_entries_added_blacklist > 0:
            print(f"New {new_entries_added_blacklist} line(s) in BLACKLIST detected. Please restart your Trigger.")
        else:
            print("No new lines added to the whitelist or blacklist.")

    except Exception as e:
        print(f"An error occurred: {e}")


if __name__ == "__main__":
    
    syslog.openlog(ident="IDS_Mailer", logoption=syslog.LOG_PID)
    
    try:
        parser = argparse.ArgumentParser(description="Manage the whitelist from PCAP or unsorted files.")
        parser.add_argument("mode", type=int, choices=[1, 2], help="1 -> To start Creation Mode || 2 -> To start Sorting Mode.")
        args = parser.parse_args()  

        if args.mode == 1:
            print("Starting Creation Mode")
            whitelist_file = os.path.join(OUTPUT_FOLDER, os.getenv('WHITELIST'))
            create_whitelist(PCAP_FILE, whitelist_file)

        elif args.mode == 2:
            print("Starting Sorting Mode")
            update_from_unsorted(UNSORTED_FILE)
            
    except Exception as e:
        syslog.syslog(syslog.LOG_ERR, f"[Trigger] Unexpected error: {e}")
        print(f"Unexpected error: {e}")
    
    finally:
        syslog.closelog()
    
