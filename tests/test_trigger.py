#!/usr/bin/env python3

import unittest
from unittest.mock import patch, mock_open
from scapy.all import IP, TCP, UDP
import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'Scripts')))

print(sys.path)

from trigger import load_whitelist, is_packet_allowed, log_anomaly  # Now it can find trigger.py

class TestPacketAnalyzer(unittest.TestCase):
    
    @patch("builtins.open", new_callable=mock_open, read_data="192.168.1.1 : 80 --> 192.168.1.2 : 443\n")
    @patch("os.getenv", side_effect=lambda key: "test_folder" if key == "OUTPUT_FOLDER" else "whitelist.txt")
    def test_load_whitelist(self, mock_getenv, mock_file):
        whitelist = load_whitelist()
        self.assertIn(("192.168.1.1", 80, "192.168.1.2", 443), whitelist)
    
    def test_is_packet_allowed_whitelisted(self):
        whitelist = {("192.168.1.1", 80, "192.168.1.2", 443)}
        packet = IP(src="192.168.1.1", dst="192.168.1.3") / TCP(sport=80, dport=443)
        self.assertTrue(is_packet_allowed(packet, whitelist))
    
    @patch("builtins.open", new_callable=mock_open)
    def test_is_packet_allowed_non_whitelisted(self, mock_file):
        whitelist = {("192.168.1.1", 80, "192.168.1.2", 443)}
        packet = IP(src="192.168.2.1", dst="192.168.2.2") / UDP(sport=53, dport=8080)
        self.assertFalse(is_packet_allowed(packet, whitelist))
        mock_file.assert_called_with("../filtered_files/unsorted.txt", "a")
    
    @patch("syslog.syslog")
    @patch("time.time", return_value=1000)
    @patch("trigger.ANOMALY_LOG") 
    def test_log_anomaly_new(self, mock_anomaly_log, mock_time, mock_syslog):
        anomaly = "Test anomaly"
        self.assertTrue(log_anomaly(anomaly, "NEW"))
        
if __name__ == "__main__":
    unittest.main()
