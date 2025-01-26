#!/usr/bin/env python3

import sys
import unittest
from unittest.mock import patch, mock_open, MagicMock
from scapy.all import IP, TCP, UDP

from Scripts.trigger import load_whitelist, is_packet_allowed, log_anomaly # type: ignore

class TestPacketAnalyzer(unittest.TestCase):
    
    @patch("builtins.open", new_callable=mock_open, read_data="192.168.1.1 : 80 --> 192.168.1.2 : 443\n")
    @patch("os.getenv", side_effect=lambda key: "test_folder" if key == "OUTPUT_FOLDER" else "whitelist.txt")
    def test_load_whitelist(self, mock_getenv, mock_file):
        whitelist = load_whitelist()
        self.assertIn(("192.168.1.1", 80, "192.168.1.2", 443), whitelist)
    
    def test_is_packet_allowed_whitelisted(self):
        whitelist = {("192.168.1.1", 80, "192.168.1.2", 443)}
        packet = IP(src="192.168.1.1", dst="192.168.1.2") / TCP(sport=80, dport=443)
        self.assertTrue(is_packet_allowed(packet, whitelist))
    
    def test_is_packet_allowed_non_whitelisted(self):
        whitelist = {("192.168.1.1", 80, "192.168.1.2", 443)}
        packet = IP(src="192.168.2.1", dst="192.168.2.2") / UDP(sport=53, dport=8080)
        self.assertFalse(is_packet_allowed(packet, whitelist))
    
    @patch("syslog.syslog")
    @patch("time.time", return_value=1000)
    def test_log_anomaly_new(self, mock_time, mock_syslog):
        global ANOMALY_LOG
        ANOMALY_LOG = {}
        anomaly = "Test anomaly"
        self.assertTrue(log_anomaly(anomaly, "NEW"))
        self.assertIn(anomaly, ANOMALY_LOG)
        
    @patch("syslog.syslog")
    @patch("time.time", side_effect=[1000, 1500])
    def test_log_anomaly_within_timeout(self, mock_time, mock_syslog):
        global ANOMALY_LOG
        ANOMALY_LOG = {"Test anomaly": 1000}
        anomaly = "Test anomaly"
        self.assertFalse(log_anomaly(anomaly, "NEW"))
        
if __name__ == "__main__":
    unittest.main()
