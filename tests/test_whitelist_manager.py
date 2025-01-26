#!/usr/bin/env python3

import unittest
from unittest.mock import patch, mock_open, MagicMock
import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'Scripts')))

from whitelist_manager import create_whitelist, add_to_blacklist, add_to_whitelist, update_from_unsorted

class TestWhitelistManager(unittest.TestCase):
    
    @patch.dict(os.environ, {'CAPTURE_FILE': 'test.pcap', 'OUTPUT_FOLDER': 'output', 'UNSORTED_FILE': 'unsorted.txt', 'BLACKLIST': 'blacklist.txt', 'WHITELIST': 'whitelist.txt'})
    @patch('os.path.exists', return_value=True)
    @patch('builtins.open', new_callable=mock_open, read_data="")
    def test_create_whitelist(self, mock_open, mock_exists):
        create_whitelist('test.pcap', 'output/whitelist.txt')
        
        # Read PCAP and Whitelist
        mock_open.assert_any_call('test.pcap', 'rb')
        mock_open.assert_any_call('output/whitelist.txt', 'r')

    # Test for Whitelist
    @patch.dict(os.environ, {'OUTPUT_FOLDER': 'output', 'WHITELIST': 'whitelist.txt'})
    @patch('os.path.exists', return_value=True)
    @patch('builtins.open', new_callable=mock_open, read_data="192.168.1.1 : 80 --> 192.168.1.2 : 443\n")
    @patch('os.chmod')
    def test_add_to_whitelist(self, mock_open, mock_exists, mock_chmod):
        result = add_to_whitelist("192.168.1.1 : 80 --> 192.168.1.2 : 443", 'output/whitelist.txt', {"192.168.1.1 : 80 --> 192.168.1.2 : 443"})
        
        # Ensure file has 600 permission
        mock_open.assert_called_with('output/whitelist.txt', 0o600)
        # Ensure entry was added
        self.assertEqual(result, 1)
        
    # Test for Blacklist
    @patch.dict(os.environ, {'OUTPUT_FOLDER': 'output', 'BLACKLIST': 'blacklist.txt'})
    @patch('os.path.exists', return_value=True)
    @patch('builtins.open', new_callable=mock_open, read_data="192.168.1.1 : 80 --> 192.168.1.2 : 443\n")
    @patch('os.chmod')
    def test_add_to_whitelist(self, mock_open, mock_exists, mock_chmod):
        result = add_to_whitelist("192.168.1.1 : 80 --> 192.168.1.2 : 443", 'output/blacklist.txt', {"192.168.1.1 : 80 --> 192.168.1.2 : 443"})
        
        # Ensure file has 600 permission
        mock_open.assert_called_with('output/blacklist.txt', 0o600)
        # Ensure entry was added
        self.assertEqual(result, 1)
        
    # Test for unsorted   
    @patch.dict(os.environ, {'OUTPUT_FOLDER': 'output', 'UNSORTED_FILE': 'unsorted.txt', 'BLACKLIST': 'blacklist.txt', 'WHITELIST': 'whitelist.txt'})
    @patch('os.path.exists', return_value=True)
    @patch('builtins.open', new_callable=mock_open, read_data="192.168.1.1 : 80 --> 192.168.1.2 : 443\n")
    @patch('syslog.syslog')  # Mock syslog logging
    def test_update_from_unsorted(self, mock_syslog, mock_open, mock_exists):
        with patch('builtins.input', return_value='w'):
            update_from_unsorted('unsorted.txt')
            
        mock_open.assert_called_with('unsorted.txt', 'w')
        
if __name__ == '__main__':
    unittest.main()