#!/usr/bin/env python3

import unittest
from unittest.mock import patch, mock_open
import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'Scripts')))

from whitelist_manager import create_whitelist, add_to_blacklist, add_to_whitelist, update_from_unsorted

class TestWhitelistManager(unittest.TestCase):
    # assert mock has been called with args
    @patch.dict(os.environ, {'CAPTURE_FILE': 'test.pcap', 'OUTPUT_FOLDER': 'output', 'WHITELIST': 'whitelist.txt'})
    @patch('os.path.exists', return_value=True)
    @patch('builtins.open', new_callable=mock_open, read_data="")
    def test_create_whitelist(self, mock_open, mock_exists):
        create_whitelist('test.pcap', 'output/whitelist.txt')
        mock_open.assert_any_call('test.pcap', 'rb')
        mock_open.assert_any_call('output/whitelist.txt', 'r')

    # Test for Whitelist
    @patch.dict(os.environ, {'OUTPUT_FOLDER': 'output', 'WHITELIST': 'whitelist.txt'})
    @patch('builtins.open', new_callable=mock_open)
    @patch('os.chmod')
    def test_add_to_whitelist(self, mock_open, mock_chmod):
        
        result = add_to_whitelist("192.168.50.134 : 1024 --> 152.131.96.26 : 443", 'output/whitelist.txt', {"192.168.50.134 : 1024 --> 152.131.96.26 : 443"})
        
        # 600 permission
        mock_open.assert_called_with('output/whitelist.txt', 0o600)
        # Ensure 1 entry was added
        self.assertEqual(result, 1)
        
    # Test for Blacklist
    @patch.dict(os.environ, {'OUTPUT_FOLDER': 'output', 'BLACKLIST': 'blacklist.txt'})
    @patch('os.path.exists', return_value=True)
    @patch('builtins.open', new_callable=mock_open)
    @patch('os.chmod')
    def test_add_to_blacklist(self, mock_open, mock_chmod, mock_exists):
        result = add_to_blacklist("192.168.50.134 : 1024 --> 152.131.96.26 : 443", 'output/blacklist.txt', {"192.168.50.134 : 1024 --> 152.131.96.26 : 443"})
        
        # 600 permission
        mock_open.assert_called_with('output/blacklist.txt', 0o600)
        # Ensure 1 entry was added
        self.assertEqual(result, 1)
        
    # Test for unsorted   
    @patch.dict(os.environ, {'OUTPUT_FOLDER': 'output', 'UNSORTED_FILE': 'unsorted.txt'})
    @patch('os.path.exists', return_value=True)
    @patch('builtins.open', new_callable=mock_open)
    def test_update_from_unsorted(self, mock_open, mock_exists):
        with patch('builtins.input', return_value='w'):
            update_from_unsorted('unsorted.txt')
            
        mock_open.assert_called_with('unsorted.txt', 'w')
        
if __name__ == '__main__':
    unittest.main()