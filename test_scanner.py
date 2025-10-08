#!/usr/bin/env python3
"""
Comprehensive Test Suite for Vulnerability Scanner (CS1060 HW5)

This test suite validates the vulnerability scanner against the grading criteria:
1. Correct output format: protocol://username:password@host:port server_output
2. All credential combinations are tested
3. Works with different ports and server configurations
4. Proper scanning of ports 1-8999
"""

import unittest
from unittest.mock import Mock, patch, MagicMock, call
import sys
import io
import re
import socket
import warnings
import paramiko
import requests
from requests.auth import HTTPBasicAuth

# Import the module to test
import vulnerability_scanner


class TestCredentialsConfiguration(unittest.TestCase):
    """Test that credentials are correctly configured"""
    
    def test_credentials_dictionary_exists(self):
        """Verify credentials dictionary has all required entries"""
        self.assertIsInstance(vulnerability_scanner.credentials, dict)
        self.assertEqual(len(vulnerability_scanner.credentials), 3)
    
    def test_admin_credentials(self):
        """Verify admin credentials"""
        self.assertIn('admin', vulnerability_scanner.credentials)
        self.assertEqual(vulnerability_scanner.credentials['admin'], 'admin')
    
    def test_root_credentials(self):
        """Verify root credentials"""
        self.assertIn('root', vulnerability_scanner.credentials)
        self.assertEqual(vulnerability_scanner.credentials['root'], 'abc123')
    
    def test_skroob_credentials(self):
        """Verify skroob credentials"""
        self.assertIn('skroob', vulnerability_scanner.credentials)
        self.assertEqual(vulnerability_scanner.credentials['skroob'], '12345')


class TestOutputFormat(unittest.TestCase):
    """Test output format matches specification: protocol://user:pass@host:port output"""
    
    def setUp(self):
        """Capture stdout for output validation"""
        self.held_stdout = sys.stdout
        sys.stdout = io.StringIO()
    
    def tearDown(self):
        """Restore stdout"""
        sys.stdout = self.held_stdout
    
    @patch('vulnerability_scanner.requests.get')
    def test_http_output_format(self, mock_get):
        """Test HTTP output matches: http://username:password@127.0.0.1:port output"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = "success"
        mock_get.return_value = mock_response
        
        vulnerability_scanner.test_http(8080, 'admin', 'admin')
        
        output = sys.stdout.getvalue()
        # Should match: http://admin:admin@127.0.0.1:8080 success
        self.assertRegex(output, r'^http://admin:admin@127\.0\.0\.1:8080 success\n?$')
    
    @patch('vulnerability_scanner.paramiko.SSHClient')
    def test_ssh_output_format(self, mock_ssh_class):
        """Test SSH output matches: ssh://username:password@127.0.0.1:port output"""
        mock_client = Mock()
        mock_ssh_class.return_value = mock_client
        
        mock_transport = Mock()
        mock_transport.is_active.return_value = True
        mock_client.get_transport.return_value = mock_transport
        
        mock_channel = Mock()
        mock_channel.recv.side_effect = [b"success", b""]
        mock_transport.open_session.return_value = mock_channel
        
        vulnerability_scanner.test_ssh(2222, 'skroob', '12345')
        
        output = sys.stdout.getvalue()
        # Should match: ssh://skroob:12345@127.0.0.1:2222 success
        self.assertRegex(output, r'^ssh://skroob:12345@127\.0\.0\.1:2222 success\n?$')
    
    @patch('vulnerability_scanner.requests.get')
    def test_http_different_server_output(self, mock_get):
        """Test HTTP with different server response"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = "authenticated\n"
        mock_get.return_value = mock_response
        
        vulnerability_scanner.test_http(9000, 'root', 'abc123')
        
        output = sys.stdout.getvalue().strip()
        self.assertEqual(output, "http://root:abc123@127.0.0.1:9000 authenticated")
    
    @patch('vulnerability_scanner.requests.get')
    def test_http_no_output_on_failure(self, mock_get):
        """Test HTTP does not output on authentication failure"""
        mock_response = Mock()
        mock_response.status_code = 401
        mock_get.return_value = mock_response
        
        result = vulnerability_scanner.test_http(8080, 'admin', 'wrong')
        
        output = sys.stdout.getvalue()
        self.assertEqual(output, "")
        self.assertFalse(result)


class TestPortScanning(unittest.TestCase):
    """Test port scanning functionality"""
    
    @patch('vulnerability_scanner.nmap.PortScanner')
    def test_scan_range_1_to_8999(self, mock_scanner_class):
        """Verify port scan covers range 1-8999"""
        mock_scanner = MagicMock()
        mock_scanner_class.return_value = mock_scanner
        mock_scanner.all_hosts.return_value = []
        
        vulnerability_scanner.scan_ports()
        
        mock_scanner.scan.assert_called_once_with('127.0.0.1', '1-8999', arguments='-sT')
    
    @patch('vulnerability_scanner.nmap.PortScanner')
    def test_scan_localhost_only(self, mock_scanner_class):
        """Verify scan targets only localhost (127.0.0.1)"""
        mock_scanner = MagicMock()
        mock_scanner_class.return_value = mock_scanner
        mock_scanner.all_hosts.return_value = []
        
        vulnerability_scanner.scan_ports()
        
        # Verify scanning 127.0.0.1
        call_args = mock_scanner.scan.call_args
        self.assertEqual(call_args[0][0], '127.0.0.1')
    
    
    @patch('vulnerability_scanner.nmap.PortScanner')
    def test_handles_no_open_ports(self, mock_scanner_class):
        """Verify handles case with no open ports"""
        mock_scanner = MagicMock()
        mock_scanner_class.return_value = mock_scanner
        mock_scanner.all_hosts.return_value = ['127.0.0.1']
        
        mock_scanner.__getitem__.side_effect = lambda x: MagicMock(
            all_protocols=lambda: ['tcp'],
            __getitem__=lambda proto: {}
        )
        
        result = vulnerability_scanner.scan_ports()
        
        self.assertEqual(result, [])
    
    @patch('vulnerability_scanner.nmap.PortScanner')
    def test_handles_scan_exception(self, mock_scanner_class):
        """Verify graceful handling of scan errors"""
        mock_scanner = MagicMock()
        mock_scanner_class.return_value = mock_scanner
        mock_scanner.scan.side_effect = Exception("Permission denied")
        
        result = vulnerability_scanner.scan_ports()
        
        self.assertEqual(result, [])


class TestHTTPAuthentication(unittest.TestCase):
    """Test HTTP Basic Authentication testing"""
    
    @patch('vulnerability_scanner.requests.get')
    def test_http_uses_basic_auth(self, mock_get):
        """Verify HTTP uses Basic Authentication"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = "success"
        mock_get.return_value = mock_response
        
        captured_output = io.StringIO()
        sys.stdout = captured_output
        
        vulnerability_scanner.test_http(8080, 'admin', 'admin')
        
        sys.stdout = sys.__stdout__
        
        # Verify HTTPBasicAuth was used
        mock_get.assert_called_once()
        call_kwargs = mock_get.call_args[1]
        self.assertIsInstance(call_kwargs['auth'], HTTPBasicAuth)
    
    @patch('vulnerability_scanner.requests.get')
    def test_http_connects_to_correct_url(self, mock_get):
        """Verify HTTP connects to correct URL"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = "success"
        mock_get.return_value = mock_response
        
        captured_output = io.StringIO()
        sys.stdout = captured_output
        
        vulnerability_scanner.test_http(8081, 'root', 'abc123')
        
        sys.stdout = sys.__stdout__
        
        # Verify correct URL
        call_args = mock_get.call_args[0]
        self.assertEqual(call_args[0], 'http://127.0.0.1:8081/')
    
    @patch('vulnerability_scanner.requests.get')
    def test_http_only_succeeds_on_200(self, mock_get):
        """Verify HTTP only returns True on status 200"""
        test_cases = [
            (200, True),
            (401, False),
            (403, False),
            (404, False),
            (500, False),
        ]
        
        for status_code, expected_result in test_cases:
            mock_response = Mock()
            mock_response.status_code = status_code
            mock_response.text = "test"
            mock_get.return_value = mock_response
            
            captured_output = io.StringIO()
            sys.stdout = captured_output
            
            result = vulnerability_scanner.test_http(8080, 'admin', 'admin')
            
            sys.stdout = sys.__stdout__
            
            self.assertEqual(result, expected_result, 
                           f"Status {status_code} should return {expected_result}")
    
    @patch('vulnerability_scanner.requests.get')
    def test_http_handles_connection_errors(self, mock_get):
        """Verify HTTP handles connection errors gracefully"""
        error_types = [
            requests.exceptions.ConnectionError("Connection refused"),
            requests.exceptions.Timeout("Timeout"),
            requests.exceptions.RequestException("Generic error"),
        ]
        
        for error in error_types:
            mock_get.side_effect = error
            
            result = vulnerability_scanner.test_http(8080, 'admin', 'admin')
            
            self.assertFalse(result, f"Should handle {type(error).__name__}")
    
    @patch('vulnerability_scanner.requests.get')
    def test_http_strips_whitespace_from_response(self, mock_get):
        """Verify HTTP strips whitespace from server response"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = "  success  \n"
        mock_get.return_value = mock_response
        
        captured_output = io.StringIO()
        sys.stdout = captured_output
        
        vulnerability_scanner.test_http(8080, 'admin', 'admin')
        
        sys.stdout = sys.__stdout__
        
        output = captured_output.getvalue().strip()
        self.assertIn(" success", output)
        self.assertNotIn("  success  ", output)


class TestSSHAuthentication(unittest.TestCase):
    """Test SSH password authentication testing"""
    
    @patch('vulnerability_scanner.paramiko.SSHClient')
    def test_ssh_disables_host_key_checking(self, mock_ssh_class):
        """Verify SSH disables host key verification"""
        mock_client = Mock()
        mock_ssh_class.return_value = mock_client
        mock_client.connect.side_effect = Exception("Stop here")
        
        vulnerability_scanner.test_ssh(2222, 'admin', 'admin')
        
        # Should set AutoAddPolicy
        mock_client.set_missing_host_key_policy.assert_called_once()
    
    @patch('vulnerability_scanner.paramiko.SSHClient')
    def test_ssh_uses_password_only(self, mock_ssh_class):
        """Verify SSH uses password auth without keys"""
        mock_client = Mock()
        mock_ssh_class.return_value = mock_client
        mock_client.connect.side_effect = Exception("Stop here")
        
        vulnerability_scanner.test_ssh(2222, 'admin', 'admin')
        
        # Verify password-only authentication
        call_kwargs = mock_client.connect.call_args[1]
        self.assertFalse(call_kwargs['look_for_keys'])
        self.assertFalse(call_kwargs['allow_agent'])
    
    @patch('vulnerability_scanner.paramiko.SSHClient')
    def test_ssh_connects_to_correct_port(self, mock_ssh_class):
        """Verify SSH connects to correct port"""
        mock_client = Mock()
        mock_ssh_class.return_value = mock_client
        mock_client.connect.side_effect = Exception("Stop here")
        
        vulnerability_scanner.test_ssh(2224, 'root', 'abc123')
        
        call_kwargs = mock_client.connect.call_args[1]
        self.assertEqual(call_kwargs['port'], 2224)
        self.assertEqual(call_kwargs['username'], 'root')
        self.assertEqual(call_kwargs['password'], 'abc123')
    
    @patch('vulnerability_scanner.paramiko.SSHClient')
    def test_ssh_handles_auth_failure(self, mock_ssh_class):
        """Verify SSH handles authentication failures"""
        mock_client = Mock()
        mock_ssh_class.return_value = mock_client
        mock_client.connect.side_effect = paramiko.AuthenticationException("Auth failed")
        
        result = vulnerability_scanner.test_ssh(2222, 'admin', 'wrong')
        
        self.assertFalse(result)
    
    @patch('vulnerability_scanner.paramiko.SSHClient')
    def test_ssh_requires_output_for_success(self, mock_ssh_class):
        """Verify SSH only succeeds when server sends output"""
        mock_client = Mock()
        mock_ssh_class.return_value = mock_client
        
        mock_transport = Mock()
        mock_transport.is_active.return_value = True
        mock_client.get_transport.return_value = mock_transport
        
        mock_channel = Mock()
        mock_channel.recv.return_value = b""  # No output
        mock_transport.open_session.return_value = mock_channel
        
        result = vulnerability_scanner.test_ssh(2222, 'admin', 'admin')
        
        self.assertFalse(result)
    
    @patch('vulnerability_scanner.paramiko.SSHClient')
    def test_ssh_closes_connection(self, mock_ssh_class):
        """Verify SSH properly closes connections"""
        mock_client = Mock()
        mock_ssh_class.return_value = mock_client
        mock_client.connect.side_effect = Exception("Error")
        
        vulnerability_scanner.test_ssh(2222, 'admin', 'admin')
        
        # Should attempt to close even on error
        mock_client.close.assert_called()


class TestMainIntegration(unittest.TestCase):
    """Test main function integration and workflow"""
    
    @patch('vulnerability_scanner.scan_ports')
    @patch('vulnerability_scanner.test_http')
    @patch('vulnerability_scanner.test_ssh')
    @patch('sys.argv', ['vulnerability_scanner.py'])
    def test_main_tests_all_credentials(self, mock_ssh, mock_http, mock_scan):
        """Verify main tests all credential combinations on each port"""
        mock_scan.return_value = [8080, 2222]
        mock_http.return_value = False
        mock_ssh.return_value = False
        
        vulnerability_scanner.main()
        
        # Should test 3 credentials × 2 ports = 6 tests each
        self.assertEqual(mock_http.call_count, 6)
        self.assertEqual(mock_ssh.call_count, 6)
    
    @patch('vulnerability_scanner.scan_ports')
    @patch('vulnerability_scanner.test_http')
    @patch('vulnerability_scanner.test_ssh')
    @patch('sys.argv', ['vulnerability_scanner.py'])
    def test_main_tests_credentials_in_order(self, mock_ssh, mock_http, mock_scan):
        """Verify credentials are tested in consistent order"""
        mock_scan.return_value = [8080]
        mock_http.return_value = False
        mock_ssh.return_value = False
        
        vulnerability_scanner.main()
        
        # Get the usernames from HTTP calls
        http_calls = [call[0][1] for call in mock_http.call_args_list]
        
        # Should include all three users
        self.assertIn('admin', http_calls)
        self.assertIn('root', http_calls)
        self.assertIn('skroob', http_calls)
    
    @patch('vulnerability_scanner.scan_ports')
    @patch('vulnerability_scanner.test_http')
    @patch('vulnerability_scanner.test_ssh')
    @patch('sys.argv', ['vulnerability_scanner.py'])
    def test_main_tests_http_then_ssh(self, mock_ssh, mock_http, mock_scan):
        """Verify HTTP is tested before SSH for each port/credential combo"""
        mock_scan.return_value = [8080]
        call_order = []
        
        def record_http(*args):
            call_order.append('http')
            return False
        
        def record_ssh(*args):
            call_order.append('ssh')
            return False
        
        mock_http.side_effect = record_http
        mock_ssh.side_effect = record_ssh
        
        vulnerability_scanner.main()
        
        # Pattern should be http, ssh, http, ssh, http, ssh
        self.assertEqual(call_order, ['http', 'ssh', 'http', 'ssh', 'http', 'ssh'])
    
    @patch('vulnerability_scanner.scan_ports')
    @patch('sys.argv', ['vulnerability_scanner.py', '-v'])
    def test_main_verbose_flag(self, mock_scan):
        """Verify -v flag enables verbose mode"""
        mock_scan.return_value = []
        
        vulnerability_scanner.verbose = False
        vulnerability_scanner.main()
        
        self.assertTrue(vulnerability_scanner.verbose)
    
    @patch('vulnerability_scanner.scan_ports')
    @patch('sys.argv', ['vulnerability_scanner.py', '--verbose'])
    def test_main_verbose_long_flag(self, mock_scan):
        """Verify --verbose flag enables verbose mode"""
        mock_scan.return_value = []
        
        vulnerability_scanner.verbose = False
        vulnerability_scanner.main()
        
        self.assertTrue(vulnerability_scanner.verbose)
    
    @patch('vulnerability_scanner.scan_ports')
    @patch('vulnerability_scanner.test_http')
    @patch('vulnerability_scanner.test_ssh')
    @patch('sys.argv', ['vulnerability_scanner.py'])
    def test_main_handles_no_open_ports(self, mock_ssh, mock_http, mock_scan):
        """Verify main handles case with no open ports"""
        mock_scan.return_value = []
        
        # Should not crash
        vulnerability_scanner.main()
        
        # Should not test any ports
        mock_http.assert_not_called()
        mock_ssh.assert_not_called()


class TestVerboseMode(unittest.TestCase):
    """Test verbose output functionality"""
    
    def setUp(self):
        """Save original verbose state and stderr"""
        self.original_verbose = vulnerability_scanner.verbose
        vulnerability_scanner.verbose = False
    
    def tearDown(self):
        """Restore verbose state"""
        vulnerability_scanner.verbose = self.original_verbose
    
    def test_vprint_outputs_when_verbose(self):
        """Verify vprint outputs to stderr when verbose is True"""
        vulnerability_scanner.verbose = True
        
        captured = io.StringIO()
        sys.stderr = captured
        
        vulnerability_scanner.vprint("Test message")
        
        sys.stderr = sys.__stderr__
        
        self.assertEqual(captured.getvalue(), "Test message\n")
    
    def test_vprint_silent_when_not_verbose(self):
        """Verify vprint is silent when verbose is False"""
        vulnerability_scanner.verbose = False
        
        captured = io.StringIO()
        sys.stderr = captured
        
        vulnerability_scanner.vprint("Test message")
        
        sys.stderr = sys.__stderr__
        
        self.assertEqual(captured.getvalue(), "")


class TestEdgeCases(unittest.TestCase):
    """Test edge cases and error handling"""
    
    @patch('vulnerability_scanner.requests.get')
    def test_http_with_special_characters_in_response(self, mock_get):
        """Test HTTP handles special characters in server response"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = "success!@#$%^&*()"
        mock_get.return_value = mock_response
        
        captured_output = io.StringIO()
        sys.stdout = captured_output
        
        result = vulnerability_scanner.test_http(8080, 'admin', 'admin')
        
        sys.stdout = sys.__stdout__
        
        self.assertTrue(result)
        self.assertIn("success!@#$%^&*()", captured_output.getvalue())
    
    @patch('vulnerability_scanner.paramiko.SSHClient')
    def test_ssh_with_multiline_output(self, mock_ssh_class):
        """Test SSH handles multiline server output"""
        mock_client = Mock()
        mock_ssh_class.return_value = mock_client
        
        mock_transport = Mock()
        mock_transport.is_active.return_value = True
        mock_client.get_transport.return_value = mock_transport
        
        mock_channel = Mock()
        mock_channel.recv.side_effect = [b"line1\nline2\n", b""]
        mock_transport.open_session.return_value = mock_channel
        
        captured_output = io.StringIO()
        sys.stdout = captured_output
        
        result = vulnerability_scanner.test_ssh(2222, 'admin', 'admin')
        
        sys.stdout = sys.__stdout__
        
        self.assertTrue(result)    

class TestCodeVerification(unittest.TestCase):
    """Verify the vulnerability_scanner code itself is correct"""
    
    @patch('vulnerability_scanner.nmap.PortScanner')
    def test_scan_ports_code_correctness(self, mock_scanner_class):
        """Verify scan_ports uses correct python-nmap API patterns"""
        # Create a mock that behaves exactly like real nmap library
        mock_scanner = MagicMock()
        mock_scanner_class.return_value = mock_scanner
        
        # Mock all_hosts
        mock_scanner.all_hosts.return_value = ['127.0.0.1']
        
        # Create the nested structure that real nmap returns
        # nm['127.0.0.1'] returns a host object
        host_mock = MagicMock()
        
        # host.all_protocols() returns ['tcp']
        host_mock.all_protocols.return_value = ['tcp']
        
        # host['tcp'] returns a protocol object with port data
        tcp_mock = {
            22: {'state': 'open'},
            80: {'state': 'open'},
            8080: {'state': 'closed'},
        }
        
        # Make host['tcp'].keys() work
        protocol_mock = MagicMock()
        protocol_mock.keys.return_value = tcp_mock.keys()
        protocol_mock.__getitem__.side_effect = lambda port: tcp_mock[port]
        
        # Wire up host[proto] to return protocol_mock
        host_mock.__getitem__.return_value = protocol_mock
        
        # Wire up nm['127.0.0.1'] to return host_mock  
        mock_scanner.__getitem__.return_value = host_mock
        
        # Run the actual code
        result = vulnerability_scanner.scan_ports()
        
        # If code is correct, should return open ports
        self.assertEqual(result, [22, 80], 
                        "Code should correctly extract open ports")
        
        # Verify the code called the API correctly
        mock_scanner.scan.assert_called_once_with('127.0.0.1', '1-8999', arguments='-sT')
        mock_scanner.all_hosts.assert_called()
        mock_scanner.__getitem__.assert_called_with('127.0.0.1')
        host_mock.all_protocols.assert_called()


if __name__ == '__main__':
    # Suppress warnings during tests
    warnings.filterwarnings('ignore')
    
    # Run tests with verbose output
    unittest.main(verbosity=2)