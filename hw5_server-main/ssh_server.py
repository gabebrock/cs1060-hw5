import paramiko
import socket
import threading
import time
import argparse

class SSHServer(paramiko.ServerInterface):
    def __init__(self, username, password):
        self.username = username
        self.password = password

    def check_auth_password(self, username, password):
        if username == self.username and password == self.password:
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_channel_request(self, kind, chanid):
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

def handle_ssh_connection(client, server_key, username, password):
    transport = None
    try:
        # Set a timeout for the initial connection
        client.settimeout(30)
        transport = paramiko.Transport(client)
        
        try:
            # Load moduli for key exchange
            transport.load_server_moduli()
        except:
            print("Failed to load moduli, using fixed modulus")
            pass

        try:
            # Use the pre-generated server key
            transport.add_server_key(server_key)
            
            # Start the server
            server = SSHServer(username, password)
            try:
                transport.start_server(server=server)
            except paramiko.SSHException as e:
                print(f'SSH negotiation failed: {str(e)}')
                return
            
            # Wait for auth
            channel = transport.accept(20)
            if channel is not None:
                channel.send('success')
                channel.close()
            
        except (paramiko.SSHException, socket.error) as e:
            print(f'SSH error: {str(e)}')
        except Exception as e:
            print(f'Unexpected error: {str(e)}')
    finally:
        if transport:
            try:
                transport.close()
            except:
                pass
        try:
            client.close()
        except:
            pass

def start_ssh_server(port=2222, username='admin', password='admin'):
    # Generate server key once during initialization
    server_key = paramiko.RSAKey.generate(2048)
    
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(('', port))
    server_socket.listen(10)
    print(f'SSH server listening on port {port} with username {username}...')

    while True:
        try:
            client, addr = server_socket.accept()
            print(f'SSH connection from {addr[0]}:{addr[1]}')
            threading.Thread(target=handle_ssh_connection, args=(client, server_key, username, password)).start()
        except Exception as e:
            print(f'Error accepting connection: {str(e)}')

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Start SSH server with custom credentials')
    parser.add_argument('--port', type=int, default=2222, help='Port number to listen on')
    parser.add_argument('--username', default='admin', help='Username for SSH authentication')
    parser.add_argument('--password', default='admin', help='Password for SSH authentication')
    args = parser.parse_args()
    
    start_ssh_server(port=args.port, username=args.username, password=args.password)
