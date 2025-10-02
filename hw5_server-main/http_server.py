from http.server import BaseHTTPRequestHandler, HTTPServer
import base64
import argparse

class SimpleHTTPRequestHandler(BaseHTTPRequestHandler):
    def __init__(self, username, password, *args, **kwargs):
        self.username = username
        self.password = password
        super().__init__(*args, **kwargs)

    def do_GET(self):
        auth_header = self.headers.get('Authorization')
        if not auth_header or not self.verify_auth(auth_header):
            self.send_response(401)
            self.send_header('WWW-Authenticate', 'Basic realm="Secure Area"')
            self.end_headers()
            return

        self.send_response(200)
        self.send_header('Content-type', 'text/plain')
        self.end_headers()
        self.wfile.write(b'success')

    def verify_auth(self, auth_header):
        auth_type, auth_string = auth_header.split(' ')
        if auth_type.lower() != 'basic':
            return False
        decoded = base64.b64decode(auth_string).decode('utf-8')
        username, password = decoded.split(':')
        return username == self.username and password == self.password

def run(server_class=HTTPServer, handler_class=SimpleHTTPRequestHandler, port=8080, username='admin', password='admin'):
    server_address = ('', port)
    handler = lambda *args, **kwargs: handler_class(username, password, *args, **kwargs)
    httpd = server_class(server_address, handler)
    print(f'Starting server on port {port} with username {username}...')
    httpd.serve_forever()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Start HTTP server with basic auth')
    parser.add_argument('--port', type=int, default=8080, help='Port number to listen on')
    parser.add_argument('--username', default='admin', help='Username for basic auth')
    parser.add_argument('--password', default='admin', help='Password for basic auth')
    args = parser.parse_args()
    run(port=args.port, username=args.username, password=args.password)
