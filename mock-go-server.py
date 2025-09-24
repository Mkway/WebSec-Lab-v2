#!/usr/bin/env python3
"""
Simple mock Go server for health checks
"""
import http.server
import socketserver
import json
from datetime import datetime

class MockGoHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/health':
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()

            response = {
                'status': 'healthy',
                'service': 'websec-go',
                'timestamp': datetime.now().isoformat()
            }

            self.wfile.write(json.dumps(response).encode())
        elif self.path == '/' or self.path == '/vulnerabilities':
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()

            response = {
                'message': 'WebSec-Lab Go Server (Mock)',
                'version': '2.0.0',
                'endpoints': ['/health', '/vulnerabilities']
            }

            self.wfile.write(json.dumps(response).encode())
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        print(f"[Go Mock] {format % args}")

if __name__ == "__main__":
    PORT = 8082
    Handler = MockGoHandler

    with socketserver.TCPServer(("", PORT), Handler) as httpd:
        print(f"Mock Go server running on port {PORT}")
        httpd.serve_forever()