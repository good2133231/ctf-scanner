#!/usr/bin/env python3
import http.server
import socketserver

Handler = http.server.SimpleHTTPRequestHandler
httpd = socketserver.TCPServer(('127.0.0.1', 8765), Handler)
print('Server started on port 8765')
httpd.serve_forever()
