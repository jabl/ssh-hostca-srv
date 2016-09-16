#!/usr/bin/env python3

"""
    Simple HTTP service to sign ssh host keys.
    Copyright (C) 2016  Janne Blomqvist

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.

"""

from http.server import BaseHTTPRequestHandler, HTTPServer

def sign(pubkeypath, hostname):
    """Sign a ssh host public key"""
    import subprocess
    import os.path
    host_short = hostname.split('.')[0]
    if host_short != hostname:
        principals = host_short + ',' + hostname
    else:
        principals = hostname
    subprocess.check_call(['/usr/bin/ssh-keygen', '-s', capath, 
                           '-I', hostname, '-h',
                           '-n', principals, pubkeypath])
    certpath = pubkeypath.rsplit(',', maxsplit=1)[0] + '-cert.pub'
    return certpath

class S(BaseHTTPRequestHandler):
    def _set_headers(self, length=None):
        self.send_response(200)
        self.send_header('Content-type', 'application/octet-stream')
        if length != None:
            self.send_header('Content-Length', length)            
        self.end_headers()

    def do_GET(self):
        self._set_headers()
        self.wfile.write(b"<html><body><h1>hi!</h1></body></html>\n")

    def do_HEAD(self):
        self._set_headers()
        
    def do_POST(self):
        import tempfile
        import os
        import socket
        hostname = socket.gethostbyaddr(self.client_address[0])[0]
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        t = tempfile.NamedTemporaryFile(delete=False)
        t.write(post_data)
        t.close()
        certpath = sign(t.name, hostname)
        os.unlink(t.name)
        with open(certpath, 'rb') as f:
            certcontent = f.read()
        os.unlink(certpath)
        self._set_headers(length=len(certcontent))
        self.wfile.write(certcontent)
        
def run(server_class=HTTPServer, handler_class=S, port=8080):
    server_address = ('', port)
    httpd = server_class(server_address, handler_class)
    print('Starting httpd...')
    httpd.serve_forever()


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='Run a HTTP service for signing SSH host keys.')
    parser.add_argument('-p', '--port', default=8080, type=int)
    parser.add_argument('-c', '--capath', default='./hostca', 
                        help='Path to the host CA private key file')
    args = parser.parse_args()
    global capath
    capath = args.capath
    run(port=args.port)
