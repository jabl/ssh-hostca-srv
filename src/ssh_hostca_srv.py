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
from __future__ import print_function
from __future__ import unicode_literals
from __future__ import division
from __future__ import absolute_import
from builtins import int
from builtins import open
from future import standard_library
standard_library.install_aliases()

from flask import Flask, request
from flask import Response

app = Flask(__name__)
app.debug = True

import os

capath = os.getenv('SSH_CAPATH', './hostca')

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
    certpath = pubkeypath.rsplit('.', 1)[0] + '-cert.pub'
    return certpath


def do_GET():
    """Return a ssh_known_hosts line with the CA public key id"""
    capub = capath + '.pub'
    cadomain = os.getenv('SSH_CADOMAIN', '*')
    with open(capub, "rb") as f:
        ca = f.read()
    resp = b'@cert-authority ' + cadomain + ' ' + ca
    return Response(resp, mimetype='application/octet-stream')

def do_POST():
    """Client POST's a ssh public host key, server signs it with host CA,
    returns signed certificate.
    """
    import tempfile
    import os
    import socket
    hostname = socket.gethostbyaddr(request.remote_addr)[0]
    pubkeyfile = request.files['file']
    if not pubkeyfile:
        return ""
    t = tempfile.mkdtemp()
    pubkeypath = os.path.join(t, 'key.pub')
    pubkeyfile.save(pubkeypath)
    certpath = sign(pubkeypath, hostname)
    with open(certpath, 'rb') as f:
        certcontent = f.read()
    os.unlink(certpath)
    os.unlink(pubkeypath)
    os.rmdir(t)
    return Response(certcontent, mimetype='application/octet-stream')

@app.route('/', methods=['GET', 'POST'])
def myapp():
    if request.method == 'GET':
        return do_GET()
    else:
        return do_POST()

if __name__ == '__main__':
    app.run(debug=True)
