#!/usr/bin/env python3

"""
    Simple HTTP service to sign ssh host keys.
    Copyright (C) 2016-2022  Janne Blomqvist

    SPDX-License-Identifier: MPL-2.0
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

def sign(pubkeypath, remote_addr):
    """Sign a ssh host public key"""
    import subprocess
    import os.path
    import socket
    host = socket.gethostbyaddr(remote_addr)
    principals = set()
    principals.add(host[0])
    for alias in host[1]:
        principals.add(alias)
    princ_str = ','.join(principals)
    subprocess.check_call(['/usr/bin/ssh-keygen', '-s', capath, 
                           '-I', host[0], '-h',
                           '-n', princ_str, pubkeypath])
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
    pubkeyfile = request.files['file']
    if not pubkeyfile:
        return ""
    t = tempfile.mkdtemp()
    pubkeypath = os.path.join(t, 'key.pub')
    pubkeyfile.save(pubkeypath)
    certpath = sign(pubkeypath, request.remote_addr)
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
