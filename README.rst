ssh-hostca-srv
==============

A simple daemon that listens on HTTP, and signs ssh public host keys
with a host certificate, then returns the signed certificate.

A client can get a signed ssh host cert with something like::

  curl -o /etc/ssh/ssh_host_ed25519_key-cert.pub -F file=@/etc/ssh/ssh_host_ed25519_key.pub http://sshca.example.org:5000

A ssh known_hosts line for the CA can be retrieved with a normal HTTP GET request, like::

  curl http://sshca.example.org:5000 >> /etc/ssh/ssh_known_hosts

Running
-------

ssh-hostca-srv is built using `flask <http://flask.pocoo.org/>`_ . You can start it directly with::

  python path/to/ssh_hostca_srv.py

This launches the flask internal webserver on
port 8000. Alternatively, you can deploy it like any other WSGI
app. E.g. with gunicorn, something like::

  gunicorn --pythonpath path/to/src ssh_hostca_srv:app

The environment variable ``SSH_CAPATH`` should point to the path of
the SSH host CA private key. It defaults to ``./hostca`` in the
current directory.

The environment variable ``SSH_CADOMAIN`` specifies the DNS domain for
which the known_hosts specifies that the CA public key is valid.

TODO
----

- There should be a whitelist or such, so that as part of a node
  provisioning process signing a cert for that node is temporarily
  allowed, otherwise denied.
