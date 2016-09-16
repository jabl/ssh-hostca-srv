ssh-hostca-src
==============

A simple daemon that listens on HTTP, and signs ssh public host keys
with a host certificate, then returns the signed certificate.

A client can get a signed ssh host cert with something like::

  curl -o /etc/ssh/ssh_host_ed25519_key-cert.pub -F file=@/etc/ssh/ssh_host_ed25519_key.pub http://sshca.example.org:8080

The ssh_known_hosts line for the CA can be retrieved with a normal HTTP GET request, like::

  curl http://sshca.example.org:8080

TODO
----

- There should be a whitelist or such, so that as part of a node
  provisioning process signing a cert for that node is temporarily
  allowed, otherwise denied.
