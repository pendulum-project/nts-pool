# DNS SRV record based NTS pool
Pooling is a way to combine the power of multiple NTP servers. By offering a set
of servers all available under the same DNS name, we can efficiently send
clients multiple NTP servers and pick servers that are geographically close to
the client. The pool does this by dynamically generating a DNS response
containing a set IP addresses of servers for a specific region. The introduction
of NTS however complicates the ability of pooling NTP servers together.

NTS extends NTP with a key exchange step based on TLS to exchange secrets. These
secrets are then later used to secure regular NTP packets using extension fields
in the NTP packet.
