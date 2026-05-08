# Implementing SRV pool support

The SRV pool option is entirely based on existing specifications, primarily SRV records ([RFC 2782](https://datatracker.ietf.org/doc/rfc2782/)) and DNSSEC ([RFC 9364](https://datatracker.ietf.org/doc/rfc9364/)). To use the SRV pool to find NTS capable servers for use, the client does a lookup for SRV records under the pool's domain name. These records are then ordered randomly using their weighting as defined in RFC 2782, after which the client uses the first acceptable record.

In using an SRV record, the server contacts the NTS ke server at the port and domain name indicated by the SRV record. For the TLS connection, it validates that the certificate provided by the server is valid for the domain name provided in the SRV record (e.g. the domain name provided in the SRV record fully replaces the domain name of the pool for all communication with the NTS server).

To ensure that this does not introduce a security issue, it is of paramount importance that the client verifies that the SRV records are correctly signed with a valid DNSSEC signature. Clients MUST reject any SRV records which are unsigned, or whose signatures are invalid.
