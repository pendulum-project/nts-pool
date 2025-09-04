

# Threat modelling session notes


## Agenda


### Establish mission and suitable performance indicators

1.  Mission

    -   Secure distribution of time

2.  Objectives/Performance indicators

    -   Availability
    -   Time source quality
    -   Public image/trustability
    -   ?


### Scoping

Which are the most important assets for our mission?


### System Characterization

What does our system look like?


### Threat Identification

Which threats apply to our system?


### Risk Determination

To which degree of risk are we exposed?


## Identified as security properties for the pool


### Provenance

Time server is who it says it is and part of the pool

1.  NTS
    - TLS handshake
2.  Pool
    - KELB
        - TLS handshake with client        
        - TLS handshake with time source
    - SRV
        - DNSSEC


### Confidentiality

Security of keys

1.  NTS/SRV Pool
    - Trust in the time source
    - TLS

2.  KELB Pool
    - Trust in KELB
    - Trust in time source

### Secure choice of time servers

1.  NTS
    - N/A
2.  KELB pool
    - Trust in KELB
    - TLS
3.  SRV pool
    - Trust or verification van DNS subsystem


# Level 1 Data Flow Diagram

https://github.com/cikzh/nts-pool/blob/main/documentation/threat-model/level1.svg
## Legend
-   PO: Pool Operator (admin)
-   TSO: Time Source Operator (manager)
-   TS: Time Source
-   TU: Time User (client)
-   TUO: Time User Operator (end user)

# What next
- Level 1 system characterization for SRV
- Per trust-boundary-crossing arrow, provide a short description

