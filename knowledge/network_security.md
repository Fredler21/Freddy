# Network Security Reference

## Exposure Categories
- Administrative: SSH, RDP, WinRM, web admin panels
- Data services: MySQL, PostgreSQL, MongoDB, Redis, Elasticsearch
- Legacy protocols: FTP, Telnet, SMBv1-era services
- Public web: HTTP, HTTPS, reverse proxies, APIs

## Defensive Interpretation of Open Ports
Questions to answer:
- Is the service intentionally exposed?
- Is it bound to all interfaces or only trusted networks?
- Does the firewall restrict who can reach it?
- Is the service protected by authentication, encryption, and monitoring?

## High-Risk Service Notes
- FTP: cleartext credentials unless FTPS is used
- Telnet: cleartext remote administration, rarely justified
- Redis: often unsafe when exposed without auth or TLS
- Elasticsearch: severe data exposure risk if public and unauthenticated
- Database listeners: should usually remain private

## Recommended Remediation Pattern
1. Confirm need for the service
2. Restrict network exposure
3. Enforce strong authentication and encryption
4. Patch and inventory the service
5. Add monitoring and alerting
