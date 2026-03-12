# Vulnerability Intelligence: Open Ports and Exposed Services

## Condition
Scan results or local enumeration show listening ports.

## Why It Matters
Open ports are not automatically vulnerabilities, but every exposed listener expands reachable attack surface and should be justified, protected, and monitored.

## Review Questions
- Is the service intended to be exposed?
- Is it reachable from the public internet?
- Does the service hold sensitive data or privileged control?
- Are authentication, encryption, and logging adequate?

## High Attention Services
- 21 FTP
- 22 SSH
- 23 Telnet
- 3306 MySQL
- 5432 PostgreSQL
- 6379 Redis
- 9200 Elasticsearch

## Defensive Actions
- Close unused listeners
- Restrict management services to trusted networks
- Patch exposed services
- Add service-specific hardening and monitoring
