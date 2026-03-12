# Linux Security Operations Guide

## Service Exposure
Internet-facing Linux systems should minimize listening services. Publicly exposed services such as SSH, databases, Elasticsearch, and Redis should be intentional, controlled, and reviewed.

Checklist:
- Enumerate listeners with `ss -tulpn`
- Confirm firewall policy matches intended exposure
- Bind administrative services to localhost or management networks
- Remove or disable unused daemons

## Authentication Hardening
- Disable direct root SSH login
- Prefer key-based authentication over passwords
- Apply PAM lockout or fail2ban for repeated failures
- Review `/var/log/auth.log`, `journalctl -u ssh`, and sudo history

## Privilege Management
- Keep login-capable accounts to a minimum
- Audit sudoers and privileged groups regularly
- Disable stale accounts and rotate credentials after incidents

## Firewall and Network Controls
- Use default-deny inbound rules where feasible
- Document approved ports and expected source networks
- Restrict database and admin services to trusted segments

## Logging and Detection
Useful Linux data sources:
- `/var/log/auth.log`
- `/var/log/syslog`
- `journalctl`
- Web server access and error logs
- Package manager history

Detection ideas:
- Repeated failed logins from one source IP
- New listening services after changes
- Admin tools exposed to the internet
- High-volume 401, 403, or 404 responses from a single IP

## Hardening Priorities
1. Reduce exposure
2. Enforce strong authentication
3. Patch internet-facing services
4. Centralize logging
5. Validate backups and recovery procedures
