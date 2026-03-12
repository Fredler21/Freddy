# SSH Hardening Guide

## High-Risk Conditions
- Port 22 exposed to untrusted networks
- Password authentication enabled
- Direct root login enabled
- Weak or reused administrator credentials
- No brute-force protection

## Recommended Configuration
Key `sshd_config` controls:
- `PermitRootLogin no`
- `PasswordAuthentication no` when operationally possible
- `PubkeyAuthentication yes`
- `MaxAuthTries 3`
- `AllowUsers` or `AllowGroups` for restricted admin access
- `LoginGraceTime 30`

## Network Protections
- Restrict SSH by firewall source IPs
- Place SSH behind VPN, bastion, or management network
- Consider port-knocking or alternate ports only as noise reduction, not primary security

## Detection Guidance
Signals of SSH attack activity:
- Many `Failed password` lines in a short time window
- Invalid user attempts
- Root login attempts
- Authentication activity from unfamiliar geographies or networks

## Remediation Guidance
- Migrate administrators to key-based authentication
- Rotate credentials after suspected brute-force attempts
- Deploy fail2ban or equivalent rate limiting
- Review all successful SSH logins after sustained attack activity
