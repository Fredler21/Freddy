# Vulnerability Intelligence: SSH Exposure

## Condition
SSH service reachable on port 22 from untrusted or public networks.

## Why It Matters
SSH is commonly targeted for brute-force attacks, credential stuffing, and exploitation of weak administrative practices. Exposure is not automatically a vulnerability, but public reachability materially increases attack surface.

## Escalation Factors
- Password authentication enabled
- Root login permitted
- No source-IP restriction
- Repeated failed login activity in logs
- Old OpenSSH version or weak ciphers

## Recommended Inspection Area
- `sshd_config`
- Firewall policy
- Auth logs
- Bastion or VPN architecture

## Defensive Actions
- Restrict SSH to management networks
- Disable password auth where possible
- Disable root login
- Apply fail2ban or equivalent throttling
- Review successful logins after brute-force attempts
