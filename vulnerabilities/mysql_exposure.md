# Vulnerability Intelligence: MySQL Exposure

## Condition
MySQL reachable on port 3306 or reported by scan output.

## Why It Matters
MySQL should rarely be publicly reachable. Exposure can enable password attacks, exploitation of weak accounts, data theft, and service fingerprinting.

## Escalation Factors
- Bound to `0.0.0.0`
- Weak or default credentials
- No network allowlist
- Old server version
- Sensitive data hosted on the instance

## Recommended Inspection Area
- MySQL bind address
- Host firewall
- User grants and remote access settings
- Backup and replication paths

## Defensive Actions
- Bind to localhost or internal addresses only
- Limit remote access to trusted application hosts
- Rotate credentials and remove unnecessary users
- Patch to supported versions
