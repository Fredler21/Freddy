# Vulnerability Intelligence: Redis Exposure

## Condition
Redis reachable on port 6379 or identified in service banners.

## Why It Matters
Historically, internet-exposed Redis instances have led to data leakage, unauthorized modification, and post-exploitation abuse. Many deployments assume private-network trust.

## Escalation Factors
- No authentication
- Protected mode disabled
- Bound to all interfaces
- No TLS in untrusted environments

## Recommended Inspection Area
- Redis `bind` and `protected-mode`
- Firewall policy
- Authentication and ACL configuration
- Persistence and sensitive cache data

## Defensive Actions
- Restrict Redis to private networks
- Enable authentication and ACLs
- Use TLS where remote access is required
- Audit keys and data exposure after suspected access
