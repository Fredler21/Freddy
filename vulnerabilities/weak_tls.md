# Vulnerability Intelligence: Weak TLS

## Condition
TLS configuration shows legacy protocols, weak ciphers, invalid certificate chains, or verification failures.

## Why It Matters
Weak TLS reduces transport security and can expose users to downgrade, interception, and trust failures.

## Escalation Factors
- SSLv2 or SSLv3 supported
- TLS 1.0 or 1.1 enabled on modern services
- Expired or self-signed certificates where not expected
- Missing HSTS on public web services

## Recommended Inspection Area
- Web server TLS policy
- Load balancer TLS policy
- Certificate lifecycle management
- Client compatibility requirements

## Defensive Actions
- Disable weak protocol versions
- Prefer modern AEAD cipher suites
- Replace invalid or weak certificates
- Enforce HTTPS with HSTS where appropriate
