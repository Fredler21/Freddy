# OWASP Top 10 Defensive Reference

## Overview
The OWASP Top 10 is a practical prioritization of common web application security risks. For Freddy, this file is used as defensive guidance during interpretation of scan data, headers, exposed routes, authentication behavior, and developer configuration findings.

## A01 Broken Access Control
Indicators:
- Administrative endpoints reachable without access controls
- Forced browsing patterns to `/admin`, `/manage`, `/console`, `/wp-admin`, `/phpmyadmin`
- HTTP 200 responses on sensitive paths that should require authentication

Defensive actions:
- Enforce server-side authorization checks
- Remove reliance on hidden URLs for protection
- Restrict administrative routes by network, identity, or MFA
- Log and alert on sensitive route access attempts

## A02 Cryptographic Failures
Indicators:
- Plain HTTP exposure for login or session traffic
- Legacy TLS versions enabled
- Weak ciphers or certificate validation errors
- Sensitive tokens or secrets exposed in logs

Defensive actions:
- Require HTTPS with modern TLS
- Disable SSLv2, SSLv3, TLS 1.0, and TLS 1.1
- Rotate exposed secrets immediately
- Apply HSTS and secure cookie flags

## A03 Injection
Indicators:
- Suspicious URL parameters in logs
- Error traces showing SQL syntax failures
- Command injection-like payloads in query strings or form fields

Defensive actions:
- Use parameterized queries
- Validate and normalize input
- Run applications with least privilege
- Block obvious exploit payloads with layered controls

## A04 Insecure Design
Indicators:
- No rate limiting on authentication
- Administrative features exposed publicly
- Sensitive workflows missing verification steps

Defensive actions:
- Add abuse cases to design reviews
- Enforce throttling and lockouts
- Segment high-risk workflows

## A05 Security Misconfiguration
Indicators:
- Default credentials suspected
- Debug headers or verbose banners
- Directory indexing or public backup files
- Missing security headers

Defensive actions:
- Harden baseline configurations
- Remove default accounts and sample content
- Apply secure HTTP headers consistently
- Review internet-facing services regularly

## A06 Vulnerable and Outdated Components
Indicators:
- Old server banners
- EOL platforms or legacy packages
- Known weak services exposed to the internet

Defensive actions:
- Track inventory and versions
- Patch on a risk-based cadence
- Remove unused software

## A07 Identification and Authentication Failures
Indicators:
- Repeated failed login events
- Root login attempts
- Password authentication enabled for SSH on exposed hosts

Defensive actions:
- Prefer MFA and strong key-based auth
- Rate limit login attempts
- Disable direct root login where possible
- Deploy fail2ban or equivalent protections

## A08 Software and Data Integrity Failures
Indicators:
- Unsigned updates or scripts
- Unexpected build or deployment artifacts
- Downloads from untrusted sources

Defensive actions:
- Verify signatures and checksums
- Use trusted package repositories
- Restrict deployment paths

## A09 Security Logging and Monitoring Failures
Indicators:
- Important events not retained
- No alerting for brute force or admin endpoint access
- Sparse context in logs

Defensive actions:
- Log authentication, privilege, and configuration changes
- Centralize logs for correlation
- Alert on repeated denials and suspicious path enumeration

## A10 Server-Side Request Forgery
Indicators:
- Internal IPs or metadata service references in application behavior
- Outbound callbacks triggered by user input

Defensive actions:
- Restrict outbound connectivity
- Validate destinations
- Deny access to link-local and internal admin networks where not needed
