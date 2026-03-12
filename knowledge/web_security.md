# Web Security Defensive Guide

## Header Baseline
Security headers commonly expected on modern sites:
- `Content-Security-Policy`
- `Strict-Transport-Security`
- `X-Frame-Options` or `frame-ancestors` in CSP
- `X-Content-Type-Options: nosniff`
- `Referrer-Policy`
- `Permissions-Policy`

Missing headers do not always mean compromise, but they often indicate incomplete hardening.

## Enumeration and Forced Browsing
Repeated 401, 403, and 404 responses may indicate:
- Directory brute force
- Content discovery
- Admin endpoint probing
- Poorly segmented public/internal applications

Recommended actions:
- Rate limit repeated denied requests
- Alert on admin path probing
- Disable directory listing
- Remove test or backup paths from production

## Administrative Exposure
Paths such as `/admin`, `/login`, `/manage`, `/console`, `/wp-admin`, `/phpmyadmin`, and `/actuator` should not be publicly exposed without strong controls.

Recommended controls:
- MFA for administrative access
- IP restrictions or VPN-only access
- Short session duration and strong logging
- WAF rules for sensitive paths

## Web Scanning Interpretation
When tools like WhatWeb or Nikto report outdated components, unsafe methods, or missing headers, validate:
- Whether the finding is externally reachable
- Whether the service is intended to be public
- Whether compensating controls already exist
