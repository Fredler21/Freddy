# Vulnerability Intelligence: Missing Security Headers

## Condition
HTTP response headers are missing expected browser hardening controls.

## Why It Matters
Missing headers can increase the blast radius of content injection, clickjacking, MIME confusion, downgrade attacks, and privacy leakage.

## Priority Headers
- `Content-Security-Policy`
- `Strict-Transport-Security`
- `X-Frame-Options`
- `X-Content-Type-Options`
- `Referrer-Policy`
- `Permissions-Policy`

## Recommended Inspection Area
- Reverse proxy config
- Application middleware
- CDN edge policies

## Defensive Actions
- Apply a baseline header policy centrally
- Tune CSP iteratively to avoid breakage
- Add HSTS only after HTTPS is stable
- Validate headers on all public virtual hosts
