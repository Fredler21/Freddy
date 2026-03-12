# Incident Response Quick Guide

## Triage Priorities
1. Confirm whether the activity is still ongoing
2. Determine the exposure boundary
3. Preserve high-value evidence
4. Contain without destroying forensic context
5. Eradicate and recover in a controlled order

## For Authentication Attacks
If logs show brute-force behavior:
- Identify targeted accounts
- Check for successful logins following failures
- Review source IP concentration and time window
- Lock or protect exposed accounts
- Harden login controls immediately

## For Exposed Services
If sensitive services are publicly reachable:
- Validate business need
- Restrict exposure quickly
- Rotate credentials if unauthenticated access was possible
- Review logs for prior access and configuration changes

## For Web Enumeration
If logs show forced browsing:
- Identify targeted paths and patterns
- Check for successful responses on sensitive routes
- Search for follow-on admin access or exploit attempts
- Increase logging around auth and privileged actions

## Recovery Notes
- Document what was changed during containment
- Re-scan after remediation
- Compare new findings against prior history
- Update hardening standards from lessons learned
