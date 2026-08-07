# Security Policy

Occludra (AI Security Gateway) is a security product. We take vulnerability reports seriously.

## Reporting a Vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

Instead, email us at **security@occludra.ai** with:

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if you have one)

We will acknowledge your report within **48 hours** and aim to provide a fix or mitigation plan within **7 days**.

## Scope

The following are in scope for security reports:

- Authentication bypass in the gateway API
- DLP scan bypass (PII or secrets passing through undetected)
- Prompt injection patterns that evade detection
- Information disclosure via logs or error messages
- Container escape or privilege escalation in Docker setup

## Recognition

We credit all confirmed vulnerability reporters in our release notes (unless you prefer to remain anonymous).

## Supported Versions

| Version | Supported |
|---|---|
| Latest release | Yes |
| Older releases | Best effort |

## Security Best Practices

When deploying Occludra:

- Always set a strong `AISG_API_KEY` — never deploy with the default key
- Run behind a reverse proxy (nginx, Caddy, Traefik) with TLS in production
- Keep Docker images updated
- Review `gateway.yaml` DLP entity list for your compliance requirements
