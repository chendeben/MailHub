# Security Policy

## Supported Versions

Only the latest code on the default branch is currently maintained. Supported version ranges will be documented here after formal releases are published.

## Reporting a Vulnerability

Do not disclose unpatched vulnerabilities in public issues.

Use GitHub Security Advisories to report security issues privately. If advisories are not enabled for the repository, use the security contact published by the maintainer on the repository page.

Please include as much of the following as possible:

- Affected version or commit.
- Reproduction steps.
- Impact assessment.
- Suggested mitigations, if available.

## Sensitive Data

MailHub may handle SMTP passwords, API tokens, DNS API secrets, and TLS private keys. Do not include these values in issues, pull requests, logs, or screenshots.

## Operational Guidance

- Replace the default administrator password and `SESSION_SECRET` in production.
- Keep `.env`, SQLite databases, certificates, and private keys out of Git.
- Scope DNS API tokens to the minimum required permissions.
- Require authentication on public SMTP ports to avoid open relays.
- Follow applicable law, provider policies, and recipient consent requirements when sending mail.
