# MailHub

MailHub is a Dockerized, multi-user outbound mail control panel with an SMTP Submission service and an HTTP sending API. It is designed for teams that want to self-host outbound email infrastructure with domain verification, DKIM signing, DNS guidance, SMTP credential management, outbound SMTP relay management, and API tokens.

## Demo

- **Live demo:** [https://mail-send.ss5.xyz](https://mail-send.ss5.xyz)
- **Source:** [github.com/chendeben/MailHub](https://github.com/chendeben/MailHub)

## Features

- Multi-user accounts with isolated domains, SMTP credentials, DNS API credentials, API tokens, outbound SMTP relays, and sending logs.
- DNS record generation for domain verification TXT, DKIM, SPF, DMARC, sending-host A records, and PTR guidance.
- Basic DNS write support for Cloudflare, Aliyun DNS, and Tencent DNSPod.
- Public DNS checks for SPF, DKIM, DMARC, PTR, and sending-host A records.
- DKIM signing per sending domain before messages enter the outbound delivery path.
- SMTP Submission and HTTP sending API.
- User-managed outbound SMTP relays, including per-request, per-domain, user-default, and global fallback routing.
- React + Ant Design administration interface.

## Tech Stack

- Node.js ESM, requiring Node.js `>=24.0.0`
- SQLite persistence
- React、Vite、Ant Design
- Docker Compose + Postfix
- Node.js built-in `node:test`

## Quick Start

```bash
cp .env.example .env
npm install
npm test
npm run build
docker compose up -d --build
docker compose logs -f app postfix
```

By default, the admin console is exposed on `127.0.0.1:3025` through `APP_PORT`. In production, put MailHub behind Nginx, Caddy, or another HTTPS reverse proxy.

Before the first production start, update the default administrator password, `SESSION_SECRET`, SMTP settings, and domain/IP settings in `.env`.

## Configuration

Create `.env` from `.env.example`. Common settings include:

- `APP_BASE_URL`: public URL for the admin console and sending API.
- `MAIL_HOSTNAME`: outbound HELO, Postfix `myhostname`, and the sending hostname used in DNS guidance.
- `SENDING_IP`: public IP address of the sending server.
- `SESSION_SECRET`: random secret for sessions and server-side encryption; use a strong random value in production.
- `SUBMISSION_HOST`, `SUBMISSION_PORTS`: public SMTP Submission connection details.
- `SUBMISSION_TLS_CERT`, `SUBMISSION_TLS_KEY`: TLS certificate paths. Keep certificate files under local `certs/` and do not commit them.
- `DEFAULT_SPF_MECHANISMS`: third-party SPF mechanisms that should be preserved, such as transactional email provider includes.
- `SEND_REQUIRES_VERIFIED`: whether sending requires the domain DNS checks to pass first.

## SMTP Submission

MailHub exposes an SMTP Submission service. All sending ports require SMTP AUTH; unauthenticated requests are not relayed.

```txt
Host: configured by SUBMISSION_HOST, for example smtp.mailhub.example.com
Port 25:   SMTP + STARTTLS + AUTH
Port 587:  SMTP Submission + STARTTLS + AUTH
Port 465:  SMTPS implicit TLS + AUTH
Port 2525: SMTP + STARTTLS + AUTH
Username: configured by each user on the SMTP Credentials page
Password: configured by each user on the SMTP Credentials page
```

SMTP Submission passwords are stored both as a hash and as server-side encrypted ciphertext. The hash is used for authentication; the encrypted value lets the account owner copy the password from the UI. Legacy hash-only passwords cannot be recovered and must be reset before they can be copied.

## Outbound SMTP Relays

Users can configure multiple outbound SMTP relays from the SMTP page. Relay passwords are encrypted at rest and are shown only when the owner opens the relay editor; relay lists never include plaintext passwords.

When MailHub sends a message, it chooses the upstream relay in this order:

1. `smtpRelayId` explicitly provided in the API request or test-send form.
2. The default outbound SMTP relay bound to the sending domain.
3. The user's default outbound SMTP relay.
4. The global SMTP fallback configured in `.env`.

This makes it possible to route different domains or individual sends through different providers while keeping a safe global fallback.

## Sending API

Each user can create sending API tokens in the console. A token is shown in full only once at creation time; later lists show only the token prefix.

```bash
curl -X POST https://mailhub.example.com/api/send \
  -H "Authorization: Bearer <USER_API_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{
    "from": "noreply@example.com",
    "to": "user@example.net",
    "subject": "Hello from MailHub",
    "text": "Signed with DKIM and queued by MailHub."
  }'
```

The `From` domain must belong to the user that owns the token. The `.env` `API_TOKEN` is kept only as a legacy admin-compatible token; new integrations should use user-level tokens created in the UI.

To select a specific outbound relay for one request, include `smtpRelayId`:

```json
{
  "from": "noreply@example.com",
  "to": "user@example.net",
  "subject": "Hello from MailHub",
  "text": "Signed with DKIM and queued by MailHub.",
  "smtpRelayId": 12
}
```

## One-Click DNS API

Users can save provider credentials on the DNS API page:

- Cloudflare: API Token, preferably scoped to DNS Edit on the target zone; Zone ID is optional.
- Aliyun DNS: AccessKeyId and AccessKeySecret.
- Tencent DNSPod: SecretId and SecretKey.

After a domain is bound to a DNS credential, the one-click DNS action writes or updates verification TXT, DKIM TXT, SPF TXT, DMARC TXT, and sending-host A records. PTR reverse DNS is checked and reported only; it is usually configured at the cloud server or IP provider.

## Deployment

Recommended production setup:

1. Deploy the repository to a server directory, for example `/opt/mailhub`.
2. Create `.env` from `.env.example` and set real domains, IPs, certificate paths, and strong random secrets.
3. Put TLS certificates under local `certs/` and keep private keys out of Git.
4. Run `docker compose up -d --build`.
5. Proxy HTTPS traffic to `127.0.0.1:${APP_PORT}`.
6. Open the required SMTP ports in both cloud and system firewalls.

The optional remote deploy script requires an explicit SSH target and directory:

```bash
MAILHUB_DEPLOY_REMOTE=deploy@example.com \
MAILHUB_DEPLOY_DIR=/opt/mailhub \
MAILHUB_DEPLOY_BRANCH=main \
npm run deploy:remote
```

The script requires local `HEAD` to already be pushed to the matching remote branch. It then runs `git pull --ff-only` and `docker compose up -d --build` in the target directory. If the remote working tree is dirty, the script stops; set `MAILHUB_DEPLOY_STASH_REMOTE=1` only when you intentionally want to stash the remote worktree before deployment.

## Testing

```bash
npm test
npm run build
```

Tests cover database migrations, multi-user isolation, SMTP credentials, outbound SMTP relays, API tokens, DNS provider logic, DKIM, delivery log parsing, and frontend model logic.

## Security Checklist

- Do not commit `.env`, SQLite databases, API tokens, SMTP passwords, DNS API secrets, certificate private keys, or real production certificates.
- Replace default administrator credentials and set a sufficiently strong `SESSION_SECRET`.
- Before production sending, verify SPF, DKIM, DMARC, PTR, and sending-host A records.
- Confirm that outbound TCP 25 is not blocked by the cloud provider.
- Confirm that inbound `25/465/587/2525` are open in cloud and system firewalls.
- Warm up new IP addresses gradually instead of sending large bursts immediately.
- Follow applicable law, provider policies, and recipient consent requirements. Do not use MailHub to send spam.

## Contributing

Issues and pull requests are welcome. Before contributing, read [CONTRIBUTING.md](CONTRIBUTING.md), [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md), and [SECURITY.md](SECURITY.md).

## License

MailHub is licensed under the MIT License. See [LICENSE](LICENSE).
