# Aegis Login

A small, dependency-free login system built with Node.js using only built-in
modules. It includes custom authentication, server-side sessions, CSRF
protection, rate limiting, and hardened security headers.

See [DOCUMENTATION.html](./DOCUMENTATION.html) for the full API and database
reference.

## Features

- **Custom auth**: Username/password registration and login without external auth libraries
- **Secure passwords**: `scrypt` with fixed N/r/p parameters, 16-byte salts, and constant-time comparison
- **Server-side sessions**: Opaque tokens hashed with SHA-256, stored in SQLite, with HttpOnly and SameSite=Strict cookies
- **CSRF protection**: Per-session CSRF tokens validated on every state-changing JSON request
- **Rate limiting**: Sliding-window limits for logins (by IP and account), registrations, and session creation
- **Security headers**: CSP, HSTS (when secure), COOP, CORP, Permissions-Policy, Referrer-Policy, X-Content-Type-Options, and X-Frame-Options
- **Request hardening**: Origin and Fetch Metadata checks, body size limits, method restrictions, input validation, and request timeouts

## Requirements

- Node.js **24 or newer** (uses the built-in `node:sqlite` module)
- No third-party npm dependencies

## Getting Started

```bash
git clone https://github.com/mukitkhan699/aegis.git
cd aegis
cp .env.example .env
npm start
```

Open <http://127.0.0.1:3000> and create an account. The SQLite database is
created automatically in `data/` on first run.

You can also run the server directly:

```bash
node server.js
```

Note: `npm start` loads `.env` automatically; `node server.js` only uses
environment variables exported in your shell.

## Configuration

| Variable | Default | Description |
| --- | --- | --- |
| `PORT` | `3000` | Server listening port |
| `HOST` | `127.0.0.1` | Server listening host (`0.0.0.0` for external access) |
| `DATABASE_PATH` | `./data/auth.db` | Path to the SQLite database file |
| `TRUST_PROXY` | unset | Set to `1` when behind a reverse proxy to trust X-Forwarded headers |
| `COOKIE_SECURE` | auto | `true` or `false` to override secure-cookie auto-detection |

Example:

```bash
PORT=8080 HOST=0.0.0.0 TRUST_PROXY=1 COOKIE_SECURE=true npm start
```

## Endpoints

| Method | Path | Description |
| --- | --- | --- |
| `GET` | `/` | Login UI |
| `GET` | `/api/session` | Current session (creates an anonymous session if none exists) |
| `POST` | `/api/register` | Create an account (JSON + CSRF) |
| `POST` | `/api/login` | Sign in (JSON + CSRF) |
| `POST` | `/api/logout` | Sign out (JSON + CSRF) |

## Project Structure

```text
.
├── server.js            # HTTP server, auth, sessions, and security logic
├── public/              # Static login UI (HTML, CSS, JS, favicon)
├── DOCUMENTATION.html   # Detailed documentation
├── .env.example         # Example environment configuration
└── package.json
```

## Deployment Notes

- Run behind a reverse proxy with TLS in production.
- Set `TRUST_PROXY=1` only if the proxy correctly sets `X-Forwarded-*` headers.
- Set `COOKIE_SECURE=true` when serving over HTTPS.
- Back up the SQLite database in `data/`; it contains password hashes and session records.
- The `data/` directory, `.env`, and database files are excluded from version control via `.gitignore`.

## Security Disclaimer

This project is intended as a compact, self-hosted example of authentication
hardening. It has not undergone an independent security audit. Review and test
it for your own threat model before using it in production.

## License

[MIT](./LICENSE)
