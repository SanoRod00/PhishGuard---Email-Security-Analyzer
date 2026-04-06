# PhishGuard - Authenticated Email Security Analyzer

PhishGuard is a protected email-review workspace for suspicious URLs and sender addresses. The app now uses a production-style authentication layer built on `Node.js`, `Express`, `PostgreSQL`, `JWT access tokens`, rotating `refresh tokens` in `httpOnly` cookies, CSRF protection, rate limiting, and email-based verification/reset flows.

## Tech Stack

- Backend: Node.js, Express, PostgreSQL, bcrypt, jsonwebtoken, helmet, cors, express-rate-limit
- Frontend: Vanilla JavaScript, HTML, CSS
- Database: PostgreSQL with SQL migration file
- Tests: Node test runner

## Auth Features

- Registration with email verification
- bcrypt password hashing with 12 rounds
- JWT access tokens with 15 minute expiry
- Refresh tokens with 7 day expiry stored in `httpOnly` cookies
- Refresh-token invalidation on logout and password reset
- Login rate limiting at 5 attempts per 15 minutes
- Password reset via email with 1 hour expiry
- CSRF protection for state-changing requests
- Protected API routes and protected frontend routes
- Automatic token refresh on the client before expiry
- Profile page for authenticated users

## Security Controls

- `helmet` security headers
- Strict CORS allowlist via `FRONTEND_URL`
- HTTPS enforcement in production
- Input validation and sanitization for auth endpoints
- Parameterized PostgreSQL queries
- Failed login and password-reset security logging
- No plain-text password storage
- Refresh tokens kept out of `localStorage`

## Local Setup

1. Copy `.env.example` to `.env`.
2. Choose a storage mode:
   - For quick local development, leave `STORAGE_DRIVER=memory`.
   - For persistent auth data, set `STORAGE_DRIVER=postgres`, configure PostgreSQL, and update `DATABASE_URL`.
3. Set strong values for:
   - `JWT_SECRET`
   - `JWT_REFRESH_SECRET`
4. Configure SMTP credentials if you want real email delivery.
   In development, the app logs verification/reset links when SMTP is not configured or when a local SMTP server is unavailable.
5. Install dependencies:

```bash
npm install
```

6. If you are using PostgreSQL, apply the authentication schema:

```bash
npm run migrate:auth
```

7. Start the server:

```bash
npm start
```

8. Open [http://127.0.0.1:3000/login](http://127.0.0.1:3000/login).

## Route Gating

- Public frontend routes:
  - `/login`
  - `/register`
  - `/forgot-password`
  - `/reset-password`
  - `/verify-email`
- Protected frontend routes:
  - `/`
  - `/app`
  - `/profile`
- Protected API routes return `401` when no valid access token is supplied.

## Auth Flow

1. Request a CSRF token from `GET /api/auth/csrf`.
2. Register with `POST /api/auth/register`.
3. Verify the account from the email link.
4. Login with `POST /api/auth/login`.
5. The frontend stores the short-lived access token in memory and the server stores the refresh token in an `httpOnly` cookie.
6. Before access-token expiry, the frontend calls `POST /api/auth/refresh`.
7. Logout revokes the refresh token and clears the cookie.

## Scan Workflow

1. Sign in.
2. Scan a suspicious link with the protected URL endpoint.
3. Validate the sender email with the protected email endpoint.
4. Save investigation history to the authenticated account.
5. Review analytics and export filtered history.

## Scripts

```bash
npm start
npm run migrate:auth
npm test
```

`npm run migrate:auth` is only needed when `STORAGE_DRIVER=postgres`.

## Database Files

- Migration: `db/migrations/001_auth_schema.sql`
- Migration runner: `scripts/migrate-auth.js`

## API Documentation

See `docs/AUTH_API.md`.

## Deployment

See `docs/DEPLOYMENT.md`.

## Multi-Server Deployment And Load Balancing

This application can be deployed behind a load balancer with:

- `Web01`: application node
- `Web02`: application node
- `Lb01`: HAProxy load balancer

Important: both app nodes must use the same PostgreSQL database in production. Do not use `STORAGE_DRIVER=memory` behind a load balancer, because users, verification tokens, refresh tokens, and history would be different on each server.

### Target architecture

- `Web01` runs the Node.js app on `127.0.0.1:3000`
- `Web02` runs the same Node.js app on `127.0.0.1:3000`
- `Lb01` accepts public HTTP traffic and forwards requests to both app servers
- PostgreSQL stores shared authentication and history data for both app nodes

### 1. Deploy the app to both web servers

Repeat these steps on `Web01` and `Web02`.

Install runtime packages:

```bash
sudo apt update
sudo apt install -y nginx postgresql-client
```

Install Node.js 18+ and then copy the project to the server:

```bash
sudo mkdir -p /opt/phishguard
sudo chown "$USER":"$USER" /opt/phishguard
rsync -av --delete ./ /opt/phishguard/
cd /opt/phishguard
npm ci --omit=dev
```

### 2. Configure the production environment on both web servers

Create `/opt/phishguard/.env` on both `Web01` and `Web02` using `deploy/production.env.example` as the base.

Required production settings:

```env
NODE_ENV=production
HOST=127.0.0.1
PORT=3000
FRONTEND_URL=http://<LB01_PUBLIC_IP_OR_DOMAIN>
STORAGE_DRIVER=postgres
DATABASE_URL=postgres://phishguard:<password>@<postgres_host>:5432/phishguard
JWT_SECRET=<same_secret_on_both_web_servers>
JWT_REFRESH_SECRET=<same_refresh_secret_on_both_web_servers>
EMAIL_FROM=PhishGuard <no-reply@example.com>
SMTP_HOST=<smtp_host>
SMTP_PORT=587
SMTP_USER=<smtp_user>
SMTP_PASS=<smtp_password>
```

The following values must be identical on `Web01` and `Web02`:

- `FRONTEND_URL`
- `DATABASE_URL`
- `JWT_SECRET`
- `JWT_REFRESH_SECRET`
- SMTP settings

### 3. Prepare the shared PostgreSQL database

Create the database once on the PostgreSQL server:

```sql
CREATE USER phishguard WITH PASSWORD 'change_me';
CREATE DATABASE phishguard OWNER phishguard;
```

Run the migration from one deployed app node:

```bash
cd /opt/phishguard
npm run migrate:auth
```

### 4. Run the app with systemd on both web servers

Install the provided service file:

```bash
sudo cp /opt/phishguard/deploy/systemd/phishguard.service /etc/systemd/system/phishguard.service
sudo systemctl daemon-reload
sudo systemctl enable --now phishguard
sudo systemctl status phishguard
```

The service expects:

- app path: `/opt/phishguard`
- env file: `/opt/phishguard/.env`
- runtime user: `www-data`

If needed:

```bash
sudo chown -R www-data:www-data /opt/phishguard
```

### 5. Configure nginx on both web servers

Use the provided nginx config as a local reverse proxy:

```bash
sudo cp /opt/phishguard/deploy/nginx/phishguard.conf /etc/nginx/sites-available/phishguard
sudo ln -sf /etc/nginx/sites-available/phishguard /etc/nginx/sites-enabled/phishguard
sudo nginx -t
sudo systemctl reload nginx
```

On each web server, the nginx config proxies requests to the local Node.js process at `127.0.0.1:3000`.

### 6. Configure HAProxy on Lb01

Copy the HAProxy template and replace the backend IPs with the real private or public IPs of `Web01` and `Web02`:

```bash
sudo cp /path/to/project/deploy/haproxy/haproxy.cfg /etc/haproxy/haproxy.cfg
sudo systemctl restart haproxy
sudo systemctl status haproxy
```

Use a backend section shaped like this:

```haproxy
backend phishguard_backend
    balance roundrobin
    option httpchk GET /health
    http-check expect status 200
    server web01 <WEB01_IP>:3000 check
    server web02 <WEB02_IP>:3000 check
```

If HAProxy is using the repo template directly, the matching starter file is `deploy/haproxy/haproxy.cfg`.

### 7. Verify traffic is balanced correctly

Check the app directly on both web servers:

```bash
curl -i http://<WEB01_IP>:3000/health
curl -i http://<WEB02_IP>:3000/health
```

Check the load balancer:

```bash
curl -i http://<LB01_PUBLIC_IP>/health
```

To verify round-robin distribution, temporarily make each web server return a distinct response header or serve a small identifying value, then call the load balancer multiple times:

```bash
for i in 1 2 3 4 5 6; do curl -s http://<LB01_PUBLIC_IP>/health; echo; done
```

You can also confirm balancing from logs:

```bash
sudo journalctl -u phishguard -f
sudo tail -f /var/log/haproxy.log
```

### 8. Deployment result

When the deployment is correct:

- the application is reachable through `Lb01`
- HAProxy distributes requests between `Web01` and `Web02`
- both app nodes share the same PostgreSQL-backed auth and history data
- email verification and password reset continue to work across both web servers
- users can authenticate successfully even when consecutive requests hit different backend nodes

## Security Checklist

See `SECURITY_CHECKLIST.md`.

## Tests

The automated suite in `tests/auth.test.js` covers auth-critical validation and middleware behavior in a sandbox-safe way:

- password complexity enforcement
- registration payload validation/sanitization
- CSRF rejection behavior
- access-token middleware behavior
- refresh-token hashing behavior

## Project Structure

```text
.
├── db/
│   └── migrations/
├── docs/
├── public/
├── scripts/
├── src/
│   └── repositories/
├── tests/
├── server.js
├── package.json
└── .env.example
```
