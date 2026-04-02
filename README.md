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
2. Configure PostgreSQL and update `DATABASE_URL`.
3. Set strong values for:
   - `JWT_SECRET`
   - `JWT_REFRESH_SECRET`
4. Configure SMTP credentials if you want real email delivery.
   In development, the app logs verification/reset links when SMTP is not configured.
5. Install dependencies:

```bash
npm install
```

6. Apply the authentication schema:

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

## Database Files

- Migration: `db/migrations/001_auth_schema.sql`
- Migration runner: `scripts/migrate-auth.js`

## API Documentation

See `docs/AUTH_API.md`.

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
