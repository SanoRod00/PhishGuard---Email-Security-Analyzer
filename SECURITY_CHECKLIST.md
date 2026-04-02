# Security Audit Checklist

## Authentication

- [x] Passwords hashed with bcrypt at 12 rounds
- [x] Access and refresh token secrets are separate
- [x] Access tokens expire after 15 minutes
- [x] Refresh tokens expire after 7 days
- [x] Refresh tokens stored in `httpOnly` cookies
- [x] Logout revokes refresh tokens
- [x] Password reset revokes refresh tokens
- [x] Email verification required before login

## Request Protection

- [x] CSRF token required for state-changing operations
- [x] Login rate limit set to 5 requests per 15 minutes
- [x] General auth rate limiting enabled
- [x] Protected routes return `401` without a valid bearer token
- [x] Input validation and sanitization applied to auth payloads

## Transport and Headers

- [x] `helmet` enabled
- [x] CORS restricted to `FRONTEND_URL`
- [x] HTTPS enforced in production
- [x] Cookies use `SameSite=Strict`
- [x] Cookies use `Secure` in production

## Data Handling

- [x] Passwords never stored in plain text
- [x] Verification and reset tokens stored as hashes
- [x] SQL queries use parameters
- [x] Refresh tokens are tracked server-side for revocation

## Monitoring

- [x] Failed login attempts logged
- [x] Password reset requests logged
- [x] Unexpected server errors logged without leaking internals to users

## Frontend

- [x] Login page shown first for unauthenticated users
- [x] Protected routes redirect to login when unauthenticated
- [x] Access token stored only in memory
- [x] Automatic token refresh implemented
- [x] 401 responses trigger session recovery or redirect to login
