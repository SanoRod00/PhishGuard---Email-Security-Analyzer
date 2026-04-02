# Auth API

## Public Endpoints

### `GET /api/auth/csrf`

Returns a CSRF token and sets the CSRF cookie used for state-changing requests.

### `POST /api/auth/register`

Request body:

```json
{
  "firstName": "Taylor",
  "lastName": "Analyst",
  "email": "taylor@example.com",
  "password": "Strong!Pass1"
}
```

Response:

```json
{
  "message": "Registration successful. Check your email to verify your account."
}
```

### `POST /api/auth/verify-email`

Request body:

```json
{
  "token": "verification-token"
}
```

### `POST /api/auth/login`

Request body:

```json
{
  "email": "taylor@example.com",
  "password": "Strong!Pass1",
  "rememberMe": true
}
```

Response:

```json
{
  "accessToken": "jwt",
  "accessTokenExpiresAt": "2026-01-01T00:15:00.000Z",
  "csrfToken": "csrf-token",
  "user": {
    "id": "uuid",
    "email": "taylor@example.com",
    "firstName": "Taylor",
    "lastName": "Analyst",
    "isVerified": true,
    "createdAt": "2026-01-01T00:00:00.000Z",
    "updatedAt": "2026-01-01T00:00:00.000Z"
  }
}
```

### `POST /api/auth/refresh`

Uses the refresh-token cookie plus `X-CSRF-Token` to rotate the session and return a new access token.

### `POST /api/auth/logout`

Revokes the refresh token and clears the cookie.

### `POST /api/auth/forgot-password`

Request body:

```json
{
  "email": "taylor@example.com"
}
```

Returns a generic response so email enumeration is not exposed.

### `POST /api/auth/reset-password`

Request body:

```json
{
  "token": "reset-token",
  "password": "NewStrong!Pass1"
}
```

## Protected Endpoints

All protected endpoints require:

- `Authorization: Bearer <access-token>`
- `X-CSRF-Token` for state-changing requests

### `GET /api/profile`

Returns authenticated user info and saved settings.

### `GET /api/bootstrap`

Returns:

- user
- settings
- history

### `PUT /api/settings`

Request body:

```json
{
  "displayName": "Case Desk",
  "defaultThreatFilter": "suspicious",
  "timelineLength": 8,
  "dashboardRangeDays": 30,
  "disposableOnly": true
}
```

### `POST /api/history`

Request body:

```json
{
  "record": {
    "id": "uuid",
    "type": "email",
    "target": "alerts@example.com",
    "domain": "example.com",
    "threatLevel": "dangerous",
    "threatScore": 92,
    "disposable": false,
    "summary": "Synthetic example",
    "timestamp": "2026-01-01T00:00:00.000Z"
  }
}
```

### `DELETE /api/history`

Clears stored investigation history for the authenticated account.

### `POST /api/scan/url`

```json
{
  "url": "https://suspicious.example"
}
```

### `POST /api/scan/email`

```json
{
  "email": "alerts@example.com"
}
```

### `POST /api/scan/combined`

```json
{
  "url": "https://suspicious.example",
  "email": "alerts@example.com"
}
```

## Error Model

All API errors return:

```json
{
  "error": "User-friendly message",
  "details": {}
}
```
