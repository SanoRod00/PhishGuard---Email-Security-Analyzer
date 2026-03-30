# PhishGuard - Email Security Analyzer

PhishGuard helps people inspect suspicious links and sender email addresses before they click, reply, or download anything. It combines URL reputation checks, disposable inbox detection, optional deliverability validation, and a browser-local investigation history so users can make safer decisions quickly.

## 1. What is PhishGuard?

Phishing emails are designed to look urgent, familiar, and harmless long enough to steal credentials, money, or trust. PhishGuard gives individual users, small teams, students, and older adults a practical pre-click checkpoint:

- Scan a suspicious URL against VirusTotal.
- Validate whether a sender address is disposable or risky.
- Save scan metadata in local browser storage for follow-up review.
- Export filtered history as CSV for incident tracking or reporting.

## 2. Why It Matters

Phishing and business email compromise continue to cause billions of dollars in losses globally each year. The most common failure pattern is not malware sophistication; it is a user being forced to judge a message too quickly. PhishGuard slows that moment down and adds visible evidence before action.

## 3. How To Use

### Run locally

1. Copy `.env.example` to `.env`.
2. Add your `VIRUSTOTAL_API_KEY`.
3. Optionally add your `ABSTRACT_API_KEY` for deliverability scoring.
4. Start the app:

```bash
npm start
```

5. Open `http://localhost:3000`.

### Scan workflow

1. Paste a suspicious link into the URL scanner and select `Scan URL`.
2. Enter the sender email into the validator and select `Validate sender`.
3. If you have both values, use `Run combined scan` for a unified risk snapshot.
4. Review the gauge, vendor verdicts, sender flags, and timeline.
5. Use the history dashboard to sort, search, filter, and export CSV results.

### Recommended screenshots for documentation

- Hero section with the tagline `Scan before you click`
- URL scan result with vendor detection table expanded
- Sender validator result showing trust score and flags
- Filtered history dashboard with CSV export button visible

## 4. API Credits

- VirusTotal API: https://docs.virustotal.com/
- Disify API: https://www.disify.com/
- Abstract Email Validation API: https://www.abstractapi.com/email-verification-validation-api

## 5. Deployment Guide

### Environment variables

Set these on both `Web01` and `Web02`:

```bash
HOST=127.0.0.1
PORT=3000
VIRUSTOTAL_API_KEY=your_key_here
ABSTRACT_API_KEY=optional_key_here
```

### Start the service

```bash
npm start
```

For a production service example, see:

- `deploy/systemd/phishguard.service`
- `deploy/nginx/phishguard.conf`
- `deploy/haproxy/haproxy.cfg`

### Health check

The app exposes:

```text
GET /health
```

It returns `200 OK` with a JSON status payload and is suitable for load balancer health checks.

### Load balancer notes

- Run the same build on `Web01` and `Web02`.
- Keep identical `.env` values on both application servers.
- Route traffic only to healthy nodes using `/health`.
- Terminate TLS at the proxy or load balancer and keep upstream traffic on a trusted private network.

## 6. Privacy Policy

- PhishGuard does not store email contents on the server.
- API keys remain in `.env` and must never be committed to Git.
- Scan history is stored only in the user browser via `localStorage`.
- Exported CSV files are created client-side when the user requests them.
- All upstream integrations are HTTPS endpoints.

## Project Structure

```text
.
├── public/
│   ├── app.js
│   ├── index.html
│   └── styles.css
├── deploy/
│   ├── haproxy/
│   ├── nginx/
│   └── systemd/
├── server.js
├── .env.example
└── package.json
```
