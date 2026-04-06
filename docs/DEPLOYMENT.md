# Deployment Guide

This project includes a Node.js app, PostgreSQL-backed auth storage, and reverse-proxy templates for `systemd`, `nginx`, and `haproxy`.

## Production assumptions

- Domain: `phishguard.example.com`
- App path: `/opt/phishguard`
- Node app listens on `127.0.0.1:3000`
- Reverse proxy terminates TLS and forwards traffic to the app
- Production storage uses PostgreSQL
- Production email uses real SMTP credentials

## 1. Prepare the server

Install the required packages:

```bash
sudo apt update
sudo apt install -y nginx postgresql postgresql-contrib
```

Install Node.js 18+ before continuing.

## 2. Deploy the app

Copy the project to the target host:

```bash
sudo mkdir -p /opt/phishguard
sudo chown "$USER":"$USER" /opt/phishguard
rsync -av --delete ./ /opt/phishguard/
cd /opt/phishguard
npm ci --omit=dev
```

## 3. Create the production environment file

Use [production.env.example](/home/sanorod/PhishGuard---Email-Security-Analyzer/deploy/production.env.example) as the starting point:

```bash
cp deploy/production.env.example .env
```

Required production values:

- `NODE_ENV=production`
- `FRONTEND_URL=https://your-domain`
- `STORAGE_DRIVER=postgres`
- `DATABASE_URL=postgres://...`
- `JWT_SECRET` and `JWT_REFRESH_SECRET`
- `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASS`

## 4. Create the PostgreSQL database

Create a database and user:

```bash
sudo -u postgres psql
```

Inside `psql`:

```sql
CREATE USER phishguard WITH PASSWORD 'change_me';
CREATE DATABASE phishguard OWNER phishguard;
\q
```

Apply the auth schema:

```bash
npm run migrate:auth
```

## 5. Install the systemd service

Copy the service template:

```bash
sudo cp deploy/systemd/phishguard.service /etc/systemd/system/phishguard.service
```

The service expects:

- app code in `/opt/phishguard`
- environment file at `/opt/phishguard/.env`
- runtime user `www-data`

Ensure the files are readable by that user, then enable the service:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now phishguard
sudo systemctl status phishguard
```

## 6. Configure nginx

Copy the nginx template:

```bash
sudo cp deploy/nginx/phishguard.conf /etc/nginx/sites-available/phishguard
sudo ln -s /etc/nginx/sites-available/phishguard /etc/nginx/sites-enabled/phishguard
```

Before reloading nginx:

- replace `phishguard.example.com` with your real domain
- obtain a TLS certificate and update the server block to use HTTPS

Validate and reload:

```bash
sudo nginx -t
sudo systemctl reload nginx
```

## 7. Add TLS

With Certbot on Ubuntu:

```bash
sudo apt install -y certbot python3-certbot-nginx
sudo certbot --nginx -d phishguard.example.com
```

After TLS is configured:

- keep `FRONTEND_URL` set to the `https://` origin
- leave `NODE_ENV=production`
- confirm cookies are marked `Secure`

## 8. Verify the deployment

Check health:

```bash
curl -i http://127.0.0.1:3000/health
curl -i https://phishguard.example.com/health
```

Check logs:

```bash
sudo journalctl -u phishguard -f
```

## 9. Optional HAProxy mode

If you want multiple app instances behind HAProxy, use [haproxy.cfg](/home/sanorod/PhishGuard---Email-Security-Analyzer/deploy/haproxy/haproxy.cfg) as the starting point and point the backend servers at your app nodes.

## Deployment notes

- Do not use `STORAGE_DRIVER=memory` in production.
- Do not leave placeholder JWT or SMTP secrets in `.env`.
- Registration and password reset depend on working SMTP in production.
- The nginx template in this repo is HTTP-only by default; add TLS before exposing the service publicly.
