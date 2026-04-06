#!/bin/bash
set -e

# Colors
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'

# Config
WEB01_IP="3.91.161.91"
WEB02_IP="172.18.0.3"
LB01_IP="172.18.0.4"
SSH_USER="ubuntu"

log() { echo -e "${GREEN}[INFO]${NC} $1"; }

# Configure
read -p "App name [myapp]: " APP_NAME
APP_NAME=${APP_NAME:-myapp}
read -p "App port [3000]: " APP_PORT
APP_PORT=${APP_PORT:-3000}
read -p "App path [./]: " APP_PATH
APP_PATH=${APP_PATH:-.}

log "Deploying to Web01..."
ssh ${SSH_USER}@${WEB01_IP} "sudo apt update && sudo apt install -y nginx nodejs npm && \
  sudo mkdir -p /var/www/${APP_NAME} && sudo chown ubuntu:ubuntu /var/www/${APP_NAME}"
scp -r ${APP_PATH}/* ${SSH_USER}@${WEB01_IP}:/var/www/${APP_NAME}/
ssh ${SSH_USER}@${WEB01_IP} "cd /var/www/${APP_NAME} && npm install"

# Create service on Web01
ssh ${SSH_USER}@${WEB01_IP} "sudo tee /etc/systemd/system/${APP_NAME}.service > /dev/null << EOF
[Unit]
Description=${APP_NAME}
[Service]
WorkingDirectory=/var/www/${APP_NAME}
ExecStart=/usr/bin/node /var/www/${APP_NAME}/server.js
Restart=always
Environment=PORT=${APP_PORT}
[Install]
WantedBy=multi-user.target
EOF
sudo systemctl daemon-reload && sudo systemctl enable ${APP_NAME} && sudo systemctl restart ${APP_NAME}"

# Configure Nginx on Web01
ssh ${SSH_USER}@${WEB01_IP} "sudo tee /etc/nginx/sites-available/${APP_NAME} > /dev/null << 'EOF'
server {
  listen 80;
  add_header X-Served-By \$hostname;
  location / {
    proxy_pass http://localhost:${APP_PORT};
    proxy_set_header Host \$host;
  }
}
EOF
sudo ln -sf /etc/nginx/sites-available/${APP_NAME} /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl restart nginx"

log "Deploying to Web02 via jump host..."
ssh -J ${SSH_USER}@${WEB01_IP} ${SSH_USER}@${WEB02_IP} "sudo apt update && sudo apt install -y nginx nodejs npm && \
  sudo mkdir -p /var/www/${APP_NAME} && sudo chown ubuntu:ubuntu /var/www/${APP_NAME}"
scp -o ProxyJump=${SSH_USER}@${WEB01_IP} -r ${APP_PATH}/* ${SSH_USER}@${WEB02_IP}:/var/www/${APP_NAME}/
ssh -J ${SSH_USER}@${WEB01_IP} ${SSH_USER}@${WEB02_IP} "cd /var/www/${APP_NAME} && npm install"

ssh -J ${SSH_USER}@${WEB01_IP} ${SSH_USER}@${WEB02_IP} "sudo tee /etc/systemd/system/${APP_NAME}.service > /dev/null << EOF
[Unit]
Description=${APP_NAME}
[Service]
WorkingDirectory=/var/www/${APP_NAME}
ExecStart=/usr/bin/node /var/www/${APP_NAME}/server.js
Restart=always
Environment=PORT=${APP_PORT}
[Install]
WantedBy=multi-user.target
EOF
sudo systemctl daemon-reload && sudo systemctl enable ${APP_NAME} && sudo systemctl restart ${APP_NAME}"

ssh -J ${SSH_USER}@${WEB01_IP} ${SSH_USER}@${WEB02_IP} "sudo tee /etc/nginx/sites-available/${APP_NAME} > /dev/null << 'EOF'
server {
  listen 80;
  add_header X-Served-By \$hostname;
  location / {
    proxy_pass http://localhost:${APP_PORT};
    proxy_set_header Host \$host;
  }
}
EOF
sudo ln -sf /etc/nginx/sites-available/${APP_NAME} /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl restart nginx"

log "Configuring load balancer..."
ssh -J ${SSH_USER}@${WEB01_IP} ${SSH_USER}@${LB01_IP} "sudo apt update && sudo apt install -y nginx"
ssh -J ${SSH_USER}@${WEB01_IP} ${SSH_USER}@${LB01_IP} "sudo tee /etc/nginx/sites-available/lb > /dev/null << 'EOF'
upstream backend {
  server ${WEB01_IP}:80;
  server ${WEB02_IP}:80;
}
server {
  listen 80;
  location / { proxy_pass http://backend; }
}
EOF
sudo ln -sf /etc/nginx/sites-available/lb /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl restart nginx"

log "✓ Deployment complete! Access at http://${WEB01_IP}"
