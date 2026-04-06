#!/bin/bash

#######################################################
# ALL-IN-ONE WEB APPLICATION DEPLOYMENT SCRIPT
# Deploys to Web01, Web02, and configures LB01
# Just run: bash deploy-all.sh
#######################################################

set -e

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

#######################################################
# CONFIGURATION - EDIT THESE VALUES
#######################################################

# Server IPs (from your screenshot)
WEB01_IP="3.91.161.91"
WEB02_IP="172.18.0.3"
LB01_IP="172.18.0.4"
SSH_USER="ubuntu"

# Application Settings - CHANGE THESE
APP_NAME="myapp"              # Your application name
APP_PORT="3000"              # Port your app runs on
APP_TYPE="nodejs"            # Options: nodejs, python, static

# Deployment Method - CHOOSE ONE
# Option 1: Git Repository
GIT_REPO=""                  # Example: "https://github.com/yourusername/yourapp.git"
GIT_BRANCH="main"

# Option 2: Local Files
LOCAL_APP_PATH="./app"       # Path to your app folder (if not using git)

APP_DIR="/var/www/${APP_NAME}"

#######################################################
# DO NOT EDIT BELOW THIS LINE
#######################################################

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_step() {
    echo -e "${BLUE}[STEP]${NC} $1"
}

check_ssh() {
    local host=$1
    if ssh -o ConnectTimeout=5 -o BatchMode=yes ${SSH_USER}@${host} exit &>/dev/null; then
        return 0
    else
        return 1
    fi
}

#######################################################
# Interactive Configuration
#######################################################

configure_app() {
    clear
    echo -e "${BLUE}╔══════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║     Web Application Deployment Script           ║${NC}"
    echo -e "${BLUE}╚══════════════════════════════════════════════════╝${NC}"
    echo ""
    
    read -p "Enter your application name [${APP_NAME}]: " input_name
    APP_NAME=${input_name:-$APP_NAME}
    
    read -p "Enter application port [${APP_PORT}]: " input_port
    APP_PORT=${input_port:-$APP_PORT}
    
    echo ""
    echo "Select application type:"
    echo "1) Node.js"
    echo "2) Python"
    echo "3) Static HTML"
    read -p "Choose (1-3) [1]: " type_choice
    
    case ${type_choice:-1} in
        1) APP_TYPE="nodejs" ;;
        2) APP_TYPE="python" ;;
        3) APP_TYPE="static" ;;
        *) APP_TYPE="nodejs" ;;
    esac
    
    echo ""
    echo "Deployment method:"
    echo "1) From Git repository"
    echo "2) Upload local files"
    read -p "Choose (1-2) [2]: " deploy_choice
    
    if [ "${deploy_choice:-2}" = "1" ]; then
        read -p "Enter Git repository URL: " GIT_REPO
        read -p "Enter branch [main]: " input_branch
        GIT_BRANCH=${input_branch:-main}
    else
        read -p "Enter path to app folder [./app]: " input_path
        LOCAL_APP_PATH=${input_path:-./app}
        GIT_REPO=""
    fi
    
    APP_DIR="/var/www/${APP_NAME}"
    
    echo ""
    log_info "Configuration complete!"
    echo "  App Name: ${APP_NAME}"
    echo "  App Port: ${APP_PORT}"
    echo "  App Type: ${APP_TYPE}"
    if [ -n "$GIT_REPO" ]; then
        echo "  Source: ${GIT_REPO}"
    else
        echo "  Source: ${LOCAL_APP_PATH}"
    fi
    echo ""
    read -p "Press Enter to start deployment..."
}

#######################################################
# Deploy to Web Server
#######################################################

deploy_web_server() {
    local server_ip=$1
    local server_name=$2
    
    log_step "========================================"
    log_step "Deploying to ${server_name} (${server_ip})"
    log_step "========================================"
    
    # Create deployment script
    cat > /tmp/web_deploy_${server_name}.sh << WEBEOF
#!/bin/bash
set -e

echo "Updating system packages..."
sudo apt update -y
sudo DEBIAN_FRONTEND=noninteractive apt upgrade -y

echo "Installing Nginx..."
sudo apt install -y nginx

# Install runtime based on type
if [ "${APP_TYPE}" = "nodejs" ]; then
    echo "Installing Node.js..."
    if ! command -v node &> /dev/null; then
        curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
        sudo apt install -y nodejs
    fi
elif [ "${APP_TYPE}" = "python" ]; then
    echo "Installing Python..."
    sudo apt install -y python3 python3-pip python3-venv
fi

echo "Setting up application directory..."
sudo mkdir -p ${APP_DIR}
sudo chown -R ubuntu:ubuntu ${APP_DIR}

# Deploy application
if [ -n "${GIT_REPO}" ]; then
    echo "Cloning from Git..."
    sudo apt install -y git
    cd ${APP_DIR}
    if [ -d ".git" ]; then
        git pull origin ${GIT_BRANCH}
    else
        git clone -b ${GIT_BRANCH} ${GIT_REPO} .
    fi
fi

# Install dependencies
cd ${APP_DIR}
if [ "${APP_TYPE}" = "nodejs" ] && [ -f "package.json" ]; then
    echo "Installing npm dependencies..."
    npm install --production
elif [ "${APP_TYPE}" = "python" ] && [ -f "requirements.txt" ]; then
    echo "Installing Python dependencies..."
    python3 -m venv venv
    source venv/bin/activate
    pip install -r requirements.txt
fi

# Create systemd service
echo "Creating systemd service..."
sudo tee /etc/systemd/system/${APP_NAME}.service > /dev/null <<EOF
[Unit]
Description=${APP_NAME} Application
After=network.target

[Service]
Type=simple
User=ubuntu
WorkingDirectory=${APP_DIR}
$(if [ "${APP_TYPE}" = "nodejs" ]; then
    echo "ExecStart=/usr/bin/node ${APP_DIR}/server.js"
elif [ "${APP_TYPE}" = "python" ]; then
    echo "ExecStart=${APP_DIR}/venv/bin/python ${APP_DIR}/app.py"
fi)
Restart=always
RestartSec=10
Environment="NODE_ENV=production"
Environment="PORT=${APP_PORT}"

[Install]
WantedBy=multi-user.target
EOF

# Configure Nginx
echo "Configuring Nginx..."
sudo tee /etc/nginx/sites-available/${APP_NAME} > /dev/null <<'NGINXEOF'
server {
    listen 80;
    server_name _;
    
    add_header X-Served-By \$hostname;
    
    location / {
        proxy_pass http://localhost:${APP_PORT};
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host \$host;
        proxy_cache_bypass \$http_upgrade;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }
    
    location /health {
        proxy_pass http://localhost:${APP_PORT}/health;
        access_log off;
    }
}
NGINXEOF

sudo ln -sf /etc/nginx/sites-available/${APP_NAME} /etc/nginx/sites-enabled/
sudo rm -f /etc/nginx/sites-enabled/default
sudo nginx -t
sudo systemctl restart nginx
sudo systemctl enable nginx

# Start application
echo "Starting application..."
sudo systemctl daemon-reload
sudo systemctl enable ${APP_NAME}
sudo systemctl restart ${APP_NAME}

sleep 3
sudo systemctl status ${APP_NAME} --no-pager || true

echo "✓ ${server_name} deployment complete!"
WEBEOF

    # Copy script to server
    log_info "Uploading deployment script to ${server_name}..."
    scp -o StrictHostKeyChecking=no /tmp/web_deploy_${server_name}.sh ${SSH_USER}@${server_ip}:/tmp/
    
    # Upload application files if using local method
    if [ -z "$GIT_REPO" ] && [ -d "$LOCAL_APP_PATH" ]; then
        log_info "Uploading application files to ${server_name}..."
        ssh ${SSH_USER}@${server_ip} "sudo mkdir -p ${APP_DIR} && sudo chown -R ubuntu:ubuntu ${APP_DIR}"
        scp -r ${LOCAL_APP_PATH}/* ${SSH_USER}@${server_ip}:${APP_DIR}/
    fi
    
    # Execute deployment
    log_info "Executing deployment on ${server_name}..."
    ssh ${SSH_USER}@${server_ip} "chmod +x /tmp/web_deploy_${server_name}.sh && /tmp/web_deploy_${server_name}.sh"
    
    # Test
    sleep 2
    if curl -f -s -o /dev/null http://${server_ip}; then
        log_info "✓ ${server_name} is responding"
    else
        log_warn "⚠ ${server_name} might have issues"
    fi
    
    echo ""
}

#######################################################
# Configure Load Balancer
#######################################################

configure_load_balancer() {
    log_step "========================================"
    log_step "Configuring Load Balancer (${LB01_IP})"
    log_step "========================================"
    
    cat > /tmp/lb_deploy.sh << LBEOF
#!/bin/bash
set -e

echo "Updating system..."
sudo apt update -y
sudo DEBIAN_FRONTEND=noninteractive apt upgrade -y

echo "Installing Nginx..."
sudo apt install -y nginx

echo "Configuring load balancer..."
sudo tee /etc/nginx/sites-available/load-balancer > /dev/null <<'NGINXLB'
upstream backend_servers {
    server ${WEB01_IP}:80 max_fails=3 fail_timeout=30s;
    server ${WEB02_IP}:80 max_fails=3 fail_timeout=30s;
    keepalive 32;
}

server {
    listen 80;
    server_name _;
    
    access_log /var/log/nginx/load-balancer-access.log;
    error_log /var/log/nginx/load-balancer-error.log;
    
    location / {
        proxy_pass http://backend_servers;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
        
        proxy_http_version 1.1;
        proxy_set_header Connection "";
    }
    
    location /health {
        proxy_pass http://backend_servers/health;
        access_log off;
    }
}
NGINXLB

sudo ln -sf /etc/nginx/sites-available/load-balancer /etc/nginx/sites-enabled/
sudo rm -f /etc/nginx/sites-enabled/default
sudo nginx -t
sudo systemctl restart nginx
sudo systemctl enable nginx

echo "✓ Load balancer configured!"
LBEOF

    log_info "Uploading load balancer configuration..."
    scp -o StrictHostKeyChecking=no /tmp/lb_deploy.sh ${SSH_USER}@${LB01_IP}:/tmp/
    
    log_info "Configuring load balancer..."
    ssh ${SSH_USER}@${LB01_IP} "chmod +x /tmp/lb_deploy.sh && /tmp/lb_deploy.sh"
    
    sleep 2
    if curl -f -s -o /dev/null http://${LB01_IP}; then
        log_info "✓ Load balancer is responding"
    else
        log_warn "⚠ Load balancer might have issues"
    fi
    
    echo ""
}

#######################################################
# Test Deployment
#######################################################

test_deployment() {
    log_step "========================================"
    log_step "Testing Load Balancing"
    log_step "========================================"
    
    log_info "Sending 10 test requests..."
    for i in {1..10}; do
        server=$(curl -s -I http://${LB01_IP} 2>/dev/null | grep -i "X-Served-By" | cut -d: -f2 | tr -d ' \r')
        echo "Request $i: ${server:-Load Balancer}"
        sleep 0.3
    done
    
    echo ""
}

#######################################################
# Main Execution
#######################################################

main() {
    # Interactive configuration
    configure_app
    
    clear
    log_step "========================================"
    log_step "Starting Deployment"
    log_step "========================================"
    echo ""
    
    # Check SSH connections
    log_info "Checking SSH connections..."
    
    if ! check_ssh ${WEB01_IP}; then
        log_error "Cannot connect to Web01 (${WEB01_IP})"
        log_info "Run: ssh-copy-id ${SSH_USER}@${WEB01_IP}"
        exit 1
    fi
    log_info "✓ Web01 connected"
    
    if ! check_ssh ${WEB02_IP}; then
        log_error "Cannot connect to Web02 (${WEB02_IP})"
        log_info "Run: ssh-copy-id ${SSH_USER}@${WEB02_IP}"
        exit 1
    fi
    log_info "✓ Web02 connected"
    
    if ! check_ssh ${LB01_IP}; then
        log_error "Cannot connect to LB01 (${LB01_IP})"
        log_info "Run: ssh-copy-id ${SSH_USER}@${LB01_IP}"
        exit 1
    fi
    log_info "✓ LB01 connected"
    
    echo ""
    
    # Deploy
    deploy_web_server ${WEB01_IP} "Web01"
    deploy_web_server ${WEB02_IP} "Web02"
    configure_load_balancer
    test_deployment
    
    # Summary
    log_step "========================================"
    log_step "Deployment Complete!"
    log_step "========================================"
    echo ""
    log_info "🎉 Your application is now live!"
    echo ""
    echo "  Load Balancer: http://${LB01_IP}"
    echo "  Web01 Direct:  http://${WEB01_IP}"
    echo "  Web02 Direct:  http://${WEB02_IP}"
    echo ""
    log_info "Traffic is being distributed across both servers"
    echo ""
}

main
