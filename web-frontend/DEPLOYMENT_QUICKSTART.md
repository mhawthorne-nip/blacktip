# Production Deployment Quick Reference

Quick commands for deploying Blacktip web frontend to production on a fresh Ubuntu server.

## Prerequisites
- **Fresh Ubuntu 22.04 or 24.04 LTS server**
- **Domain**: app.niceshark.com (DNS configured)
- **Root/sudo access**

## Fresh Ubuntu Setup

### 1. Update System & Install Essentials
```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y git curl wget build-essential python3 python3-pip \
    python3-venv nmap net-tools iproute2 dnsutils nginx \
    certbot python3-certbot-nginx ufw
```

### 2. Configure Firewall
```bash
sudo ufw allow ssh
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw --force enable
```

### 3. Set Network Capabilities
```bash
# For Python 3.10 (Ubuntu 22.04)
sudo setcap cap_net_raw,cap_net_admin=eip /usr/bin/python3.10
# For Python 3.12 (Ubuntu 24.04)
sudo setcap cap_net_raw,cap_net_admin=eip /usr/bin/python3.12
```

## Install Blacktip

### 1. Clone Repository
```bash
sudo mkdir -p /opt/blacktip
sudo chown $USER:$USER /opt/blacktip
cd /opt
git clone https://github.com/mhawthorne-nip/blacktip.git
cd blacktip
```

### 2. Install Backend
```bash
sudo pip3 install -r requirements.txt
sudo pip3 install -e .
```

### 3. Create Directories
```bash
sudo mkdir -p /var/lib/blacktip /var/log/blacktip /run/blacktip
sudo chmod 755 /var/lib/blacktip /var/log/blacktip /run/blacktip
```

## System User Setup
## System User Setup

```bash
sudo groupadd --system blacktip
sudo useradd --system --no-create-home --shell /bin/false --gid blacktip blacktip
sudo chown -R blacktip:blacktip /var/log/blacktip /run/blacktip
sudo chown root:blacktip /var/lib/blacktip
### 1. Install Python Dependencies
```bash
cd /opt/blacktip/web-frontend
sudo pip3 install -r requirements.txt
```

### 2. Install Python Dependencies
```bash
cd /opt/blacktip/web-frontend
sudo pip3 install -r requirements.txt
```

### 2. Configure Environment
```bash
cp .env.example .env
SECRET_KEY=$(python3 -c 'import os; print(os.urandom(24).hex())')
sed -i "s/CHANGE_THIS_TO_A_RANDOM_SECRET_KEY/$SECRET_KEY/" .env
sudo chmod 600 .env
sudo chown blacktip:blacktip .env
```

## Nginx & SSL Setup

### 1. Temporary HTTP Config
### 6. Temporary HTTP-Only Config (for Let's Encrypt)
```bash
sudo tee /etc/nginx/sites-available/blacktip > /dev/null <<'EOF'
### 1. Temporary HTTP Config
```bash
sudo mkdir -p /var/www/certbot
sudo tee /etc/nginx/sites-available/blacktip > /dev/null <<'EOF'
server {
    listen 80;
    listen [::]:80;
    server_name app.niceshark.com;
    location /.well-known/acme-challenge/ {
        root /var/www/certbot;
        allow all;
    }
    location / {
        return 200 "Ready for HTTPS\n";
        add_header Content-Type text/plain;
    }
}
EOF

sudo ln -s /etc/nginx/sites-available/blacktip /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
```

### 2. Obtain SSL Certificate
```bash
sudo certbot certonly \
    --webroot \
    --webroot-path=/var/www/certbot \
    -d app.niceshark.com \
    --email your-email@example.com \
    --agree-tos \
### 3. Install Full Nginx Config
```bash
sudo cp /opt/blacktip/web-frontend/nginx-blacktip.conf /etc/nginx/sites-available/blacktip
sudo nginx -t && sudo systemctl reload nginx
```

### 3. Web Frontend Service
```bash
sudo cp /opt/blacktip/web-frontend/blacktip-web.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable blacktip-web.service
sudo systemctl start blacktip-web.service
sudo systemctl status blacktip-web.service
```

### 4ystemctl start blacktip.service
### 4. Verify Deployment
```bash
# Check both services
sudo systemctl status 'blacktip*'

# Test HTTPS

### 2. Wait for Database
```bash
# Main scanner service
sudo systemctl status blacktip.service
sudo systemctl restart blacktip.service

# Web frontend service
sudo systemctl status blacktip-web.service
sudo systemctl restart blacktip-web.service

# Check all blacktip services
# Main scanner
sudo journalctl -u blacktip.service -f

# Web frontend
sudo journalctl -u blacktip-web.service -f

# Gunicorn logs
sudo tail -f /var/log/blacktip/gunicorn-error.log

# Nginx logs

### 3. Web Fronten systemctl reload nginx
```

### 9. Install Systemd Service
```bash
sudo cp blacktip-web.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable blacktip-web.service
sudo systemctl start blacktip-web.service
```

### 10. Verify Deployment
```bash
sudo systemctl status blacktip-web.service

# Check database permissions (web needs write access for device names)
sudo chown root:blacktip /var/lib/blacktip/blacktip.db
sudo chmod 664 /var/lib/blacktip/blacktip.db

# Verify main service is running
sudo systemctl status blacktip.service

## Daily Operations

### Service Management
```bash
sudo systemctl status blacktip-web.service    # Check status
sudo systemctl restart blacktip-web.service   # Restart
sudo systemctl stop blacktip-web.service      # Stop
sudo systemctl start blacktip-web.service     # Start
```

### View Logs
```bash
sudo journalctl -u blacktip-web.service -f    # Follow service logs
sudo tail -f /var/log/blacktip/gunicorn-error.log
sudo tail -f /var/log/nginx/blacktip-error.log
```

### Certificate Renewal
```bash
sudo certbot renew                            # Manual renewal
# Database (allows web to update device names)
sudo chown root:blacktip /var/lib/blacktip/blacktip.db
sudo chmod 664 /var/lib/blacktip/blacktip.db

# Environment file
sudo chmod 600 /opt/blacktip/web-frontend/.env
sudo chown blacktip:blacktip /opt/blacktip/web-frontend/.env

# Application files
sudo chown -R $USER:$USER /opt/blacktip
### Update Application
```bash
cd /opt/blacktip
git pull origin main
cd web-frontend
sudo pip3 install -r requirements.txt
sudo systemctl restart blacktip-web.service
```

## Troubleshooting

### Service won't start
```bash
sudo journalctl -u blacktip-web.service -n 50
sudo chmod 644 /var/lib/blacktip/blacktip.db
sudo chown blacktip:blacktip /var/lib/blacktip/blacktip.db
```

### 502 Bad Gateway
```bash
sudo systemctl status blacktip-web.service
sudo ss -tlnp | grep 5000
sudo systemctl restart blacktip-web.service
```

### Certificate issues
```bash
sudo certbot renew --force-renewal
sudo systemctl reload nginx
```

## Security

### Firewall (UFW)
```bash
sudo ufw allow 443/tcp
sudo ufw allow 80/tcp
sudo ufw enable
```

### File Permissions
```bash
sudo chmod 600 /opt/blacktip/web-frontend/.env
sudo chmod 644 /var/lib/blacktip/blacktip.db
sudo chown -R blacktip:blacktip /opt/blacktip/web-frontend
```

## URLs
- **Production**: https://app.niceshark.com
- **Health Check**: https://app.niceshark.com/api/health
- **SSL Test**: https://www.ssllabs.com/ssltest/analyze.html?d=app.niceshark.com

For detailed documentation, see `PRODUCTION_DEPLOYMENT.md`
