# Blacktip Web Frontend - Production Deployment Guide

Complete guide for deploying the Blacktip web interface to production with HTTPS using Let's Encrypt on a fresh Ubuntu server.

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Fresh Ubuntu Server Setup](#fresh-ubuntu-server-setup)
3. [Install Blacktip Backend](#install-blacktip-backend)
4. [System User Setup](#system-user-setup)
5. [Install Web Frontend Dependencies](#install-web-frontend-dependencies)
6. [Configure Application](#configure-application)
7. [Install and Configure Nginx](#install-and-configure-nginx)
8. [Install Let's Encrypt SSL Certificates](#install-lets-encrypt-ssl-certificates)
9. [Configure Systemd Services](#configure-systemd-services)
10. [Deployment and Testing](#deployment-and-testing)
11. [Monitoring and Maintenance](#monitoring-and-maintenance)
12. [Troubleshooting](#troubleshooting)

---

## Prerequisites

- **Domain Name**: `app.niceshark.com` pointing to your server's IP address
- **Server**: Fresh Ubuntu 22.04 LTS or 24.04 LTS server
- **Ports**: 80 and 443 accessible (at least initially for Let's Encrypt validation)
- **Root/Sudo Access**: Required for installation
- **Minimum Resources**: 2GB RAM, 2 CPU cores, 20GB storage

### Verify DNS Configuration

Before proceeding, verify your domain resolves correctly:

```bash
# Check DNS resolution
dig app.niceshark.com +short

# Should return your server's IP address
ping app.niceshark.com
```

---

## Fresh Ubuntu Server Setup

Start with a clean Ubuntu 22.04 LTS or 24.04 LTS installation.

### 1. Update System

```bash
# Update package lists
sudo apt update

# Upgrade all packages
sudo apt upgrade -y

# Install essential tools
sudo apt install -y git curl wget build-essential python3 python3-pip \
    python3-venv nmap net-tools iproute2 dnsutils
```

### 2. Configure Firewall (UFW)

```bash
# Install UFW if not present
sudo apt install -y ufw

# Allow SSH (important - don't lock yourself out!)
sudo ufw allow ssh
sudo ufw allow 22/tcp

# Allow HTTP and HTTPS
sudo ufw allow 80/tcp comment 'HTTP - Let\'s Encrypt'
sudo ufw allow 443/tcp comment 'HTTPS'

# Enable firewall
sudo ufw --force enable

# Check status
sudo ufw status verbose
```

### 3. Set System Timezone (Optional)

```bash
# List available timezones
timedatectl list-timezones

# Set timezone (example: US Eastern)
sudo timedatectl set-timezone America/New_York

# Verify
timedatectl
```

### 4. Configure Network Capabilities for Python

Blacktip needs raw socket access for network scanning:

```bash
# Allow Python3 to use raw sockets (required for packet capture)
sudo setcap cap_net_raw,cap_net_admin=eip /usr/bin/python3.10
# Or for Python 3.12 on Ubuntu 24.04
sudo setcap cap_net_raw,cap_net_admin=eip /usr/bin/python3.12
```

---

## Install Blacktip Backend

### 1. Clone Repository

```bash
# Create installation directory
sudo mkdir -p /opt/blacktip
sudo chown $USER:$USER /opt/blacktip

# Clone the repository
cd /opt
git clone https://github.com/mhawthorne-nip/blacktip.git
cd blacktip
```

### 2. Install Python Dependencies

```bash
# Install main Blacktip dependencies
sudo pip3 install -r requirements.txt

# Install the package in editable mode
sudo pip3 install -e .
```

### 3. Verify Installation

```bash
# Check that commands are available
which blacktip
which blacktip-state-monitor

# Test help output
blacktip --help
blacktip-state-monitor --help
```

### 4. Create Required Directories

```bash
# Create directories for database and logs
sudo mkdir -p /var/lib/blacktip
sudo mkdir -p /var/log/blacktip
sudo mkdir -p /var/run/blacktip

# Set initial permissions (will be refined later)
sudo chmod 755 /var/lib/blacktip /var/log/blacktip /var/run/blacktip
```

---

## System User Setup

Create a dedicated system user for running the web frontend:

```bash
# Create blacktip group and user
sudo groupadd --system blacktip
sudo useradd --system --no-create-home --shell /bin/false --gid blacktip blacktip

# Verify user was created
id blacktip
# Should output: uid=... gid=... groups=...
```

### Set Permissions

```bash
# Set ownership for log and run directories
sudo chown -R blacktip:blacktip /var/log/blacktip
sudo chown -R blacktip:blacktip /var/run/blacktip

# Database directory needs special permissions
# Root owns it, but blacktip group can read/write
sudo chown root:blacktip /var/lib/blacktip
sudo chmod 775 /var/lib/blacktip
```

**Important:** The database file will be created by the root-owned scanner service, but the web frontend (running as `blacktip` user) needs write access to update device names.

---

## Install Web Frontend Dependencies

### 1. Install Nginx

```bash
sudo apt install -y nginx
sudo systemctl enable nginx
sudo systemctl start nginx

# Verify Nginx is running
sudo systemctl status nginx

# Test default page
curl http://localhost
```

### 2. Install Python Web Dependencies

Navigate to the web-frontend directory and install requirements:

```bash
cd /opt/blacktip/web-frontend

# Install production dependencies
sudo pip3 install -r requirements.txt

# Or install in virtual environment (recommended)
sudo python3 -m venv /opt/blacktip/venv
sudo /opt/blacktip/venv/bin/pip install -r requirements.txt
```

**Production dependencies installed:**
- Flask (web framework)
- Flask-CORS (cross-origin resource sharing)
- Gunicorn (production WSGI server)
- python-dotenv (environment variable management)
- Flask-Limiter (rate limiting)

---

## Configure Application

### 1. Create Environment Configuration

```bash
cd /opt/blacktip/web-frontend

# Copy example configuration
sudo cp .env.example .env

# Generate a secure secret key
SECRET_KEY=$(python3 -c 'import os; print(os.urandom(24).hex())')

# Edit configuration
sudo nano .env
```

**Edit `.env` file with your settings:**

```bash
# Flask Configuration
SECRET_KEY=<paste-generated-key-here>

# Database
BLACKTIP_DB=/var/lib/blacktip/blacktip.db

# CORS Configuration
ALLOWED_ORIGINS=https://app.niceshark.com

# Server Configuration
PORT=5000
DEBUG=false

# Gunicorn Configuration
GUNICORN_BIND=127.0.0.1:5000
GUNICORN_WORKERS=4
GUNICORN_ACCESS_LOG=/var/log/blacktip/gunicorn-access.log
GUNICORN_ERROR_LOG=/var/log/blacktip/gunicorn-error.log
GUNICORN_LOG_LEVEL=info
```

### 2. Set Secure Permissions

```bash
# Protect .env file (contains secret key)
sudo chown blacktip:blacktip /opt/blacktip/web-frontend/.env
sudo chmod 600 /opt/blacktip/web-frontend/.env

# Ensure application files are readable
sudo chown -R blacktip:blacktip /opt/blacktip/web-frontend
sudo chmod -R 755 /opt/blacktip/web-frontend
sudo chmod 600 /opt/blacktip/web-frontend/.env
```

### 3. Test Gunicorn Manually (Optional)

Before setting up systemd, test Gunicorn works:

```bash
cd /opt/blacktip/web-frontend

# Test as blacktip user
sudo -u blacktip BLACKTIP_DB=/var/lib/blacktip/blacktip.db \
    python3 -m gunicorn -c gunicorn.conf.py app:app

# Should see: "Gunicorn server is ready. Spawning workers"
# Press Ctrl+C to stop
```

---

## Install and Configure Nginx

### 1. Copy Nginx Configuration

```bash
# Copy configuration file
sudo cp /opt/blacktip/web-frontend/nginx-blacktip.conf \
    /etc/nginx/sites-available/blacktip

# Create symbolic link to enable site
sudo ln -s /etc/nginx/sites-available/blacktip \
    /etc/nginx/sites-enabled/blacktip
```

### 2. Create Directory for Let's Encrypt Challenge

```bash
# Create webroot for ACME challenge
sudo mkdir -p /var/www/certbot
sudo chown -R www-data:www-data /var/www/certbot
```

### 3. Test Nginx Configuration (Initial)

```bash
# Test configuration syntax
sudo nginx -t

# You'll see an error about missing SSL certificates - this is expected
# We'll fix this after obtaining Let's Encrypt certificates
```

### 4. Temporarily Comment Out SSL Configuration

Edit the Nginx config to allow HTTP access for Let's Encrypt validation:

```bash
sudo nano /etc/nginx/sites-available/blacktip
```

**Comment out the entire HTTPS server block (lines 23 onwards)** by adding `#` at the start of each line, or temporarily:

```bash
# Backup original config
sudo cp /etc/nginx/sites-available/blacktip \
    /etc/nginx/sites-available/blacktip.backup

# Create temporary HTTP-only config
sudo tee /etc/nginx/sites-available/blacktip > /dev/null <<'EOF'
server {
    listen 80;
    listen [::]:80;
    server_name app.niceshark.com;

    # Let's Encrypt ACME challenge
    location /.well-known/acme-challenge/ {
        root /var/www/certbot;
        allow all;
    }

    # Temporary: allow all traffic for testing
    location / {
        return 200 "Blacktip - Preparing for HTTPS\n";
        add_header Content-Type text/plain;
    }
}
EOF
```

### 5. Reload Nginx

```bash
# Test configuration
sudo nginx -t

# Should now pass without SSL errors
# Reload Nginx
sudo systemctl reload nginx
```

### 6. Verify HTTP Access

```bash
# Test from server
curl http://app.niceshark.com

# Should return: "Blacktip - Preparing for HTTPS"
```

---

## Install Let's Encrypt SSL Certificates

### 1. Install Certbot

```bash
# Install Certbot and Nginx plugin
sudo apt install -y certbot python3-certbot-nginx
```

### 2. Obtain SSL Certificate

Use Certbot to obtain a certificate for `app.niceshark.com`:

```bash
# Request certificate using webroot method
sudo certbot certonly \
    --webroot \
    --webroot-path=/var/www/certbot \
    -d app.niceshark.com \
    --email your-email@example.com \
    --agree-tos \
    --no-eff-email
```

**Replace `your-email@example.com` with your actual email address.**

**Expected output:**
```
Successfully received certificate.
Certificate is saved at: /etc/letsencrypt/live/app.niceshark.com/fullchain.pem
Key is saved at:         /etc/letsencrypt/live/app.niceshark.com/privkey.pem
```

### 3. Verify Certificate Files

```bash
# List certificate files
sudo ls -la /etc/letsencrypt/live/app.niceshark.com/

# Should see:
# - cert.pem (certificate)
# - chain.pem (intermediate certificates)
# - fullchain.pem (cert + chain)
# - privkey.pem (private key)
```

### 4. Test Certificate

```bash
# Check certificate details
sudo openssl x509 -in /etc/letsencrypt/live/app.niceshark.com/fullchain.pem \
    -noout -text | grep -A2 "Validity"

# Check certificate expiration
sudo certbot certificates
```

### 5. Restore Full Nginx Configuration

Now that we have SSL certificates, restore the full HTTPS configuration:

```bash
# Restore original configuration with HTTPS
sudo cp /etc/nginx/sites-available/blacktip.backup \
    /etc/nginx/sites-available/blacktip

# Or copy from the project
sudo cp /opt/blacktip/web-frontend/nginx-blacktip.conf \
    /etc/nginx/sites-available/blacktip
```

### 6. Test and Reload Nginx with HTTPS

```bash
# Test configuration (should pass now with certificates)
sudo nginx -t

# Reload Nginx
sudo systemctl reload nginx
```

### 7. Configure Automatic Certificate Renewal

Let's Encrypt certificates expire after 90 days. Certbot automatically installs a renewal timer.

```bash
# Check renewal timer status
sudo systemctl status certbot.timer

# Test renewal process (dry run)
sudo certbot renew --dry-run

# Should output: "Congratulations, all simulated renewals succeeded"
```

The renewal timer runs twice daily and automatically renews certificates within 30 days of expiration.

**Manual renewal command (if needed):**
```bash
sudo certbot renew
sudo systemctl reload nginx
```

---

## Configure Systemd Services

You'll set up two systemd services:
1. **blacktip.service** - Main scanner and state monitor (runs as root)
2. **blacktip-web.service** - Web frontend (runs as blacktip user)

### 1. Install Main Blacktip Service

The main service file should already exist in the repository:

```bash
# Copy main service file
sudo cp /opt/blacktip/blacktip.service /etc/systemd/system/

# Set permissions
sudo chmod 644 /etc/systemd/system/blacktip.service

# Reload systemd
sudo systemctl daemon-reload

# Enable service to start on boot
sudo systemctl enable blacktip.service

# Start the service
sudo systemctl start blacktip.service

# Check status
sudo systemctl status blacktip.service
```

**Expected output:**
```
● blacktip.service - Blacktip Network Security Scanner with State Monitor
     Loaded: loaded (/etc/systemd/system/blacktip.service; enabled)
     Active: active (running) since ...
```

### 2. Verify Database Created

```bash
# Wait a few seconds for database to be created
sleep 10

# Check database exists
ls -lh /var/lib/blacktip/blacktip.db

# Should show permissions: -rw-rw-r-- root blacktip
# Group write permission allows web frontend to update device names
```

### 3. Install Web Frontend Service

### 3. Install Web Frontend Service

```bash
# Copy service file
sudo cp /opt/blacktip/web-frontend/blacktip-web.service \
    /etc/systemd/system/

# Set permissions
sudo chmod 644 /etc/systemd/system/blacktip-web.service
```

### 4. Reload Systemd

```bash
# Reload systemd to recognize new service
sudo systemctl daemon-reload
```

### 5. Enable and Start Web Service

```bash
# Enable service to start on boot
sudo systemctl enable blacktip-web.service

# Start the service
sudo systemctl start blacktip-web.service

# Check status
sudo systemctl status blacktip-web.service
```

**Expected output:**
```
● blacktip-web.service - Blacktip Web Frontend (Gunicorn)
     Loaded: loaded (/etc/systemd/system/blacktip-web.service; enabled)
     Active: active (running) since ...
```

### 6. Verify Both Services Running

```bash
# Check all blacktip services
sudo systemctl status 'blacktip*'

# Verify Gunicorn is listening on port 5000
sudo ss -tlnp | grep 5000

# Should show Gunicorn process listening on 127.0.0.1:5000
```

### 7. View Service Logs

```bash
# Main scanner logs
sudo journalctl -u blacktip.service -n 50

# Web frontend logs  
sudo journalctl -u blacktip-web.service -n 50

# Follow logs in real-time
sudo journalctl -u blacktip-web.service -f
```

---

## Deployment and Testing

### 1. Test HTTP to HTTPS Redirect

```bash
# Should redirect to HTTPS
curl -I http://app.niceshark.com

# Look for: HTTP/1.1 301 Moved Permanently
#           Location: https://app.niceshark.com/
```

### 2. Test HTTPS Access

```bash
# Test HTTPS connection
curl -I https://app.niceshark.com

# Should return: HTTP/2 200
```

### 3. Verify SSL Certificate

```bash
# Check SSL certificate details
openssl s_client -connect app.niceshark.com:443 -servername app.niceshark.com < /dev/null | openssl x509 -noout -dates

# Should show valid dates and issuer: Let's Encrypt
```

You can also use online tools:
- **SSL Labs**: https://www.ssllabs.com/ssltest/analyze.html?d=app.niceshark.com

### 4. Test API Endpoints

```bash
# Test health check
curl https://app.niceshark.com/api/health

# Test device list
curl https://app.niceshark.com/api/devices

# Test statistics
curl https://app.niceshark.com/api/statistics
```

### 5. Test Web Interface

Open a browser and navigate to:
- **https://app.niceshark.com**

You should see:
- ✅ HTTPS with valid certificate (green padlock)
- ✅ Blacktip web interface loads
- ✅ Device list displays
- ✅ No console errors

### 6. Verify Security Headers

```bash
# Check security headers
curl -I https://app.niceshark.com

# Should include:
# Strict-Transport-Security: max-age=63072000
# X-Frame-Options: SAMEORIGIN
# X-Content-Type-Options: nosniff
# Content-Security-Policy: ...
```

---

## Monitoring and Maintenance

### 1. View Application Logs

**Gunicorn logs (via journald):**
```bash
# Follow live logs
sudo journalctl -u blacktip-web.service -f

# View recent logs
sudo journalctl -u blacktip-web.service -n 100

# View logs for specific time period
sudo journalctl -u blacktip-web.service --since "1 hour ago"
```

**Gunicorn log files:**
```bash
# Access log
sudo tail -f /var/log/blacktip/gunicorn-access.log

# Error log
sudo tail -f /var/log/blacktip/gunicorn-error.log
```

**Nginx logs:**
```bash
# Access log
sudo tail -f /var/log/nginx/blacktip-access.log

# Error log
sudo tail -f /var/log/nginx/blacktip-error.log
```

### 2. Service Management

```bash
# Start service
sudo systemctl start blacktip-web.service

# Stop service
sudo systemctl stop blacktip-web.service

# Restart service
sudo systemctl restart blacktip-web.service

# Reload service (graceful restart)
sudo systemctl reload blacktip-web.service

# Check service status
sudo systemctl status blacktip-web.service

# View service configuration
sudo systemctl cat blacktip-web.service
```

### 3. Nginx Management

```bash
# Test configuration
sudo nginx -t

# Reload configuration (no downtime)
sudo systemctl reload nginx

# Restart Nginx
sudo systemctl restart nginx

# Check status
sudo systemctl status nginx
```

### 4. Update Application Code

When updating the application:

```bash
cd /opt/blacktip

# Pull latest changes
git pull origin main

# Update web frontend dependencies if needed
cd web-frontend
sudo pip3 install -r requirements.txt

# Restart web service
sudo systemctl restart blacktip-web.service

# Verify service restarted successfully
sudo systemctl status blacktip-web.service
```

### 5. Certificate Renewal

Certificates auto-renew, but you can manually check:

```bash
# Check certificate expiration
sudo certbot certificates

# Manually renew (if needed)
sudo certbot renew

# Reload Nginx after renewal
sudo systemctl reload nginx
```

### 6. Log Rotation

Configure log rotation to prevent disk space issues:

```bash
# Create log rotation config
sudo tee /etc/logrotate.d/blacktip > /dev/null <<'EOF'
/var/log/blacktip/*.log {
    daily
    rotate 14
    compress
    delaycompress
    notifempty
    missingok
    create 0640 blacktip blacktip
    sharedscripts
    postrotate
        systemctl reload blacktip-web.service > /dev/null 2>&1 || true
    endscript
}
EOF

# Test log rotation
sudo logrotate -d /etc/logrotate.d/blacktip
```

---

## Troubleshooting

### Issue: Service Won't Start

**Check service status:**
```bash
sudo systemctl status blacktip-web.service
sudo journalctl -u blacktip-web.service -n 50
```

**Common causes:**
1. Database file permissions
   ```bash
   # Ensure database has correct group ownership and permissions
   sudo chown root:blacktip /var/lib/blacktip/blacktip.db
   sudo chmod 664 /var/lib/blacktip/blacktip.db
   ```

2. Missing .env file
   ```bash
   ls -la /opt/blacktip/web-frontend/.env
   # If missing, copy from example
   cd /opt/blacktip/web-frontend
   sudo cp .env.example .env
   sudo chown blacktip:blacktip .env
   sudo chmod 600 .env
   ```

3. Python dependency issues
   ```bash
   cd /opt/blacktip/web-frontend
   sudo pip3 install -r requirements.txt
   ```

4. Main blacktip service not running
   ```bash
   sudo systemctl start blacktip.service
   # Wait for database to be created
   sleep 5
   sudo systemctl restart blacktip-web.service
   ```

### Issue: 502 Bad Gateway

**Cause:** Nginx can't connect to Gunicorn

**Check:**
```bash
# Verify Gunicorn is running
sudo systemctl status blacktip-web.service

# Check if listening on correct port
sudo ss -tlnp | grep 5000

# Check Gunicorn logs
sudo journalctl -u blacktip-web.service -n 50
```

**Fix:**
```bash
sudo systemctl restart blacktip-web.service
```

### Issue: SSL Certificate Error

**Check certificate:**
```bash
sudo certbot certificates
```

**Renew certificate:**
```bash
sudo certbot renew --force-renewal
sudo systemctl reload nginx
```

### Issue: Permission Denied Errors

**Fix database permissions (allows web frontend to update device names):**
```bash
# Set correct ownership and permissions
sudo chown root:blacktip /var/lib/blacktip/blacktip.db
sudo chmod 664 /var/lib/blacktip/blacktip.db

# Verify
ls -lh /var/lib/blacktip/blacktip.db
# Should show: -rw-rw-r-- root blacktip
```

**Fix log directory permissions:**
```bash
sudo chown -R blacktip:blacktip /var/log/blacktip
sudo chmod 755 /var/log/blacktip
```

### Issue: CORS Errors in Browser Console

**Verify .env configuration:**
```bash
sudo cat /opt/blacktip/web-frontend/.env | grep ALLOWED_ORIGINS

# Should show: ALLOWED_ORIGINS=https://app.niceshark.com
```

**Restart service after changes:**
```bash
sudo systemctl restart blacktip-web.service
```

### Issue: Static Files Not Loading

**Check Nginx configuration:**
```bash
sudo nginx -t
```

**Verify static files exist:**
```bash
ls -la /opt/blacktip/web-frontend/static/
```

**Check Nginx error log:**
```bash
sudo tail -f /var/log/nginx/blacktip-error.log
```

### Issue: Slow Performance

**Increase Gunicorn workers:**
```bash
# Edit .env
sudo nano /opt/blacktip/web-frontend/.env

# Increase workers (rule of thumb: 2 × CPU cores + 1)
GUNICORN_WORKERS=8

# Restart service
sudo systemctl restart blacktip-web.service
```

**Enable Nginx caching (if needed):**
Add to Nginx configuration:
```nginx
proxy_cache_path /var/cache/nginx levels=1:2 keys_zone=blacktip_cache:10m max_size=100m;
```

### Issue: Certificate Not Renewing

**Check renewal timer:**
```bash
sudo systemctl status certbot.timer
```

**Test renewal:**
```bash
sudo certbot renew --dry-run
```

**Check for firewall issues:**
```bash
# Ensure port 80 is accessible for ACME challenge
sudo ufw status
```

### Debugging Tips

1. **Check all service logs:**
   ```bash
   sudo journalctl -u blacktip-web.service -f
   ```

2. **Test Gunicorn directly:**
   ```bash
   cd /opt/blacktip/web-frontend
   sudo -u blacktip python3 -m gunicorn -c gunicorn.conf.py app:app
   ```

3. **Test Nginx configuration:**
   ```bash
   sudo nginx -t
   ```

4. **Check port bindings:**
   ```bash
   sudo ss -tlnp | grep -E '(80|443|5000)'
   ```

5. **Monitor resource usage:**
   ```bash
   htop
   ```

---

## Security Considerations

### 1. Firewall Configuration

```bash
# Allow HTTPS traffic
sudo ufw allow 443/tcp comment 'HTTPS'

# Allow HTTP (for Let's Encrypt renewal)
sudo ufw allow 80/tcp comment 'HTTP - Let's Encrypt'

# Enable firewall
sudo ufw enable
```

**For internal network only:** If you want to restrict access to specific IP ranges:

```bash
# Example: Allow only from 192.168.1.0/24 network
sudo ufw delete allow 443/tcp
sudo ufw allow from 192.168.1.0/24 to any port 443 proto tcp comment 'HTTPS - Internal'
```

### 2. Regular Updates

```bash
# Update system packages
sudo apt update && sudo apt upgrade -y

# Update Python dependencies
cd /opt/blacktip/web-frontend
sudo pip3 install --upgrade -r requirements.txt

# Restart services
sudo systemctl restart blacktip-web.service
```

### 3. Monitoring Certificate Expiration

Set up monitoring alerts for certificate expiration (30 days before):

```bash
# Add to crontab
(crontab -l 2>/dev/null; echo "0 0 * * * certbot renew --quiet --post-hook 'systemctl reload nginx'") | crontab -
```

### 4. Security Headers Verification

Regularly test your security posture:
- **SSL Labs**: https://www.ssllabs.com/ssltest/
- **Security Headers**: https://securityheaders.com/

---

## Production Checklist

Before going live, verify:

- [ ] Fresh Ubuntu server updated and secured
- [ ] Blacktip backend installed from repository
- [ ] Python has network capabilities (setcap)
- [ ] System user `blacktip` created
- [ ] DNS records point to server IP
- [ ] Main blacktip.service running and creating database
- [ ] Database permissions correct (664, root:blacktip)
- [ ] Web frontend dependencies installed
- [ ] .env file configured with secret key
- [ ] SSL certificates installed and valid
- [ ] HTTPS redirect working (HTTP → HTTPS)
- [ ] All API endpoints respond correctly over HTTPS
- [ ] Device name updates work (write access to database)
- [ ] Static files load properly
- [ ] Security headers present in responses
- [ ] Both services start on boot (blacktip.service, blacktip-web.service)
- [ ] Nginx service starts on boot
- [ ] Log rotation configured
- [ ] Certificate auto-renewal tested
- [ ] Firewall rules configured (UFW)
- [ ] .env file secured (chmod 600)
- [ ] Services running as appropriate users (root for scanner, blacktip for web)
- [ ] Monitoring/alerting configured (optional)
- [ ] Backups configured for database (optional)

---

## Additional Resources

- **Nginx Documentation**: https://nginx.org/en/docs/
- **Gunicorn Documentation**: https://docs.gunicorn.org/
- **Let's Encrypt**: https://letsencrypt.org/docs/
- **Flask Production Deployment**: https://flask.palletsprojects.com/en/stable/deploying/
- **SSL Best Practices**: https://wiki.mozilla.org/Security/Server_Side_TLS

---

## Support

For issues specific to Blacktip, check:
- GitHub Issues: https://github.com/mhawthorne-nip/blacktip/issues
- Project Documentation: `/opt/blacktip/README.md`

---

**Deployment completed successfully!** 🎉

Your Blacktip web interface should now be accessible at:
**https://app.niceshark.com**
