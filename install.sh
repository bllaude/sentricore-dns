#!/bin/bash
# Sentricore DNS Proxy - Raspberry Pi Installation Script
# Usage: sudo bash install.sh
# This script sets up Sentricore DNS Proxy as a systemd service on Raspberry Pi

set -e

echo "=========================================="
echo "Sentricore DNS Proxy - RPi Installation"
echo "=========================================="

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "Error: This script must be run as root (use sudo)"
    exit 1
fi

# Variables
INSTALL_DIR="/opt/sentricore-dns"
SERVICE_USER="sentricore"
REPO_URL="${1:-https://github.com/bllaude/sentricore-dns.git}"

echo ""
echo "Step 1: Installing system dependencies..."
apt-get update
apt-get install -y python3 python3-venv python3-pip git

echo ""
echo "Step 2: Creating sentricore user..."
if id "$SERVICE_USER" &>/dev/null; then
    echo "User $SERVICE_USER already exists"
else
    useradd -r -s /bin/bash -d $INSTALL_DIR $SERVICE_USER
    echo "Created user $SERVICE_USER"
fi

echo ""
echo "Step 3: Cloning repository..."
if [ -d "$INSTALL_DIR/.git" ]; then
    echo "Repository already exists, pulling latest changes..."
    cd $INSTALL_DIR
    sudo -u $SERVICE_USER git pull origin master
else
    git clone $REPO_URL $INSTALL_DIR
    chown -R $SERVICE_USER:$SERVICE_USER $INSTALL_DIR
fi

echo ""
echo "Step 4: Setting up Python virtual environment..."
cd $INSTALL_DIR
if [ ! -d "venv" ]; then
    sudo -u $SERVICE_USER python3 -m venv venv
fi

echo ""
echo "Step 5: Installing Python dependencies..."
$INSTALL_DIR/venv/bin/pip install -q -r requirements.txt

echo ""
echo "Step 6: Creating data directories..."
mkdir -p $INSTALL_DIR/data
mkdir -p $INSTALL_DIR/logs
mkdir -p $INSTALL_DIR/blocklists
chown -R $SERVICE_USER:$SERVICE_USER $INSTALL_DIR/data $INSTALL_DIR/logs $INSTALL_DIR/blocklists

echo ""
echo "Step 7: Installing systemd services..."
cp $INSTALL_DIR/sentricore-dns-proxy.service /etc/systemd/system/
cp $INSTALL_DIR/sentricore-dns-web.service /etc/systemd/system/
systemctl daemon-reload

echo ""
echo "Step 8: Enabling services to start on boot..."
systemctl enable sentricore-dns-proxy.service
systemctl enable sentricore-dns-web.service

echo ""
echo "Step 9: Starting services..."
systemctl start sentricore-dns-proxy.service
systemctl start sentricore-dns-web.service

echo ""
echo "=========================================="
echo "Installation Complete!"
echo "=========================================="
echo ""
echo "Service Status:"
systemctl status sentricore-dns-proxy.service --no-pager
echo ""
systemctl status sentricore-dns-web.service --no-pager
echo ""
echo "Useful Commands:"
echo "  View logs:"
echo "    sudo journalctl -u sentricore-dns-proxy.service -f"
echo "    sudo journalctl -u sentricore-dns-web.service -f"
echo ""
echo "  Control services:"
echo "    sudo systemctl stop sentricore-dns-proxy.service"
echo "    sudo systemctl start sentricore-dns-proxy.service"
echo "    sudo systemctl restart sentricore-dns-proxy.service"
echo ""
echo "  Dashboard: http://$(hostname -I | awk '{print $1}'):5000"
echo "  Health check: curl http://$(hostname -I | awk '{print $1}'):5000/healthz"
echo ""
