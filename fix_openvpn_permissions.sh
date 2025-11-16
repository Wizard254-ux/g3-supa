#!/bin/bash

# Fix OpenVPN permissions for F2Net ISP
# This script must be run as root

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

APP_USER="f2net_isp"

print_status() {
    echo -e "${YELLOW}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   print_error "This script must be run as root"
   exit 1
fi

# Check if user exists
if ! id "$APP_USER" &>/dev/null; then
    print_error "User $APP_USER does not exist"
    exit 1
fi

print_status "Fixing OpenVPN directory permissions..."

# Create directories if they don't exist
if [[ ! -d /etc/openvpn/clients ]]; then
    print_status "Creating /etc/openvpn/clients"
    mkdir -p /etc/openvpn/clients
fi

if [[ ! -d /etc/openvpn/client_metadata ]]; then
    print_status "Creating /etc/openvpn/client_metadata"
    mkdir -p /etc/openvpn/client_metadata
fi

# Set ownership and permissions
print_status "Setting ownership to $APP_USER:$APP_USER"
chown -R "$APP_USER:$APP_USER" /etc/openvpn/clients
chown -R "$APP_USER:$APP_USER" /etc/openvpn/client_metadata

print_status "Setting directory permissions to 755"
chmod 755 /etc/openvpn/clients
chmod 755 /etc/openvpn/client_metadata

# Verify
print_status "Verifying permissions..."
echo ""
echo "Permissions for /etc/openvpn/clients:"
ls -ld /etc/openvpn/clients
echo ""
echo "Permissions for /etc/openvpn/client_metadata:"
ls -ld /etc/openvpn/client_metadata
echo ""

print_success "OpenVPN permissions fixed successfully!"
print_status "The f2net_isp user can now write to these directories"