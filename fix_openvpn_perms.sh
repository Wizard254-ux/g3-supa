#!/bin/bash
# Quick fix for OpenVPN certificate permissions
# Run with: sudo bash fix_openvpn_perms.sh

APP_USER="f2net_isp"

echo "Fixing OpenVPN certificate permissions for $APP_USER..."

if [[ -d "/etc/openvpn/server" ]]; then
    # Recursively set full ownership to app user on entire server directory
    echo "Setting full ownership recursively to $APP_USER..."
    chown -R $APP_USER:$APP_USER /etc/openvpn/server

    # Recursively set all directories to be fully accessible (755)
    echo "Setting directory permissions..."
    find /etc/openvpn/server -type d -exec chmod 755 {} \;

    # Recursively set all files to be readable/writable by app user (644)
    echo "Setting file permissions..."
    find /etc/openvpn/server -type f -exec chmod 644 {} \;

#    # Make easyrsa and other scripts executable
#    echo "Making scripts executable..."
#    if [[ -f "/etc/openvpn/server/easy-rsa/easyrsa" ]]; then
#        chmod 755 /etc/openvpn/server/easy-rsa/easyrsa
#        echo "✓ Set easyrsa script as executable"
#    fi

    # Secure all private keys - keep ownership with app user but restrict permissions
    echo "Securing private keys..."
    find /etc/openvpn/server -type f -name "*.key" -exec chmod 600 {} \;

    # Secure private key directory
    if [[ -d "/etc/openvpn/server/easy-rsa/pki/private" ]]; then
        chmod 700 /etc/openvpn/server/easy-rsa/pki/private
    fi

    echo "✓ Recursively set permissions on /etc/openvpn/server"
    echo "  - Owner: $APP_USER:$APP_USER (full ownership)"
    echo "  - All directories: 755 (rwxr-xr-x)"
    echo "  - All files: 644 (rw-r--r--)"
    echo "  - Private keys: 600 (rw-------)"
fi

echo ""
echo "✅ OpenVPN certificate permissions fixed!"
echo "Your Flask app running as $APP_USER can now read all files in /etc/openvpn/server"
echo ""
echo "Verify with: ls -la /etc/openvpn/server/ca.crt"