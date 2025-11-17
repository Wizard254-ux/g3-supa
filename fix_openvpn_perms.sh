#!/bin/bash
# Quick fix for OpenVPN certificate permissions
# Run with: sudo bash fix_openvpn_perms.sh

APP_USER="f2net_isp"

echo "Fixing OpenVPN certificate permissions for $APP_USER..."

# Public certificates - app needs to read these to generate client configs
if [[ -f "/etc/openvpn/server/ca.crt" ]]; then
    chown root:$APP_USER /etc/openvpn/server/ca.crt
    chmod 640 /etc/openvpn/server/ca.crt
    echo "✓ Set permissions on ca.crt (readable by $APP_USER group)"
fi

if [[ -f "/etc/openvpn/server/server.crt" ]]; then
    chown root:$APP_USER /etc/openvpn/server/server.crt
    chmod 640 /etc/openvpn/server/server.crt
    echo "✓ Set permissions on server.crt (readable by $APP_USER group)"
fi

if [[ -f "/etc/openvpn/server/dh.pem" ]]; then
    chown root:$APP_USER /etc/openvpn/server/dh.pem
    chmod 640 /etc/openvpn/server/dh.pem
    echo "✓ Set permissions on dh.pem (readable by $APP_USER group)"
fi

if [[ -f "/etc/openvpn/server/tc.key" ]]; then
    chown root:$APP_USER /etc/openvpn/server/tc.key
    chmod 640 /etc/openvpn/server/tc.key
    echo "✓ Set permissions on tc.key (readable by $APP_USER group)"
fi

if [[ -f "/etc/openvpn/server/client-common.txt" ]]; then
    chown root:$APP_USER /etc/openvpn/server/client-common.txt
    chmod 640 /etc/openvpn/server/client-common.txt
    echo "✓ Set permissions on client-common.txt (readable by $APP_USER group)"
fi

# Private keys - keep root-only for security
if [[ -f "/etc/openvpn/server/ca.key" ]]; then
    chmod 600 /etc/openvpn/server/ca.key
    chown root:root /etc/openvpn/server/ca.key
    echo "✓ Secured ca.key (root-only)"
fi

if [[ -f "/etc/openvpn/server/server.key" ]]; then
    chmod 600 /etc/openvpn/server/server.key
    chown root:root /etc/openvpn/server/server.key
    echo "✓ Secured server.key (root-only)"
fi

# Make easy-rsa PKI directory accessible for reading client certs
if [[ -d "/etc/openvpn/server/easy-rsa/pki" ]]; then
    chown root:$APP_USER /etc/openvpn/server/easy-rsa
    chmod 750 /etc/openvpn/server/easy-rsa

    chown root:$APP_USER /etc/openvpn/server/easy-rsa/pki
    chmod 750 /etc/openvpn/server/easy-rsa/pki

    if [[ -d "/etc/openvpn/server/easy-rsa/pki/issued" ]]; then
        chown root:$APP_USER /etc/openvpn/server/easy-rsa/pki/issued
        chmod 750 /etc/openvpn/server/easy-rsa/pki/issued
    fi

    if [[ -d "/etc/openvpn/server/easy-rsa/pki/inline" ]]; then
        chown root:$APP_USER /etc/openvpn/server/easy-rsa/pki/inline
        chmod 750 /etc/openvpn/server/easy-rsa/pki/inline
    fi

    if [[ -d "/etc/openvpn/server/easy-rsa/pki/inline/private" ]]; then
        chown root:$APP_USER /etc/openvpn/server/easy-rsa/pki/inline/private
        chmod 750 /etc/openvpn/server/easy-rsa/pki/inline/private
    fi

    # Make client certificates readable
    find /etc/openvpn/server/easy-rsa/pki/issued -name "*.crt" -exec chown root:$APP_USER {} \; 2>/dev/null || true
    find /etc/openvpn/server/easy-rsa/pki/issued -name "*.crt" -exec chmod 640 {} \; 2>/dev/null || true

    # Make inline client files readable
    find /etc/openvpn/server/easy-rsa/pki/inline/private -name "*.inline" -exec chown root:$APP_USER {} \; 2>/dev/null || true
    find /etc/openvpn/server/easy-rsa/pki/inline/private -name "*.inline" -exec chmod 640 {} \; 2>/dev/null || true

    # Keep private keys secure
    if [[ -d "/etc/openvpn/server/easy-rsa/pki/private" ]]; then
        chmod 700 /etc/openvpn/server/easy-rsa/pki/private
        find /etc/openvpn/server/easy-rsa/pki/private -name "*.key" -exec chmod 600 {} \; 2>/dev/null || true
        find /etc/openvpn/server/easy-rsa/pki/private -name "*.key" -exec chown root:root {} \; 2>/dev/null || true
    fi

    echo "✓ Set PKI directory permissions for $APP_USER group"
fi

echo ""
echo "✅ OpenVPN certificate permissions fixed!"
echo "Your Flask app running as $APP_USER can now read certificates to generate client configs."
echo ""
echo "Verify with: ls -la /etc/openvpn/server/ca.crt"