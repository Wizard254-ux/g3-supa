#!/bin/bash

# =============================================================================
# F2Net Flask Application - Modular Installation Script
# This script sets up the complete F2Net environment with selective execution
# Usage: ./install.sh [OPTIONS]
# =============================================================================

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration
APP_NAME="f2net_isp"
APP_USER="f2net_isp"
APP_DIR="/opt/f2net_isp"
VENV_DIR="/opt/f2net_isp/venv"
LOG_DIR="/var/log/f2net_isp"
CONFIG_DIR="/etc/f2net_isp"
BACKUP_DIR="/var/backups/f2net_isp"
SYSTEMD_DIR="/etc/systemd/system"

# Execution flags
RUN_ALL=true
RUN_SYSTEM=false
RUN_DATABASE=false
RUN_SERVICES=false
RUN_SECURITY=false
RUN_NETWORK=false
RUN_APPLICATION=false

print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_header() {
    echo -e "${CYAN}=== $1 ===${NC}"
}



show_help() {
    cat << EOF
${CYAN}F2Net ISP Installation Script${NC}

${YELLOW}USAGE:${NC}
    $0 [OPTIONS]

${YELLOW}OPTIONS:${NC}
    ${GREEN}--help, -h${NC}              Show this help message
    ${GREEN}--all${NC}                   Run complete installation (default)

    ${YELLOW}Individual Components:${NC}
    ${GREEN}--packages${NC}              Install system packages only
    ${GREEN}--user${NC}                  Create application user only
    ${GREEN}--directories${NC}           Create directories only
    ${GREEN}--sudo${NC}                  Setup sudo permissions only
    ${GREEN}--database${NC}              Setup PostgreSQL database only
    ${GREEN}--redis${NC}                 Setup Redis only
    ${GREEN}--python-app${NC}            Install Python application only
    ${GREEN}--environment${NC}           Setup environment configuration only
    ${GREEN}--nginx${NC}                 Setup Nginx only
    ${GREEN}--systemd${NC}               Setup systemd services only
    ${GREEN}--logrotate${NC}             Setup log rotation only
    ${GREEN}--firewall${NC}              Setup firewall only
    ${GREEN}--openvpn${NC}               Setup OpenVPN only
    ${GREEN}--freeradius${NC}            Setup FreeRADIUS only
    ${GREEN}--init-db${NC}               Initialize database only
    ${GREEN}--start-services${NC}        Start services only
    ${GREEN}--admin-user${NC}            Create admin user only
    ${GREEN}--ssh${NC}                   Setup SSH (optional feature)

    ${YELLOW}Component Groups:${NC}
    ${GREEN}--system${NC}                System setup (packages, user, directories, sudo)
    ${GREEN}--data${NC}                  Database setup (database, redis, init-db)
    ${GREEN}--app${NC}                   Application setup (python-app, environment)
    ${GREEN}--web${NC}                   Web setup (nginx, systemd, logrotate)
    ${GREEN}--security${NC}              Security setup (firewall, sudo)
    ${GREEN}--network${NC}               Network services (openvpn, freeradius)

    ${YELLOW}Multiple Components:${NC}
    ${GREEN}--components "comp1,comp2"${NC}  Run specific components (comma-separated)

${YELLOW}EXAMPLES:${NC}
    # Complete installation
    $0 --all

    # System setup only
    $0 --system

    # Database and Redis only
    $0 --database --redis

    # Multiple specific components
    $0 --components "packages,user,database,nginx"

    # Web stack only
    $0 --web --database

    # Security hardening only
    $0 --security

${YELLOW}COMPONENT DEPENDENCIES:${NC}
    Some components depend on others:
    - python-app requires: packages, user, directories
    - nginx requires: user, directories
    - systemd requires: user, directories, python-app
    - start-services requires: systemd, database, redis

${YELLOW}NOTES:${NC}
    - Script must be run as root
    - Dependencies are automatically checked
    - Use --help for detailed information
    - Default behavior (no args) runs complete installation

EOF
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "This script must be run as root"
        exit 1
    fi
}

detect_os() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS=$NAME
        VER=$VERSION_ID
    else
        print_error "Cannot detect operating system"
        exit 1
    fi

    print_status "Detected OS: $OS $VER"
}

# Parse command line arguments
parse_arguments() {
    if [[ $# -eq 0 ]]; then
        return 0  # Default to --all
    fi

    RUN_ALL=false

    while [[ $# -gt 0 ]]; do
        case $1 in
            --help|-h)
                show_help
                exit 0
                ;;
            --all)
                RUN_ALL=true
                shift
                ;;
            --system)
                RUN_SYSTEM=true
                shift
                ;;
            --data)
                RUN_DATABASE=true
                shift
                ;;
            --app)
                RUN_APPLICATION=true
                shift
                ;;
            --web)
                RUN_SERVICES=true
                shift
                ;;
            --security)
                RUN_SECURITY=true
                shift
                ;;
            --network)
                RUN_NETWORK=true
                shift
                ;;
            --packages)
                INDIVIDUAL_PACKAGES=true
                shift
                ;;
            --user)
                INDIVIDUAL_USER=true
                shift
                ;;
            --directories)
                INDIVIDUAL_DIRECTORIES=true
                shift
                ;;
            --sudo)
                INDIVIDUAL_SUDO=true
                shift
                ;;
            --database)
                INDIVIDUAL_DATABASE=true
                shift
                ;;
            --redis)
                INDIVIDUAL_REDIS=true
                shift
                ;;
            --python-app)
                INDIVIDUAL_PYTHON_APP=true
                shift
                ;;
            --environment)
                INDIVIDUAL_ENVIRONMENT=true
                shift
                ;;
            --nginx)
                INDIVIDUAL_NGINX=true
                shift
                ;;
            --systemd)
                INDIVIDUAL_SYSTEMD=true
                shift
                ;;
            --logrotate)
                INDIVIDUAL_LOGROTATE=true
                shift
                ;;
            --firewall)
                INDIVIDUAL_FIREWALL=true
                shift
                ;;
            --openvpn)
                INDIVIDUAL_OPENVPN=true
                shift
                ;;
            --freeradius)
                INDIVIDUAL_FREERADIUS=true
                shift
                ;;
            --init-db)
                INDIVIDUAL_INIT_DB=true
                shift
                ;;
            --start-services)
                INDIVIDUAL_START_SERVICES=true
                shift
                ;;
            --admin-user)
                INDIVIDUAL_ADMIN_USER=true
                shift
                ;;
            --ssh)
                INDIVIDUAL_SSH=true
                shift
                ;;
            --components)
                if [[ -n $2 ]]; then
                    IFS=',' read -ra COMPONENTS <<< "$2"
                    for component in "${COMPONENTS[@]}"; do
                        case $component in
                            packages) INDIVIDUAL_PACKAGES=true ;;
                            user) INDIVIDUAL_USER=true ;;
                            directories) INDIVIDUAL_DIRECTORIES=true ;;
                            sudo) INDIVIDUAL_SUDO=true ;;
                            database) INDIVIDUAL_DATABASE=true ;;
                            redis) INDIVIDUAL_REDIS=true ;;
                            python-app) INDIVIDUAL_PYTHON_APP=true ;;
                            environment) INDIVIDUAL_ENVIRONMENT=true ;;
                            nginx) INDIVIDUAL_NGINX=true ;;
                            systemd) INDIVIDUAL_SYSTEMD=true ;;
                            logrotate) INDIVIDUAL_LOGROTATE=true ;;
                            firewall) INDIVIDUAL_FIREWALL=true ;;
                            openvpn) INDIVIDUAL_OPENVPN=true ;;
                            freeradius) INDIVIDUAL_FREERADIUS=true ;;
                            init-db) INDIVIDUAL_INIT_DB=true ;;
                            start-services) INDIVIDUAL_START_SERVICES=true ;;
                            admin-user) INDIVIDUAL_ADMIN_USER=true ;;
                            ssh) INDIVIDUAL_SSH=true ;;
                            *)
                                print_error "Unknown component: $component"
                                exit 1
                                ;;
                        esac
                    done
                    shift 2
                else
                    print_error "--components requires a comma-separated list"
                    exit 1
                fi
                ;;
            *)
                print_error "Unknown option: $1"
                show_help
                exit 1
                ;;
        esac
    done
}

# Dependency checking
check_dependencies() {
    local missing_deps=()

    # Check for python-app dependencies
    if [[ "$INDIVIDUAL_PYTHON_APP" == true ]]; then
        [[ "$INDIVIDUAL_PACKAGES" != true && "$RUN_SYSTEM" != true && "$RUN_ALL" != true ]] && missing_deps+=("packages")
        [[ "$INDIVIDUAL_USER" != true && "$RUN_SYSTEM" != true && "$RUN_ALL" != true ]] && missing_deps+=("user")
        [[ "$INDIVIDUAL_DIRECTORIES" != true && "$RUN_SYSTEM" != true && "$RUN_ALL" != true ]] && missing_deps+=("directories")
    fi

    # Check for nginx dependencies
    if [[ "$INDIVIDUAL_NGINX" == true ]]; then
        [[ "$INDIVIDUAL_USER" != true && "$RUN_SYSTEM" != true && "$RUN_ALL" != true ]] && missing_deps+=("user")
        [[ "$INDIVIDUAL_DIRECTORIES" != true && "$RUN_SYSTEM" != true && "$RUN_ALL" != true ]] && missing_deps+=("directories")
    fi

    # Check for systemd dependencies
    if [[ "$INDIVIDUAL_SYSTEMD" == true ]]; then
        [[ "$INDIVIDUAL_USER" != true && "$RUN_SYSTEM" != true && "$RUN_ALL" != true ]] && missing_deps+=("user")
        [[ "$INDIVIDUAL_DIRECTORIES" != true && "$RUN_SYSTEM" != true && "$RUN_ALL" != true ]] && missing_deps+=("directories")
    fi

    # Check for start-services dependencies
    if [[ "$INDIVIDUAL_START_SERVICES" == true ]]; then
        [[ "$INDIVIDUAL_SYSTEMD" != true && "$RUN_SERVICES" != true && "$RUN_ALL" != true ]] && missing_deps+=("systemd")
        [[ "$INDIVIDUAL_DATABASE" != true && "$RUN_DATABASE" != true && "$RUN_ALL" != true ]] && missing_deps+=("database")
        [[ "$INDIVIDUAL_REDIS" != true && "$RUN_DATABASE" != true && "$RUN_ALL" != true ]] && missing_deps+=("redis")
    fi

    if [[ ${#missing_deps[@]} -gt 0 ]]; then
        print_warning "Missing dependencies detected: ${missing_deps[*]}"
        print_warning "Consider adding these components or use a group option"
        echo ""
        read -p "Continue anyway? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            print_status "Installation cancelled"
            exit 0
        fi
    fi
}

#ssh optional feature for later use
setup_ssh(){
    print_header "Setting up SSH"
    mkdir -p /data/f2netvpnaccess/ssh/keys
    chmod 700 /data/f2netvpnaccess/ssh

    # Generate SSH key
    ssh-keygen -t ed25519 -a 100 -f /data/f2netvpnaccess/ssh/keys/id_host_access -q -N "" -C "f2netvpnaccess-host-access"

    # Add to authorized_keys
    if [ ! -f ~/.ssh/authorized_keys ]; then
        mkdir -p ~/.ssh
        chmod 700 ~/.ssh
        touch ~/.ssh/authorized_keys
        chmod 600 ~/.ssh/authorized_keys
    fi

    # Remove any previous entries
    sed -i "/f2netvpnaccess-host-access/d" ~/.ssh/authorized_keys

    # Add the new key
    cat /data/f2netvpnaccess/ssh/keys/id_host_access.pub >> ~/.ssh/authorized_keys

    # Set appropriate permissions for container access
    chown -R 1000:1000 /data/f2netvpnaccess
    chmod 600 /data/f2netvpnaccess/ssh/keys/id_host_access

    # Optional: Remove public key as it's no longer needed
    rm /data/f2netvpnaccess/ssh/keys/id_host_access.pub

    # Check SSH daemon configuration
    SSH_CONFIG="/etc/ssh/sshd_config"

    # Check PermitRootLogin setting
    ROOT_LOGIN_CONFIG=$(grep "^PermitRootLogin" $SSH_CONFIG 2>/dev/null)
    if [ -z "$ROOT_LOGIN_CONFIG" ]; then
        echo "Current configuration: PermitRootLogin setting not found or commented out"
    else
        echo "Current configuration: $ROOT_LOGIN_CONFIG"
    fi

    # Check PubkeyAuthentication setting
    PUBKEY_CONFIG=$(grep "^PubkeyAuthentication" $SSH_CONFIG 2>/dev/null)
    if [ -z "$PUBKEY_CONFIG" ]; then
        echo "Current configuration: PubkeyAuthentication setting not found or commented out"
    else
        echo "Current configuration: $PUBKEY_CONFIG"
    fi

    # Ask for confirmation to modify configuration
    echo ""
    echo "Recommended settings for container-to-host SSH access:"
    echo "  PermitRootLogin prohibit-password"
    echo "  PubkeyAuthentication yes"
    echo ""
    read -p "Do you want to update SSH configuration with these settings? (y/n): " CONFIRM

    if [ "$CONFIRM" = "y" ] || [ "$CONFIRM" = "Y" ]; then
        # Comment out any existing PermitRootLogin lines
        sed -i 's/^PermitRootLogin/#PermitRootLogin/' $SSH_CONFIG
        # Add our configuration
        echo "PermitRootLogin prohibit-password" >> $SSH_CONFIG

        # Comment out any existing PubkeyAuthentication lines
        sed -i 's/^PubkeyAuthentication/#PubkeyAuthentication/' $SSH_CONFIG
        # Add our configuration
        echo "PubkeyAuthentication yes" >> $SSH_CONFIG

        echo "SSH configuration updated. Restarting sshd..."
        # Check for systemd or alternative service managers
        if command -v systemctl >/dev/null 2>&1; then
            systemctl restart sshd
        elif command -v service >/dev/null 2>&1; then
            service sshd restart
        else
            echo "Warning: Could not restart sshd automatically. Please restart it manually."
        fi
    else
        echo "SSH configuration unchanged."
    fi
}

setup_sudo_permissions_secure() {
    print_header "Setting up secure sudo permissions"

    cat > /etc/sudoers.d/f2net_isp << 'EOF'
# F2Net ISP Service Permissions (Secure Version)
# Allow f2net_isp user to execute specific system commands without password

# Service management
f2net_isp ALL=(root) NOPASSWD: /bin/systemctl start openvpn@*
f2net_isp ALL=(root) NOPASSWD: /bin/systemctl stop openvpn@*
f2net_isp ALL=(root) NOPASSWD: /bin/systemctl restart openvpn@*
f2net_isp ALL=(root) NOPASSWD: /bin/systemctl status openvpn@*
f2net_isp ALL=(root) NOPASSWD: /bin/systemctl start freeradius
f2net_isp ALL=(root) NOPASSWD: /bin/systemctl stop freeradius
f2net_isp ALL=(root) NOPASSWD: /bin/systemctl restart freeradius
f2net_isp ALL=(root) NOPASSWD: /bin/systemctl reload freeradius
f2net_isp ALL=(root) NOPASSWD: /bin/systemctl status freeradius

# Network management
f2net_isp ALL=(root) NOPASSWD: /sbin/iptables *
f2net_isp ALL=(root) NOPASSWD: /sbin/ip *

# File access for reading logs and configs
# Allow both /bin and /usr/bin paths for compatibility
f2net_isp ALL=(root) NOPASSWD: /bin/cat /etc/openvpn/*
f2net_isp ALL=(root) NOPASSWD: /usr/bin/cat /etc/openvpn/*
f2net_isp ALL=(root) NOPASSWD: /bin/cat /etc/openvpn/server/*
f2net_isp ALL=(root) NOPASSWD: /usr/bin/cat /etc/openvpn/server/*
f2net_isp ALL=(root) NOPASSWD: /bin/cat /etc/openvpn/server/easy-rsa/pki/issued/*
f2net_isp ALL=(root) NOPASSWD: /usr/bin/cat /etc/openvpn/server/easy-rsa/pki/issued/*
f2net_isp ALL=(root) NOPASSWD: /bin/cat /etc/openvpn/server/easy-rsa/pki/private/*
f2net_isp ALL=(root) NOPASSWD: /usr/bin/cat /etc/openvpn/server/easy-rsa/pki/private/*
f2net_isp ALL=(root) NOPASSWD: /bin/cat /etc/openvpn/clients/*
f2net_isp ALL=(root) NOPASSWD: /usr/bin/cat /etc/openvpn/clients/*
f2net_isp ALL=(root) NOPASSWD: /bin/cat /etc/openvpn/client_metadata/*
f2net_isp ALL=(root) NOPASSWD: /usr/bin/cat /etc/openvpn/client_metadata/*
f2net_isp ALL=(root) NOPASSWD: /bin/tail /etc/openvpn/*
f2net_isp ALL=(root) NOPASSWD: /usr/bin/tail /etc/openvpn/*
f2net_isp ALL=(root) NOPASSWD: /bin/tail /var/log/*
f2net_isp ALL=(root) NOPASSWD: /usr/bin/tail /var/log/*
f2net_isp ALL=(root) NOPASSWD: /bin/cat /var/log/*
f2net_isp ALL=(root) NOPASSWD: /usr/bin/cat /var/log/*

# Directory listing permissions
f2net_isp ALL=(root) NOPASSWD: /bin/ls /etc/openvpn/*
f2net_isp ALL=(root) NOPASSWD: /usr/bin/ls /etc/openvpn/*
f2net_isp ALL=(root) NOPASSWD: /bin/ls /etc/openvpn/server/easy-rsa/pki/issued/*
f2net_isp ALL=(root) NOPASSWD: /usr/bin/ls /etc/openvpn/server/easy-rsa/pki/issued/*
f2net_isp ALL=(root) NOPASSWD: /bin/ls /etc/openvpn/server/easy-rsa/pki/private/*
f2net_isp ALL=(root) NOPASSWD: /usr/bin/ls /etc/openvpn/server/easy-rsa/pki/private/*
f2net_isp ALL=(root) NOPASSWD: /bin/ls /etc/openvpn/clients/*
f2net_isp ALL=(root) NOPASSWD: /usr/bin/ls /etc/openvpn/clients/*
f2net_isp ALL=(root) NOPASSWD: /bin/ls /etc/openvpn/client_metadata/*
f2net_isp ALL=(root) NOPASSWD: /usr/bin/ls /etc/openvpn/client_metadata/*

# File existence checks (secure - no content exposure)
f2net_isp ALL=(root) NOPASSWD: /bin/test -f /etc/openvpn/*
f2net_isp ALL=(root) NOPASSWD: /usr/bin/test -f /etc/openvpn/*
f2net_isp ALL=(root) NOPASSWD: /bin/test -f /etc/openvpn/server/*
f2net_isp ALL=(root) NOPASSWD: /usr/bin/test -f /etc/openvpn/server/*
f2net_isp ALL=(root) NOPASSWD: /bin/test -f /etc/openvpn/server/easy-rsa/pki/issued/*
f2net_isp ALL=(root) NOPASSWD: /usr/bin/test -f /etc/openvpn/server/easy-rsa/pki/issued/*
f2net_isp ALL=(root) NOPASSWD: /bin/test -f /etc/openvpn/server/easy-rsa/pki/private/*
f2net_isp ALL=(root) NOPASSWD: /usr/bin/test -f /etc/openvpn/server/easy-rsa/pki/private/*
f2net_isp ALL=(root) NOPASSWD: /bin/test -f /etc/openvpn/clients/*
f2net_isp ALL=(root) NOPASSWD: /usr/bin/test -f /etc/openvpn/clients/*
f2net_isp ALL=(root) NOPASSWD: /bin/test -f /etc/openvpn/client_metadata/*
f2net_isp ALL=(root) NOPASSWD: /usr/bin/test -f /etc/openvpn/client_metadata/*
f2net_isp ALL=(root) NOPASSWD: /bin/test -d /etc/openvpn/*
f2net_isp ALL=(root) NOPASSWD: /usr/bin/test -d /etc/openvpn/*

# OpenSSL operations
f2net_isp ALL=(root) NOPASSWD: /usr/bin/openssl *

# Journalctl for log access
f2net_isp ALL=(root) NOPASSWD: /usr/bin/journalctl -u openvpn@* -n * --no-pager
f2net_isp ALL=(root) NOPASSWD: /bin/journalctl -u openvpn@* -n * --no-pager

# Custom scripts (recommended approach)
f2net_isp ALL=(root) NOPASSWD: /opt/f2net_isp/scripts/
EOF

    chmod 440 /etc/sudoers.d/f2net_isp

    # Validate sudoers file
    if ! visudo -c -f /etc/sudoers.d/f2net_isp; then
        print_error "Sudoers file validation failed"
        rm -f /etc/sudoers.d/f2net_isp
        return 1
    fi

    # Create comprehensive management scripts
    mkdir -p /opt/f2net_isp/scripts
    create_management_scripts

    print_success "Secure sudo permissions configured"
}

# Create comprehensive management scripts
create_management_scripts() {
    # OpenVPN management script
    cat > /opt/f2net_isp/scripts/manage_openvpn.sh << 'EOF'
#!/bin/bash
# OpenVPN Management Script
set -euo pipefail

ACTION="$1"
CONFIG_NAME="${2:-}"

validate_config_name() {
    if [[ ! "$1" =~ ^f2net_[a-zA-Z0-9_-]+$ ]]; then
        echo "Error: Invalid config name format"
        exit 1
    fi
}

case "$ACTION" in
    "deploy_config")
        validate_config_name "$CONFIG_NAME"
        if [[ -f "/tmp/${CONFIG_NAME}.conf" ]]; then
            cp "/tmp/${CONFIG_NAME}.conf" "/etc/openvpn/"
            chmod 600 "/etc/openvpn/${CONFIG_NAME}.conf"
            chown root:root "/etc/openvpn/${CONFIG_NAME}.conf"
            echo "Config deployed: ${CONFIG_NAME}"
        fi
        ;;
    "remove_config")
        validate_config_name "$CONFIG_NAME"
        rm -f "/etc/openvpn/${CONFIG_NAME}".{conf,key,crt,pem}
        echo "Config removed: ${CONFIG_NAME}"
        ;;
    "start")
        validate_config_name "$CONFIG_NAME"
        systemctl start "openvpn@${CONFIG_NAME}"
        ;;
    "stop")
        validate_config_name "$CONFIG_NAME"
        systemctl stop "openvpn@${CONFIG_NAME}"
        ;;
    "restart")
        validate_config_name "$CONFIG_NAME"
        systemctl restart "openvpn@${CONFIG_NAME}"
        ;;
    *)
        echo "Usage: $0 {deploy_config|remove_config|start|stop|restart} <config_name>"
        exit 1
        ;;
esac
EOF

    # Certificate management script
    cat > /opt/f2net_isp/scripts/manage_certificates.sh << 'EOF'
#!/bin/bash
# Certificate Management Script
set -euo pipefail

ACTION="$1"
CERT_NAME="${2:-}"

validate_cert_name() {
    if [[ ! "$1" =~ ^f2net_[a-zA-Z0-9_-]+$ ]]; then
        echo "Error: Invalid certificate name format"
        exit 1
    fi
}

case "$ACTION" in
    "generate_client")
        validate_cert_name "$CERT_NAME"
        cd /etc/openvpn/server/easy-rsa/ || exit 1
        echo "yes" | ./easyrsa build-client-full "$CERT_NAME" nopass
        echo "Client certificate generated: ${CERT_NAME}"
        ;;
    "revoke_client")
        validate_cert_name "$CERT_NAME"
        cd /etc/openvpn/server/easy-rsa/ || exit 1
        echo "yes" | ./easyrsa revoke "$CERT_NAME"
        echo "yes" | ./easyrsa gen-crl
        echo "Client certificate revoked: ${CERT_NAME}"
        ;;
    "sign_client")
        validate_cert_name "$CERT_NAME"
        cd /etc/openvpn/server/easy-rsa/ || exit 1
        echo "Signing existing client request: $CERT_NAME"
        echo "yes" | ./easyrsa sign-req client "$CERT_NAME"
        ;;
    "list_certificates")
        if [[ -f "/etc/openvpn/server/easy-rsa/pki/ca.crt" ]]; then
            openssl x509 -in /etc/openvpn/server/easy-rsa/pki/ca.crt -noout -text
        else
            echo "CA certificate not found"
        fi
        ;;
    *)
        echo "Usage: $0 {generate_client|revoke_client|list_certificates} [cert_name]"
        exit 1
        ;;
esac
EOF

    # Set permissions on scripts
    chmod 755 /opt/f2net_isp/scripts/*.sh
    chown root:root /opt/f2net_isp/scripts/*.sh
}

# Add validation function
validate_sudoers() {
    if [[ -f "/etc/sudoers.d/f2net_isp" ]]; then
        if visudo -c -f /etc/sudoers.d/f2net_isp; then
            print_success "Sudoers file validation passed"
            return 0
        else
            print_error "Sudoers file validation failed"
            return 1
        fi
    else
        print_error "Sudoers file not found"
        return 1
    fi
}

install_system_packages() {
    print_header "Installing system packages"

    if [[ "$OS" == *"Ubuntu"* ]] || [[ "$OS" == *"Debian"* ]] || [[ "$OS" == *"Zorin OS"* ]]; then
        apt update
        apt install -y \
            python3 \
            python3-pip \
            python3-venv \
            python3-dev \
            postgresql \
            postgresql-contrib \
            redis-server \
            nginx \
            git \
            curl \
            wget \
            build-essential \
            libpq-dev \
            libssl-dev \
            libffi-dev \
            openvpn \
            easy-rsa \
            freeradius \
            freeradius-utils \
            freeradius-postgresql \
            supervisor \
            logrotate \
            fail2ban \
            ufw \
            htop \
            tree \
            nano \
            vim

    elif [[ "$OS" == *"CentOS"* ]] || [[ "$OS" == *"Red Hat"* ]] || [[ "$OS" == *"Rocky"* ]]; then
        yum update -y
        yum groupinstall -y "Development Tools"
        yum install -y \
            python3 \
            python3-pip \
            python3-devel \
            postgresql \
            postgresql-server \
            postgresql-contrib \
            redis \
            nginx \
            git \
            curl \
            wget \
            openssl-devel \
            libffi-devel \
            openvpn \
            easy-rsa \
            freeradius \
            freeradius-utils \
            freeradius-postgresql \
            supervisor \
            logrotate \
            fail2ban \
            firewalld \
            htop \
            tree \
            nano \
            vim
    else
        print_error "Unsupported operating system: $OS"
        exit 1
    fi

    print_success "System packages installed"
}

create_user() {
    print_header "Creating application user"

    if ! id "$APP_USER" &>/dev/null; then
        useradd --system --home "$APP_DIR" --shell /bin/bash "$APP_USER"
        print_success "User $APP_USER created"
    else
        print_warning "User $APP_USER already exists"
    fi
}

create_directories() {
    print_header "Creating application directories"

    # Create main directories
    mkdir -p "$APP_DIR"
    mkdir -p "$LOG_DIR"
    mkdir -p "$CONFIG_DIR"
    mkdir -p "$BACKUP_DIR"
    mkdir -p "/var/uploads/f2net_isp"

    # Create subdirectories
    mkdir -p "$LOG_DIR/nginx"
    mkdir -p "$LOG_DIR/gunicorn"
    mkdir -p "$LOG_DIR/celery"
    mkdir -p "$CONFIG_DIR/nginx"
    mkdir -p "$CONFIG_DIR/supervisor"

    # Create and set permissions for OpenVPN directories
    # These directories are needed by the application to store client configs
    print_status "Setting up OpenVPN directories for $APP_USER"

    # Create /etc/openvpn if it doesn't exist and set proper permissions
    mkdir -p /etc/openvpn
    chmod 755 /etc/openvpn
    print_status "Created /etc/openvpn base directory"

    # Create clients directory
    mkdir -p /etc/openvpn/clients
    chown -R "$APP_USER:$APP_USER" /etc/openvpn/clients
    chmod 775 /etc/openvpn/clients
    print_status "Set permissions for /etc/openvpn/clients (775, owned by $APP_USER)"

    # Create client_metadata directory
    mkdir -p /etc/openvpn/client_metadata
    chown -R "$APP_USER:$APP_USER" /etc/openvpn/client_metadata
    chmod 775 /etc/openvpn/client_metadata
    print_status "Set permissions for /etc/openvpn/client_metadata (775, owned by $APP_USER)"

    # Create ccd directory if needed
    mkdir -p /etc/openvpn/ccd
    chown -R "$APP_USER:$APP_USER" /etc/openvpn/ccd
    chmod 775 /etc/openvpn/ccd
    print_status "Set permissions for /etc/openvpn/ccd (775, owned by $APP_USER)"

    # Create keys directory
    mkdir -p /etc/openvpn/keys
    chown -R "$APP_USER:$APP_USER" /etc/openvpn/keys
    chmod 775 /etc/openvpn/keys
    print_status "Set permissions for /etc/openvpn/keys (775, owned by $APP_USER)"

    # Verify permissions were set correctly
    if [ -w /etc/openvpn/clients ] && [ -w /etc/openvpn/client_metadata ] && [ -w /etc/openvpn/ccd ] && [ -w /etc/openvpn/keys ]; then
        print_success "All OpenVPN directories are writable by $APP_USER"
    else
        print_warning "Some OpenVPN directories may not be writable. Check permissions manually."
    fi

    # Set permissions
    chown -R "$APP_USER:$APP_USER" "$APP_DIR"
    chown -R "$APP_USER:$APP_USER" "$LOG_DIR"
    chown -R "$APP_USER:$APP_USER" "$BACKUP_DIR"
    chown -R "$APP_USER:$APP_USER" "/var/uploads/f2net_isp"

    print_success "Directories created and permissions set"
}

setup_database() {
    print_header "Setting up PostgreSQL database"

    # Start PostgreSQL service
    systemctl start postgresql
    systemctl enable postgresql

    # Create database and user
    sudo -u postgres psql -c "CREATE DATABASE f2net_isp;" 2>/dev/null || print_warning "Database may already exist"
    sudo -u postgres psql -c "CREATE USER isp_user WITH PASSWORD 'isp_password';" 2>/dev/null || print_warning "User may already exist"
    sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE f2net_isp TO isp_user;" 2>/dev/null
    sudo -u postgres psql -c "ALTER USER isp_user CREATEDB;" 2>/dev/null

    print_success "PostgreSQL database configured"
}

setup_redis() {
    print_header "Setting up Redis"

    # Determine Redis service name based on OS
    REDIS_SERVICE="redis"
    if [[ "$OS" == *"Ubuntu"* ]] || [[ "$OS" == *"Debian"* ]] || [[ "$OS" == *"Zorin OS"* ]]; then
        REDIS_SERVICE="redis-server"
    fi

    # Start Redis service
    systemctl start $REDIS_SERVICE
    systemctl enable $REDIS_SERVICE

    # Configure Redis for production
    # Create Redis configuration directory if it doesn't exist
    mkdir -p /etc/redis/redis.conf.d/

    cat > /etc/redis/redis.conf.d/f2net_isp.conf << EOF
# F2Net Redis Configuration
maxmemory 256mb
maxmemory-policy allkeys-lru
save 900 1
save 300 10
save 60 10000
EOF

    systemctl restart $REDIS_SERVICE
    print_success "Redis configured"
}

install_python_app() {
    print_header "Installing Python application"

    # Switch to app user
    sudo -u "$APP_USER" bash << EOF
cd "$APP_DIR"

# Create virtual environment
python3 -m venv "$VENV_DIR"
source "$VENV_DIR/bin/activate"

# Upgrade pip
pip install --upgrade pip setuptools wheel

# Install application dependencies
if [[ -f "requirements.txt" ]]; then
    pip install -r requirements.txt
else
    echo "Warning: requirements.txt not found, installing basic packages"
    pip install flask gunicorn psycopg2-binary redis celery structlog
fi

# Install additional production packages
pip install gunicorn psycopg2-binary

echo "[SUCCESS] Python application installed"
EOF

    print_success "Python application installed"
}

check_env_file() {
    print_header "Checking .env file"

    local source_env="$APP_DIR/.env"

    if [[ ! -f "$source_env" ]]; then
        print_error ".env file not found at $source_env"
        print_error "Setup cannot continue without .env file"
        print_status "Please create .env file with required environment variables"
        print_status ""
        print_status "You can create a template with:"
        print_status "  cp .env.example .env"
        print_status ""
        print_status "Required variables:"
        echo "  - SECRET_KEY"
        echo "  - JWT_SECRET_KEY"
        echo "  - DATABASE_URL"
        echo "  - REDIS_URL"
        echo "  - OPENVPN_SERVER_HOST"
        exit 1
    fi

    print_success ".env file found at $source_env"
}

validate_env_file() {
    print_header "Validating .env configuration"

    local source_env="$APP_DIR/.env"
    local required_vars=("SECRET_KEY" "DATABASE_URL" "REDIS_URL")
    local missing_vars=()

    for var in "${required_vars[@]}"; do
        if ! grep -q "^${var}=" "$source_env" 2>/dev/null; then
            missing_vars+=("$var")
        fi
    done

    if [[ ${#missing_vars[@]} -gt 0 ]]; then
        print_warning "Missing required variables in .env file:"
        for var in "${missing_vars[@]}"; do
            echo "  - $var"
        done
        echo ""
        read -p "Generate missing SECRET_KEY and JWT_SECRET_KEY automatically? (Y/n): " generate_keys
        if [[ ! "$generate_keys" =~ ^[Nn]$ ]]; then
            generate_missing_keys "$source_env"
        else
            print_error "Cannot proceed without required environment variables"
            exit 1
        fi
    fi

    print_success "Environment file validation passed"
}

generate_missing_keys() {
    local env_file="$1"
    print_status "Generating missing secret keys..."

    # Backup .env file
    cp "$env_file" "$env_file.backup.$(date +%Y%m%d_%H%M%S)"

    # Generate and add SECRET_KEY if missing
    if ! grep -q "^SECRET_KEY=" "$env_file" 2>/dev/null; then
        echo "" >> "$env_file"
        echo "# Generated by setup script on $(date)" >> "$env_file"
        echo "SECRET_KEY=$(openssl rand -hex 32)" >> "$env_file"
        print_success "SECRET_KEY generated"
    fi

    # Generate and add JWT_SECRET_KEY if missing
    if ! grep -q "^JWT_SECRET_KEY=" "$env_file" 2>/dev/null; then
        echo "JWT_SECRET_KEY=$(openssl rand -hex 32)" >> "$env_file"
        print_success "JWT_SECRET_KEY generated"
    fi
}

setup_environment() {
    print_header "Setting up environment configuration"

    local source_env="$APP_DIR/.env"
    local target_env="$CONFIG_DIR/f2net_isp.env"

    # Validate source .env file exists and has required variables
    check_env_file
    validate_env_file

    # Copy .env file to config directory
    print_status "Copying .env to $target_env"
    cp "$source_env" "$target_env"

    # Set secure permissions
    chown "$APP_USER:$APP_USER" "$target_env"
    chmod 600 "$target_env"

    print_success "Environment configuration installed from .env file"

    # Display current configuration (sanitized)
    print_status "Current configuration summary:"
    echo "  FLASK_ENV: $(grep '^FLASK_ENV=' "$target_env" 2>/dev/null | cut -d'=' -f2 || echo 'production (default)')"
    echo "  DATABASE_URL: $(grep '^DATABASE_URL=' "$target_env" 2>/dev/null | cut -d'=' -f2 | sed 's/:.*@/:***@/' || echo 'Not set')"
    echo "  REDIS_URL: $(grep '^REDIS_URL=' "$target_env" 2>/dev/null | cut -d'=' -f2 || echo 'Not set')"
    echo "  OPENVPN_CONFIG_DIR: $(grep '^OPENVPN_CONFIG_DIR=' "$target_env" 2>/dev/null | cut -d'=' -f2 || echo '/etc/openvpn (default)')"
}

setup_nginx() {
    print_header "Setting up Nginx"

    # Create Nginx configuration
    cat > "$CONFIG_DIR/nginx/f2net_isp.conf" << EOF
upstream f2net_isp {
    server 127.0.0.1:5000;
}

server {
    listen 80;
    server_name _;

    client_max_body_size 16M;

    # Security headers
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

    # API endpoints
    location /api/ {
        proxy_pass http://f2net_isp;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }

    # Health check
    location /health {
        proxy_pass http://f2net_isp;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }

    # Metrics (restrict access)
    location /metrics {
        allow 127.0.0.1;
        allow 10.0.0.0/8;
        allow 192.168.0.0/16;
        deny all;

        proxy_pass http://f2net_isp;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }

    # Static files (if any)
    location /static/ {
        alias $APP_DIR/static/;
        expires 1y;
        add_header Cache-Control "public, immutable";
    }

    # Default location
    location / {
        return 404;
    }

    # Logging
    access_log $LOG_DIR/nginx/access.log;
    error_log $LOG_DIR/nginx/error.log;
}
EOF

    # Link configuration
    ln -sf "$CONFIG_DIR/nginx/f2net_isp.conf" /etc/nginx/sites-available/f2net_isp
    ln -sf /etc/nginx/sites-available/f2net_isp /etc/nginx/sites-enabled/f2net_isp

    # Remove default site
    rm -f /etc/nginx/sites-enabled/default

    # Test configuration
    nginx -t

    systemctl restart nginx
    systemctl enable nginx

    print_success "Nginx configured"
}

setup_systemd_services() {
    print_header "Setting up systemd services"

    # Flask application service
    cat > "$SYSTEMD_DIR/f2net-isp.service" << EOF
[Unit]
Description=F2Net Flask Application
After=network.target postgresql.service redis.service
Wants=postgresql.service redis.service

[Service]
Type=exec
User=$APP_USER
Group=$APP_USER
WorkingDirectory=$APP_DIR
Environment=PATH=$VENV_DIR/bin
EnvironmentFile=$CONFIG_DIR/f2net_isp.env
ExecStart=$VENV_DIR/bin/gunicorn --bind 127.0.0.1:5000 --workers 4 --timeout 60 --keep-alive 5 --access-logfile $LOG_DIR/gunicorn/access.log --error-logfile $LOG_DIR/gunicorn/error.log wsgi:app
ExecReload=/bin/kill -s HUP \$MAINPID
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

    # Celery worker service
    cat > "$SYSTEMD_DIR/f2net-isp-celery.service" << EOF
[Unit]
Description=F2Net Celery Worker
After=network.target redis.service
Wants=redis.service

[Service]
Type=exec
User=$APP_USER
Group=$APP_USER
WorkingDirectory=$APP_DIR
Environment=PATH=$VENV_DIR/bin
EnvironmentFile=$CONFIG_DIR/f2net_isp.env
ExecStart=$VENV_DIR/bin/celery -A app.celery worker --loglevel=info --logfile=$LOG_DIR/celery/worker.log
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

    # Celery beat service (scheduler)
    cat > "$SYSTEMD_DIR/f2net-isp-celery-beat.service" << EOF
[Unit]
Description=F2Net Celery Beat Scheduler
After=network.target redis.service
Wants=redis.service

[Service]
Type=exec
User=$APP_USER
Group=$APP_USER
WorkingDirectory=$APP_DIR
Environment=PATH=$VENV_DIR/bin
EnvironmentFile=$CONFIG_DIR/f2net_isp.env
ExecStart=$VENV_DIR/bin/celery -A app.celery beat --loglevel=info --logfile=$LOG_DIR/celery/beat.log
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

    # Reload systemd and enable services
    systemctl daemon-reload
    systemctl enable f2net-isp
    systemctl enable f2net-isp-celery
    systemctl enable f2net-isp-celery-beat

    print_success "Systemd services configured"
}

setup_logrotate() {
    print_header "Setting up log rotation"

    cat > /etc/logrotate.d/f2net-isp << EOF
$LOG_DIR/*.log {
    daily
    missingok
    rotate 52
    compress
    delaycompress
    notifempty
    create 0644 $APP_USER $APP_USER
    postrotate
        systemctl reload f2net-isp
    endscript
}

$LOG_DIR/*/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    create 0644 $APP_USER $APP_USER
}
EOF

    print_success "Log rotation configured"
}

setup_firewall() {
    print_header "Setting up firewall"

    if command -v ufw &> /dev/null; then
        # Ubuntu/Debian UFW
        ufw --force enable
        ufw default deny incoming
        ufw default allow outgoing
        ufw allow ssh
        ufw allow 80/tcp
        ufw allow 443/tcp
        ufw allow from 10.0.0.0/8 to any port 5000  # Internal Flask access
        ufw allow from 192.168.0.0/16 to any port 5000

    elif command -v firewall-cmd &> /dev/null; then
        # CentOS/RHEL firewalld
        systemctl start firewalld
        systemctl enable firewalld
        firewall-cmd --permanent --add-service=http
        firewall-cmd --permanent --add-service=https
        firewall-cmd --permanent --add-service=ssh
        firewall-cmd --reload
    fi

    print_success "Firewall configured"
}

setup_openvpn() {
    print_header "Setting up OpenVPN"

if [[ ! -e /etc/openvpn/server/server.conf ]]; then
	# Detect some Debian minimal setups where neither wget nor curl are installed
	if ! hash wget 2>/dev/null && ! hash curl 2>/dev/null; then
		echo "Wget is required to use this installer."
		read -n1 -r -p "Press any key to install Wget and continue..."
		apt-get update
		apt-get install -y wget
	fi
	clear
	echo 'Welcome to this OpenVPN road warrior installer!'
	# If system has a single IPv4, it is selected automatically. Else, ask the user
	if [[ $(ip -4 addr | grep inet | grep -vEc '127(\.[0-9]{1,3}){3}') -eq 1 ]]; then
		ip=$(ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}')
	else
		number_of_ip=$(ip -4 addr | grep inet | grep -vEc '127(\.[0-9]{1,3}){3}')
		echo
		echo "Which IPv4 address should be used?"
		ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | nl -s ') '
		read -p "IPv4 address [1]: " ip_number
		until [[ -z "$ip_number" || "$ip_number" =~ ^[0-9]+$ && "$ip_number" -le "$number_of_ip" ]]; do
			echo "$ip_number: invalid selection."
			read -p "IPv4 address [1]: " ip_number
		done
		[[ -z "$ip_number" ]] && ip_number="1"
		ip=$(ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | sed -n "$ip_number"p)
	fi
	# If $ip is a private IP address, the server must be behind NAT
	if echo "$ip" | grep -qE '^(10\.|172\.1[6789]\.|172\.2[0-9]\.|172\.3[01]\.|192\.168)'; then
		echo
		echo "This server is behind NAT. What is the public IPv4 address or hostname?"
		# Get public IP and sanitize with grep
		get_public_ip=$(grep -m 1 -oE '^[0-9]{1,3}(\.[0-9]{1,3}){3}$' <<< "$(wget -T 10 -t 1 -4qO- "http://ip1.dynupdate.no-ip.com/" || curl -m 10 -4Ls "http://ip1.dynupdate.no-ip.com/")")
		read -p "Public IPv4 address / hostname [$get_public_ip]: " public_ip
		# If the checkip service is unavailable and user didn't provide input, ask again
		until [[ -n "$get_public_ip" || -n "$public_ip" ]]; do
			echo "Invalid input."
			read -p "Public IPv4 address / hostname: " public_ip
		done
		[[ -z "$public_ip" ]] && public_ip="$get_public_ip"
	fi
	# If system has a single IPv6, it is selected automatically
	if [[ $(ip -6 addr | grep -c 'inet6 [23]') -eq 1 ]]; then
		ip6=$(ip -6 addr | grep 'inet6 [23]' | cut -d '/' -f 1 | grep -oE '([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}')
	fi
	# If system has multiple IPv6, ask the user to select one
	if [[ $(ip -6 addr | grep -c 'inet6 [23]') -gt 1 ]]; then
		number_of_ip6=$(ip -6 addr | grep -c 'inet6 [23]')
		echo
		echo "Which IPv6 address should be used?"
		ip -6 addr | grep 'inet6 [23]' | cut -d '/' -f 1 | grep -oE '([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}' | nl -s ') '
		read -p "IPv6 address [1]: " ip6_number
		until [[ -z "$ip6_number" || "$ip6_number" =~ ^[0-9]+$ && "$ip6_number" -le "$number_of_ip6" ]]; do
			echo "$ip6_number: invalid selection."
			read -p "IPv6 address [1]: " ip6_number
		done
		[[ -z "$ip6_number" ]] && ip6_number="1"
		ip6=$(ip -6 addr | grep 'inet6 [23]' | cut -d '/' -f 1 | grep -oE '([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}' | sed -n "$ip6_number"p)
	fi
	echo
	echo "Which protocol should OpenVPN use?"
	echo "   1) UDP (recommended)"
	echo "   2) TCP"
	read -p "Protocol [1]: " protocol
	until [[ -z "$protocol" || "$protocol" =~ ^[12]$ ]]; do
		echo "$protocol: invalid selection."
		read -p "Protocol [1]: " protocol
	done
	case "$protocol" in
		1|"")
		protocol=udp
		;;
		2)
		protocol=tcp
		;;
	esac
	echo
	echo "What port should OpenVPN listen on?"
	read -p "Port [1194]: " port
	until [[ -z "$port" || "$port" =~ ^[0-9]+$ && "$port" -le 65535 ]]; do
		echo "$port: invalid port."
		read -p "Port [1194]: " port
	done
	[[ -z "$port" ]] && port="1194"
	echo
	echo "Select a DNS server for the clients:"
	echo "   1) Default system resolvers"
	echo "   2) Google"
	echo "   3) 1.1.1.1"
	echo "   4) OpenDNS"
	echo "   5) Quad9"
	echo "   6) AdGuard"
	echo "   7) Specify custom resolvers"
	read -p "DNS server [1]: " dns
	until [[ -z "$dns" || "$dns" =~ ^[1-7]$ ]]; do
		echo "$dns: invalid selection."
		read -p "DNS server [1]: " dns
	done
	# If the user selected custom resolvers, we deal with that here
	if [[ "$dns" = "7" ]]; then
		echo
		until [[ -n "$custom_dns" ]]; do
			echo "Enter DNS servers (one or more IPv4 addresses, separated by commas or spaces):"
			read -p "DNS servers: " dns_input
			# Convert comma delimited to space delimited
			dns_input=$(echo "$dns_input" | tr ',' ' ')
			# Validate and build custom DNS IP list
			for dns_ip in $dns_input; do
				if [[ "$dns_ip" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]]; then
					if [[ -z "$custom_dns" ]]; then
						custom_dns="$dns_ip"
					else
						custom_dns="$custom_dns $dns_ip"
					fi
				fi
			done
			if [ -z "$custom_dns" ]; then
				echo "Invalid input."
			fi
		done
	fi
	echo
	echo "Enter a name for the first client:"
	read -p "Name [client]: " unsanitized_client
	# Allow a limited set of characters to avoid conflicts
	client=$(sed 's/[^0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-]/_/g' <<< "$unsanitized_client")
	[[ -z "$client" ]] && client="client"
	echo
	echo "OpenVPN installation is ready to begin."
	# Install a firewall if firewalld or iptables are not already available
	if ! systemctl is-active --quiet firewalld.service && ! hash iptables 2>/dev/null; then
		if [[ "$os" == "centos" || "$os" == "fedora" ]]; then
			firewall="firewalld"
			# We don't want to silently enable firewalld, so we give a subtle warning
			# If the user continues, firewalld will be installed and enabled during setup
			echo "firewalld, which is required to manage routing tables, will also be installed."
		elif [[ "$os" == "debian" || "$os" == "ubuntu" ]]; then
			# iptables is way less invasive than firewalld so no warning is given
			firewall="iptables"
		fi
	fi
	read -n1 -r -p "Press any key to continue..."
	# If running inside a container, disable LimitNPROC to prevent conflicts
	if systemd-detect-virt -cq; then
		mkdir /etc/systemd/system/openvpn-server@server.service.d/ 2>/dev/null
		echo "[Service]
LimitNPROC=infinity" > /etc/systemd/system/openvpn-server@server.service.d/disable-limitnproc.conf
	fi
	if [[ "$os" = "debian" || "$os" = "ubuntu" ]]; then
		apt-get update
		apt-get install -y --no-install-recommends openvpn openssl ca-certificates $firewall
	elif [[ "$os" = "centos" ]]; then
		apt install -y epel-release
		apt install -y openvpn openssl ca-certificates tar $firewall
	else
		# Else, OS must be Fedora
		apt install -y openvpn openssl ca-certificates tar $firewall
	fi
	# If firewalld was just installed, enable it
	if [[ "$firewall" == "firewalld" ]]; then
		systemctl enable --now firewalld.service
	fi
	# Get easy-rsa
	easy_rsa_url='https://github.com/OpenVPN/easy-rsa/releases/download/v3.2.3/EasyRSA-3.2.3.tgz'
	mkdir -p /etc/openvpn/server/easy-rsa/
	{ wget -qO- "$easy_rsa_url" 2>/dev/null || curl -sL "$easy_rsa_url" ; } | tar xz -C /etc/openvpn/server/easy-rsa/ --strip-components 1
	chown -R root:root /etc/openvpn/server/easy-rsa/
	cd /etc/openvpn/server/easy-rsa/
	# Create the PKI, set up the CA and create TLS key
	./easyrsa --batch init-pki
	./easyrsa --batch build-ca nopass
	./easyrsa gen-tls-crypt-key
	# Create the DH parameters file using the predefined ffdhe2048 group
	echo '-----BEGIN DH PARAMETERS-----
MIIBCAKCAQEA//////////+t+FRYortKmq/cViAnPTzx2LnFg84tNpWp4TZBFGQz
+8yTnc4kmz75fS/jY2MMddj2gbICrsRhetPfHtXV/WVhJDP1H18GbtCFY2VVPe0a
87VXE15/V8k1mE8McODmi3fipona8+/och3xWKE2rec1MKzKT0g6eXq8CrGCsyT7
YdEIqUuyyOP7uWrat2DX9GgdT0Kj3jlN9K5W7edjcrsZCwenyO4KbXCeAvzhzffi
7MA0BM0oNC9hkXL+nOmFg/+OTxIy7vKBg8P+OxtMb61zO7X8vC7CIAXFjvGDfRaD
ssbzSibBsu/6iGtCOGEoXJf//////////wIBAg==
-----END DH PARAMETERS-----' > /etc/openvpn/server/dh.pem
	# Make easy-rsa aware of our external DH file (prevents a warning)
	ln -s /etc/openvpn/server/dh.pem pki/dh.pem
	# Create certificates and CRL
	./easyrsa --batch --days=3650 build-server-full server nopass
	./easyrsa --batch --days=3650 build-client-full "$client" nopass
	./easyrsa --batch --days=3650 gen-crl
	# Move the stuff we need
	cp pki/ca.crt pki/private/ca.key pki/issued/server.crt pki/private/server.key pki/crl.pem /etc/openvpn/server
	cp pki/private/easyrsa-tls.key /etc/openvpn/server/tc.key
	# CRL is read with each client connection, while OpenVPN is dropped to nobody
	chown nobody:"$group_name" /etc/openvpn/server/crl.pem
	# Without +x in the directory, OpenVPN can't run a stat() on the CRL file
	chmod o+x /etc/openvpn/server/
	# Generate server.conf
	echo "local $ip
port $port
proto $protocol
dev tun
ca ca.crt
cert server.crt
key server.key
dh dh.pem
auth SHA512
tls-crypt tc.key
topology subnet
server 10.8.0.0 255.255.255.0" > /etc/openvpn/server/server.conf
	# IPv6
	if [[ -z "$ip6" ]]; then
		echo 'push "redirect-gateway def1 bypass-dhcp"' >> /etc/openvpn/server/server.conf
	else
		echo 'server-ipv6 fddd:1194:1194:1194::/64' >> /etc/openvpn/server/server.conf
		echo 'push "redirect-gateway def1 ipv6 bypass-dhcp"' >> /etc/openvpn/server/server.conf
	fi
	echo 'ifconfig-pool-persist ipp.txt' >> /etc/openvpn/server/server.conf
	# DNS
	case "$dns" in
		1|"")
			# Locate the proper resolv.conf
			# Needed for systems running systemd-resolved
			if grep '^nameserver' "/etc/resolv.conf" | grep -qv '127.0.0.53' ; then
				resolv_conf="/etc/resolv.conf"
			else
				resolv_conf="/run/systemd/resolve/resolv.conf"
			fi
			# Obtain the resolvers from resolv.conf and use them for OpenVPN
			grep -v '^#\|^;' "$resolv_conf" | grep '^nameserver' | grep -v '127.0.0.53' | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | while read line; do
				echo "push \"dhcp-option DNS $line\"" >> /etc/openvpn/server/server.conf
			done
		;;
		2)
			echo 'push "dhcp-option DNS 8.8.8.8"' >> /etc/openvpn/server/server.conf
			echo 'push "dhcp-option DNS 8.8.4.4"' >> /etc/openvpn/server/server.conf
		;;
		3)
			echo 'push "dhcp-option DNS 1.1.1.1"' >> /etc/openvpn/server/server.conf
			echo 'push "dhcp-option DNS 1.0.0.1"' >> /etc/openvpn/server/server.conf
		;;
		4)
			echo 'push "dhcp-option DNS 208.67.222.222"' >> /etc/openvpn/server/server.conf
			echo 'push "dhcp-option DNS 208.67.220.220"' >> /etc/openvpn/server/server.conf
		;;
		5)
			echo 'push "dhcp-option DNS 9.9.9.9"' >> /etc/openvpn/server/server.conf
			echo 'push "dhcp-option DNS 149.112.112.112"' >> /etc/openvpn/server/server.conf
		;;
		6)
			echo 'push "dhcp-option DNS 94.140.14.14"' >> /etc/openvpn/server/server.conf
			echo 'push "dhcp-option DNS 94.140.15.15"' >> /etc/openvpn/server/server.conf
		;;
		7)
		for dns_ip in $custom_dns; do
			echo "push \"dhcp-option DNS $dns_ip\"" >> /etc/openvpn/server/server.conf
		done
		;;
	esac
	echo 'push "block-outside-dns"' >> /etc/openvpn/server/server.conf
	echo "keepalive 10 120
user nobody
group $group_name
persist-key
persist-tun
verb 3
crl-verify crl.pem" >> /etc/openvpn/server/server.conf
	if [[ "$protocol" = "udp" ]]; then
		echo "explicit-exit-notify" >> /etc/openvpn/server/server.conf
	fi
	# Enable net.ipv4.ip_forward for the system
	echo 'net.ipv4.ip_forward=1' > /etc/sysctl.d/99-openvpn-forward.conf
	# Enable without waiting for a reboot or service restart
	echo 1 > /proc/sys/net/ipv4/ip_forward
	if [[ -n "$ip6" ]]; then
		# Enable net.ipv6.conf.all.forwarding for the system
		echo "net.ipv6.conf.all.forwarding=1" >> /etc/sysctl.d/99-openvpn-forward.conf
		# Enable without waiting for a reboot or service restart
		echo 1 > /proc/sys/net/ipv6/conf/all/forwarding
	fi
	if systemctl is-active --quiet firewalld.service; then
		# Using both permanent and not permanent rules to avoid a firewalld
		# reload.
		# We don't use --add-service=openvpn because that would only work with
		# the default port and protocol.
		firewall-cmd --add-port="$port"/"$protocol"
		firewall-cmd --zone=trusted --add-source=10.8.0.0/24
		firewall-cmd --permanent --add-port="$port"/"$protocol"
		firewall-cmd --permanent --zone=trusted --add-source=10.8.0.0/24
		# Set NAT for the VPN subnet
		firewall-cmd --direct --add-rule ipv4 nat POSTROUTING 0 -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to "$ip"
		firewall-cmd --permanent --direct --add-rule ipv4 nat POSTROUTING 0 -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to "$ip"
		if [[ -n "$ip6" ]]; then
			firewall-cmd --zone=trusted --add-source=fddd:1194:1194:1194::/64
			firewall-cmd --permanent --zone=trusted --add-source=fddd:1194:1194:1194::/64
			firewall-cmd --direct --add-rule ipv6 nat POSTROUTING 0 -s fddd:1194:1194:1194::/64 ! -d fddd:1194:1194:1194::/64 -j SNAT --to "$ip6"
			firewall-cmd --permanent --direct --add-rule ipv6 nat POSTROUTING 0 -s fddd:1194:1194:1194::/64 ! -d fddd:1194:1194:1194::/64 -j SNAT --to "$ip6"
		fi
	else
		# Create a service to set up persistent iptables rules
		iptables_path=$(command -v iptables)
		ip6tables_path=$(command -v ip6tables)
		# nf_tables is not available as standard in OVZ kernels. So use iptables-legacy
		# if we are in OVZ, with a nf_tables backend and iptables-legacy is available.
		if [[ $(systemd-detect-virt) == "openvz" ]] && readlink -f "$(command -v iptables)" | grep -q "nft" && hash iptables-legacy 2>/dev/null; then
			iptables_path=$(command -v iptables-legacy)
			ip6tables_path=$(command -v ip6tables-legacy)
		fi
		echo "[Unit]
After=network-online.target
Wants=network-online.target
[Service]
Type=oneshot
ExecStart=$iptables_path -w 5 -t nat -A POSTROUTING -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to $ip
ExecStart=$iptables_path -w 5 -I INPUT -p $protocol --dport $port -j ACCEPT
ExecStart=$iptables_path -w 5 -I FORWARD -s 10.8.0.0/24 -j ACCEPT
ExecStart=$iptables_path -w 5 -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
ExecStop=$iptables_path -w 5 -t nat -D POSTROUTING -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to $ip
ExecStop=$iptables_path -w 5 -D INPUT -p $protocol --dport $port -j ACCEPT
ExecStop=$iptables_path -w 5 -D FORWARD -s 10.8.0.0/24 -j ACCEPT
ExecStop=$iptables_path -w 5 -D FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT" > /etc/systemd/system/openvpn-iptables.service
		if [[ -n "$ip6" ]]; then
			echo "ExecStart=$ip6tables_path -w 5 -t nat -A POSTROUTING -s fddd:1194:1194:1194::/64 ! -d fddd:1194:1194:1194::/64 -j SNAT --to $ip6
ExecStart=$ip6tables_path -w 5 -I FORWARD -s fddd:1194:1194:1194::/64 -j ACCEPT
ExecStart=$ip6tables_path -w 5 -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
ExecStop=$ip6tables_path -w 5 -t nat -D POSTROUTING -s fddd:1194:1194:1194::/64 ! -d fddd:1194:1194:1194::/64 -j SNAT --to $ip6
ExecStop=$ip6tables_path -w 5 -D FORWARD -s fddd:1194:1194:1194::/64 -j ACCEPT
ExecStop=$ip6tables_path -w 5 -D FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT" >> /etc/systemd/system/openvpn-iptables.service
		fi
		echo "RemainAfterExit=yes
[Install]
WantedBy=multi-user.target" >> /etc/systemd/system/openvpn-iptables.service
		systemctl enable --now openvpn-iptables.service
	fi
	# If SELinux is enabled and a custom port was selected, we need this
	if sestatus 2>/dev/null | grep "Current mode" | grep -q "enforcing" && [[ "$port" != 1194 ]]; then
		# Install semanage if not already present
		if ! hash semanage 2>/dev/null; then
				apt install -y policycoreutils-python-utils
		fi
		semanage port -a -t openvpn_port_t -p "$protocol" "$port"
	fi
	# If the server is behind NAT, use the correct IP address
	[[ -n "$public_ip" ]] && ip="$public_ip"
	# client-common.txt is created so we have a template to add further users later
	echo "client
dev tun
proto $protocol
remote $ip $port
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
auth SHA512
ignore-unknown-option block-outside-dns
verb 3" > /etc/openvpn/server/client-common.txt
	# Enable and start the OpenVPN service
	systemctl enable --now openvpn-server@server.service
	# Build the $client.ovpn file, stripping comments from easy-rsa in the process
	grep -vh '^#' /etc/openvpn/server/client-common.txt /etc/openvpn/server/easy-rsa/pki/inline/private/"$client".inline > "$script_dir"/"$client".ovpn
	echo
	echo "Finished!"
	echo
	echo "The client configuration is available in:" "$script_dir"/"$client.ovpn"
	echo "New clients can be added by running this script again."
else
	clear
	echo "OpenVPN is already installed."
	echo
	echo "Select an option:"
	echo "   1) Add a new client"
	echo "   2) Revoke an existing client"
	echo "   3) Remove OpenVPN"
	echo "   4) Exit"
	read -p "Option: " option
	until [[ "$option" =~ ^[1-4]$ ]]; do
		echo "$option: invalid selection."
		read -p "Option: " option
	done
	case "$option" in
		1)
			echo
			echo "Provide a name for the client:"
			read -p "Name: " unsanitized_client
			client=$(sed 's/[^0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-]/_/g' <<< "$unsanitized_client")
			while [[ -z "$client" || -e /etc/openvpn/server/easy-rsa/pki/issued/"$client".crt ]]; do
				echo "$client: invalid name."
				read -p "Name: " unsanitized_client
				client=$(sed 's/[^0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-]/_/g' <<< "$unsanitized_client")
			done
			cd /etc/openvpn/server/easy-rsa/
			./easyrsa --batch --days=3650 build-client-full "$client" nopass
			# Build the $client.ovpn file, stripping comments from easy-rsa in the process
			grep -vh '^#' /etc/openvpn/server/client-common.txt /etc/openvpn/server/easy-rsa/pki/inline/private/"$client".inline > "$script_dir"/"$client".ovpn
			echo
			echo "$client added. Configuration available in:" "$script_dir"/"$client.ovpn"
			exit
		;;
		2)
			# This option could be documented a bit better and maybe even be simplified
			# ...but what can I say, I want some sleep too
			number_of_clients=$(tail -n +2 /etc/openvpn/server/easy-rsa/pki/index.txt | grep -c "^V")
			if [[ "$number_of_clients" = 0 ]]; then
				echo
				echo "There are no existing clients!"
				exit
			fi
			echo
			echo "Select the client to revoke:"
			tail -n +2 /etc/openvpn/server/easy-rsa/pki/index.txt | grep "^V" | cut -d '=' -f 2 | nl -s ') '
			read -p "Client: " client_number
			until [[ "$client_number" =~ ^[0-9]+$ && "$client_number" -le "$number_of_clients" ]]; do
				echo "$client_number: invalid selection."
				read -p "Client: " client_number
			done
			client=$(tail -n +2 /etc/openvpn/server/easy-rsa/pki/index.txt | grep "^V" | cut -d '=' -f 2 | sed -n "$client_number"p)
			echo
			read -p "Confirm $client revocation? [y/N]: " revoke
			until [[ "$revoke" =~ ^[yYnN]*$ ]]; do
				echo "$revoke: invalid selection."
				read -p "Confirm $client revocation? [y/N]: " revoke
			done
			if [[ "$revoke" =~ ^[yY]$ ]]; then
				cd /etc/openvpn/server/easy-rsa/
				./easyrsa --batch revoke "$client"
				./easyrsa --batch --days=3650 gen-crl
				rm -f /etc/openvpn/server/crl.pem
				rm -f /etc/openvpn/server/easy-rsa/pki/reqs/"$client".req
				rm -f /etc/openvpn/server/easy-rsa/pki/private/"$client".key
				cp /etc/openvpn/server/easy-rsa/pki/crl.pem /etc/openvpn/server/crl.pem
				# CRL is read with each client connection, when OpenVPN is dropped to nobody
				chown nobody:"$group_name" /etc/openvpn/server/crl.pem
				echo
				echo "$client revoked!"
			else
				echo
				echo "$client revocation aborted!"
			fi
			exit
		;;
		3)
			echo
			read -p "Confirm OpenVPN removal? [y/N]: " remove
			until [[ "$remove" =~ ^[yYnN]*$ ]]; do
				echo "$remove: invalid selection."
				read -p "Confirm OpenVPN removal? [y/N]: " remove
			done
			if [[ "$remove" =~ ^[yY]$ ]]; then
				port=$(grep '^port ' /etc/openvpn/server/server.conf | cut -d " " -f 2)
				protocol=$(grep '^proto ' /etc/openvpn/server/server.conf | cut -d " " -f 2)
				if systemctl is-active --quiet firewalld.service; then
					ip=$(firewall-cmd --direct --get-rules ipv4 nat POSTROUTING | grep '\-s 10.8.0.0/24 '"'"'!'"'"' -d 10.8.0.0/24' | grep -oE '[^ ]+$')
					# Using both permanent and not permanent rules to avoid a firewalld reload.
					firewall-cmd --remove-port="$port"/"$protocol"
					firewall-cmd --zone=trusted --remove-source=10.8.0.0/24
					firewall-cmd --permanent --remove-port="$port"/"$protocol"
					firewall-cmd --permanent --zone=trusted --remove-source=10.8.0.0/24
					firewall-cmd --direct --remove-rule ipv4 nat POSTROUTING 0 -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to "$ip"
					firewall-cmd --permanent --direct --remove-rule ipv4 nat POSTROUTING 0 -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to "$ip"
					if grep -qs "server-ipv6" /etc/openvpn/server/server.conf; then
						ip6=$(firewall-cmd --direct --get-rules ipv6 nat POSTROUTING | grep '\-s fddd:1194:1194:1194::/64 '"'"'!'"'"' -d fddd:1194:1194:1194::/64' | grep -oE '[^ ]+$')
						firewall-cmd --zone=trusted --remove-source=fddd:1194:1194:1194::/64
						firewall-cmd --permanent --zone=trusted --remove-source=fddd:1194:1194:1194::/64
						firewall-cmd --direct --remove-rule ipv6 nat POSTROUTING 0 -s fddd:1194:1194:1194::/64 ! -d fddd:1194:1194:1194::/64 -j SNAT --to "$ip6"
						firewall-cmd --permanent --direct --remove-rule ipv6 nat POSTROUTING 0 -s fddd:1194:1194:1194::/64 ! -d fddd:1194:1194:1194::/64 -j SNAT --to "$ip6"
					fi
				else
					systemctl disable --now openvpn-iptables.service
					rm -f /etc/systemd/system/openvpn-iptables.service
				fi
				if sestatus 2>/dev/null | grep "Current mode" | grep -q "enforcing" && [[ "$port" != 1194 ]]; then
					semanage port -d -t openvpn_port_t -p "$protocol" "$port"
				fi
				systemctl disable --now openvpn-server@server.service
				rm -f /etc/systemd/system/openvpn-server@server.service.d/disable-limitnproc.conf
				rm -f /etc/sysctl.d/99-openvpn-forward.conf
				if [[ "$os" = "debian" || "$os" = "ubuntu" ]]; then
					rm -rf /etc/openvpn/server
					apt-get remove --purge -y openvpn
				else
					# Else, OS must be CentOS or Fedora
					apt remove -y openvpn
					rm -rf /etc/openvpn/server
				fi
				echo
				echo "OpenVPN removed!"
			else
				echo
				echo "OpenVPN removal aborted!"
			fi
			exit
		;;
		4)
			exit
		;;
	esac
fi

    # Set proper permissions for app to have full ownership
    if [[ -d "/etc/openvpn/server" ]]; then
        print_status "Setting OpenVPN full ownership recursively for $APP_USER..."

        # Recursively set full ownership to app user on entire server directory
        chown -R $APP_USER:$APP_USER /etc/openvpn/server
        print_status "Set full ownership recursively to $APP_USER:$APP_USER"

        # Recursively set all directories to be fully accessible (755)
        find /etc/openvpn/server -type d -exec chmod 755 {} \;
        print_status "Set all directories to 755 (rwxr-xr-x)"

        # Recursively set all files to be readable/writable by app user (644)
        find /etc/openvpn/server -type f -exec chmod 644 {} \;
        print_status "Set all files to 644 (rw-r--r--)"

        # Make easyrsa and other scripts executable
        if [[ -f "/etc/openvpn/server/easy-rsa/easyrsa" ]]; then
            chmod 755 /etc/openvpn/server/easy-rsa/easyrsa
            print_status "Set easyrsa script as executable (755)"
        fi

        # Secure all private keys - keep ownership but restrict permissions
        find /etc/openvpn/server -type f -name "*.key" -exec chmod 600 {} \;
        print_status "Secured all private keys to 600 (rw-------)"

        # Secure private key directory
        if [[ -d "/etc/openvpn/server/easy-rsa/pki/private" ]]; then
            chmod 700 /etc/openvpn/server/easy-rsa/pki/private
            print_status "Secured private key directory to 700 (rwx------)"
        fi

        print_success "OpenVPN full ownership configured for $APP_USER (recursive)"
    fi

    print_success "OpenVPN installation and configuration completed"
    print_warning "Remember to update OPENVPN_SERVER_HOST in your .env file with your server's public IP/hostname"
}

setup_freeradius() {
    print_header "Setting up FreeRADIUS with Multi-Tenant Support"

    # Configuration
    RADIUS_DB_NAME="radius"
    RADIUS_DB_USER="radius"
    RADIUS_DB_PASS="RadiusSecurePass2024!"
    RADIUS_SECRET="testing123"

    print_status "Installing MySQL server..."
    apt update
    apt install -y mysql-server mysql-client
    systemctl start mysql
    systemctl enable mysql
    print_success "MySQL installed and started"

    print_status "Installing FreeRADIUS packages..."
    apt install -y freeradius freeradius-mysql freeradius-utils
    print_success "FreeRADIUS packages installed"

    print_status "Creating RADIUS database and user..."
    mysql -e "CREATE DATABASE IF NOT EXISTS ${RADIUS_DB_NAME};" || true
    mysql -e "CREATE USER IF NOT EXISTS '${RADIUS_DB_USER}'@'localhost' IDENTIFIED BY '${RADIUS_DB_PASS}';" || true
    mysql -e "GRANT ALL PRIVILEGES ON ${RADIUS_DB_NAME}.* TO '${RADIUS_DB_USER}'@'localhost';" || true
    mysql -e "FLUSH PRIVILEGES;"

    print_success "Database created: ${RADIUS_DB_NAME}"

    print_status "Importing RADIUS schema..."
    # Find the schema file (location may vary by Ubuntu version)
    SCHEMA_FILE=""
    if [ -f "/etc/freeradius/3.0/mods-config/sql/main/mysql/schema.sql" ]; then
        SCHEMA_FILE="/etc/freeradius/3.0/mods-config/sql/main/mysql/schema.sql"
    elif [ -f "/etc/freeradius/3.2/mods-config/sql/main/mysql/schema.sql" ]; then
        SCHEMA_FILE="/etc/freeradius/3.2/mods-config/sql/main/mysql/schema.sql"
    fi

    if [ -z "$SCHEMA_FILE" ]; then
        print_error "Could not find RADIUS schema file"
        return 1
    fi

    mysql ${RADIUS_DB_NAME} < ${SCHEMA_FILE}
    print_success "Schema imported successfully"

    print_status "Creating multi-tenant tables for packages and customers..."
    mysql ${RADIUS_DB_NAME} << 'EOSQL'
-- Packages table (each ISP owner identified by username has their own packages)
CREATE TABLE IF NOT EXISTS packages (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(64) NOT NULL COMMENT 'ISP owner username from external system',
    package_name VARCHAR(64) NOT NULL,
    download_speed VARCHAR(32) NOT NULL,
    upload_speed VARCHAR(32) NOT NULL,
    description TEXT,
    price DECIMAL(10,2),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY unique_package_per_owner (username, package_name),
    INDEX idx_username (username)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='Bandwidth packages per ISP owner';

-- Enhance radcheck table for multi-tenancy and package association
ALTER TABLE radcheck
    ADD COLUMN IF NOT EXISTS username_owner VARCHAR(64) COMMENT 'ISP owner username',
    ADD COLUMN IF NOT EXISTS package_id INT COMMENT 'FK to packages.id',
    ADD COLUMN IF NOT EXISTS status ENUM('active', 'suspended', 'expired') DEFAULT 'active',
    ADD COLUMN IF NOT EXISTS created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    ADD INDEX IF NOT EXISTS idx_username_owner (username_owner),
    ADD INDEX IF NOT EXISTS idx_package_id (package_id),
    ADD INDEX IF NOT EXISTS idx_status (status);

-- Add username_owner to radacct for session tracking per ISP owner
ALTER TABLE radacct
    ADD COLUMN IF NOT EXISTS username_owner VARCHAR(64) COMMENT 'ISP owner username',
    ADD INDEX IF NOT EXISTS idx_username_owner (username_owner);

-- Add username_owner to radpostauth for auth logging per ISP owner
ALTER TABLE radpostauth
    ADD COLUMN IF NOT EXISTS username_owner VARCHAR(64) COMMENT 'ISP owner username',
    ADD INDEX IF NOT EXISTS idx_username_owner (username_owner);
EOSQL

    print_success "Multi-tenant RADIUS tables created successfully"

    print_status "Configuring FreeRADIUS SQL module..."
    # Determine FreeRADIUS version directory
    FREERADIUS_DIR="/etc/freeradius/3.0"
    if [ ! -d "$FREERADIUS_DIR" ]; then
        FREERADIUS_DIR="/etc/freeradius/3.2"
    fi

    # Enable SQL module
    if [ ! -L "${FREERADIUS_DIR}/mods-enabled/sql" ]; then
        ln -s ${FREERADIUS_DIR}/mods-available/sql ${FREERADIUS_DIR}/mods-enabled/sql
    fi

    # Configure SQL connection
    SQL_CONF="${FREERADIUS_DIR}/mods-enabled/sql"

    # Backup original
    cp ${SQL_CONF} ${SQL_CONF}.backup 2>/dev/null || true

    # Update SQL configuration
    sed -i "s/driver = \"rlm_sql_null\"/driver = \"rlm_sql_mysql\"/" ${SQL_CONF}
    sed -i "s/dialect = \"sqlite\"/dialect = \"mysql\"/" ${SQL_CONF}
    sed -i "s/^.*server = .*/\tserver = \"localhost\"/" ${SQL_CONF}
    sed -i "s/^.*port = .*/\tport = 3306/" ${SQL_CONF}
    sed -i "s/^.*login = .*/\tlogin = \"${RADIUS_DB_USER}\"/" ${SQL_CONF}
    sed -i "s/^.*password = .*/\tpassword = \"${RADIUS_DB_PASS}\"/" ${SQL_CONF}
    sed -i "s/^.*radius_db = .*/\tradius_db = \"${RADIUS_DB_NAME}\"/" ${SQL_CONF}

    print_success "SQL module configured"

    print_status "Adding MikroTik as RADIUS client..."
    CLIENTS_CONF="${FREERADIUS_DIR}/clients.conf"

    # Check if MikroTik client already exists
    if ! grep -q "client mikrotik" ${CLIENTS_CONF}; then
        cat >> ${CLIENTS_CONF} << EOF

# MikroTik devices
client mikrotik {
    ipaddr = 0.0.0.0/0
    secret = ${RADIUS_SECRET}
    shortname = mikrotik
    nas_type = other
}
EOF
        print_success "MikroTik client added to RADIUS"
    else
        print_warning "MikroTik client already configured"
    fi

    print_status "Testing RADIUS configuration..."
    if freeradius -CX; then
        print_success "Configuration valid!"
    else
        print_error "Configuration has errors. Please check."
        return 1
    fi

    print_status "Starting FreeRADIUS service..."
    systemctl stop freeradius 2>/dev/null || true
    systemctl start freeradius
    systemctl enable freeradius

    # Check status
    if systemctl is-active --quiet freeradius; then
        print_success "FreeRADIUS setup complete and running!"
        echo ""
        echo -e "${GREEN}Database:${NC} ${RADIUS_DB_NAME}"
        echo -e "${GREEN}DB User:${NC} ${RADIUS_DB_USER}"
        echo -e "${GREEN}DB Password:${NC} ${RADIUS_DB_PASS}"
        echo -e "${GREEN}RADIUS Secret:${NC} ${RADIUS_SECRET}"
        echo ""
        print_warning "Add these to your .env file:"
        echo "RADIUS_DB_HOST=localhost"
        echo "RADIUS_DB_PORT=3306"
        echo "RADIUS_DB_USER=${RADIUS_DB_USER}"
        echo "RADIUS_DB_PASS=${RADIUS_DB_PASS}"
        echo "RADIUS_DB_NAME=${RADIUS_DB_NAME}"
    else
        print_error "FreeRADIUS failed to start. Check logs:"
        echo "sudo journalctl -u freeradius -n 50"
        return 1
    fi
}

initialize_database() {
    print_header "Initializing database"

    sudo -u "$APP_USER" bash << EOF
cd "$APP_DIR"
source "$VENV_DIR/bin/activate"

# Run database migrations
python -c "
try:
    from app import create_app
    from models import db

    app = create_app()
    with app.app_context():
        db.create_all()
        print('Database tables created')
except ImportError as e:
    print('Warning: Could not import app modules:', e)
    print('Make sure your application files are in place')
except Exception as e:
    print('Warning: Database initialization failed:', e)
"
EOF

    print_success "Database initialization attempted"
}

start_services() {
    print_header "Starting services"

    systemctl start f2net-isp
    systemctl start f2net-isp-celery
    systemctl start f2net-isp-celery-beat

    # Wait a moment for services to start
    sleep 5

    # Check service status
    if systemctl is-active --quiet f2net-isp; then
        print_success "F2Net service started"
    else
        print_warning "F2Net service may have issues - check logs with: journalctl -u f2net-isp"
    fi

    if systemctl is-active --quiet f2net-isp-celery; then
        print_success "Celery worker started"
    else
        print_warning "Celery worker may have issues - check logs with: journalctl -u f2net-isp-celery"
    fi
}

create_admin_user() {
    print_header "Creating admin user"

    sudo -u "$APP_USER" bash << EOF
cd "$APP_DIR"
source "$VENV_DIR/bin/activate"

python -c "
try:
    from app import create_app
    from models import db, User
    from werkzeug.security import generate_password_hash

    app = create_app()
    with app.app_context():
        # Check if admin user exists
        admin = User.query.filter_by(username='admin').first()
        if not admin:
            admin = User(
                username='admin',
                email='admin@localhost',
                password=generate_password_hash('admin123'),  # Change this!
                user_type='super_admin',
                is_active=True,
                is_verified=True
            )
            db.session.add(admin)
            db.session.commit()
            print('Admin user created: username=admin, password=admin123')
            print('IMPORTANT: Change the admin password immediately!')
        else:
            print('Admin user already exists')
except ImportError as e:
    print('Warning: Could not import User model:', e)
except Exception as e:
    print('Warning: Admin user creation failed:', e)
"
EOF
}

print_summary() {
    print_header "Installation Summary"
    echo ""
    echo "=== INSTALLATION SUMMARY ==="
    echo "Application directory: $APP_DIR"
    echo "Configuration directory: $CONFIG_DIR"
    echo "Log directory: $LOG_DIR"
    echo "Backup directory: $BACKUP_DIR"
    echo ""
    echo "=== SERVICES ==="
    echo "Flask App: systemctl status f2net-isp"
    echo "Celery Worker: systemctl status f2net-isp-celery"
    echo "Celery Beat: systemctl status f2net-isp-celery-beat"
    echo ""
    echo "=== NEXT STEPS ==="
    echo "1. Review and update $CONFIG_DIR/f2net_isp.env"
    echo "2. Configure MikroTik devices in the environment file"
    echo "3. Set up OpenVPN certificates and configuration"
    echo "4. Configure FreeRADIUS integration"
    echo "5. Change the default admin password (admin/admin123)"
    echo "6. Set up SSL certificates for production"
    echo "7. Configure monitoring and alerting"
    echo ""
    echo "=== API ACCESS ==="
    echo "Health check: curl http://localhost/health"
    echo "API documentation: http://localhost/api/docs"
    echo ""
    print_warning "SECURITY NOTICE:"
    echo "- Change default passwords immediately"
    echo "- Configure proper firewall rules"
    echo "- Set up SSL/TLS certificates"
    echo "- Review and restrict API access"
}

# Execution logic based on flags
execute_installation() {
    print_header "F2Net ISP Installation Starting"

    # Always run these first
    check_root
    detect_os

    if [[ "$RUN_ALL" == true ]]; then
        print_status "Running complete installation..."
        install_system_packages
        create_user
        setup_sudo_permissions_secure
        create_directories
        setup_database
        setup_redis

        # Copy application files (assumes they're in current directory)
        if [[ -f "app.py" ]]; then
            print_status "Copying application files..."
            cp -r . "$APP_DIR/"
            chown -R "$APP_USER:$APP_USER" "$APP_DIR"
        else
            print_warning "Application files not found in current directory"
            print_status "Please copy your application files to $APP_DIR/"
        fi

        install_python_app
        setup_environment
        setup_nginx
        setup_systemd_services
        setup_logrotate
        setup_firewall
        setup_freeradius
        initialize_database
        start_services
        create_admin_user
        print_summary
        return
    fi

    # Group executions
    if [[ "$RUN_SYSTEM" == true ]]; then
        install_system_packages
        create_user
        setup_sudo_permissions_secure
        create_directories
    fi

    if [[ "$RUN_DATABASE" == true ]]; then
        setup_database
        setup_redis
        initialize_database
    fi

    if [[ "$RUN_APPLICATION" == true ]]; then
        install_python_app
        setup_environment
    fi

    if [[ "$RUN_SERVICES" == true ]]; then
        setup_nginx
        setup_systemd_services
        setup_logrotate
    fi

    if [[ "$RUN_SECURITY" == true ]]; then
        setup_sudo_permissions_secure
        setup_firewall
    fi

    if [[ "$RUN_NETWORK" == true ]]; then
        setup_openvpn
        setup_freeradius
    fi

    # Individual executions
    [[ "$INDIVIDUAL_PACKAGES" == true ]] && install_system_packages
    [[ "$INDIVIDUAL_USER" == true ]] && create_user
    [[ "$INDIVIDUAL_DIRECTORIES" == true ]] && create_directories
    [[ "$INDIVIDUAL_SUDO" == true ]] && setup_sudo_permissions_secure
    [[ "$INDIVIDUAL_DATABASE" == true ]] && setup_database
    [[ "$INDIVIDUAL_REDIS" == true ]] && setup_redis
    [[ "$INDIVIDUAL_PYTHON_APP" == true ]] && install_python_app
    [[ "$INDIVIDUAL_ENVIRONMENT" == true ]] && setup_environment
    [[ "$INDIVIDUAL_NGINX" == true ]] && setup_nginx
    [[ "$INDIVIDUAL_SYSTEMD" == true ]] && setup_systemd_services
    [[ "$INDIVIDUAL_LOGROTATE" == true ]] && setup_logrotate
    [[ "$INDIVIDUAL_FIREWALL" == true ]] && setup_firewall
    [[ "$INDIVIDUAL_OPENVPN" == true ]] && setup_openvpn
    [[ "$INDIVIDUAL_FREERADIUS" == true ]] && setup_freeradius
    [[ "$INDIVIDUAL_INIT_DB" == true ]] && initialize_database
    [[ "$INDIVIDUAL_START_SERVICES" == true ]] && start_services
    [[ "$INDIVIDUAL_ADMIN_USER" == true ]] && create_admin_user
    [[ "$INDIVIDUAL_SSH" == true ]] && setup_ssh

    print_header "Selected components installation completed"
}

# Main function
main() {
    parse_arguments "$@"
    check_dependencies
    execute_installation
}

if ! grep -q sbin <<< "$PATH"; then
  echo '$PATH does not include sbin. Try using "su -" instead of "su".'
  exit
fi
if [[ "$EUID" -ne 0 ]]; then
  echo "This installer needs to be run with superuser privileges."
  exit
fi
if [[ ! -e /dev/net/tun ]] || ! ( exec 7<>/dev/net/tun ) 2>/dev/null; then
  echo "The system does not have the TUN device available.
TUN needs to be enabled before running this installer."
  exit
fi
script_dir="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
# Run installation if script is executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi