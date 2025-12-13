#!/bin/bash

###############################################################################
# FreeRADIUS Installation & Configuration Script for MikroTik Integration
#
# This script will:
# 1. Install FreeRADIUS and MySQL
# 2. Create RADIUS database and user
# 3. Import RADIUS schema
# 4. Configure FreeRADIUS to use MySQL
# 5. Set up RADIUS for MikroTik authentication
# 6. Configure rate-limit support for bandwidth packages
#
# Usage: sudo bash setup_radius.sh
###############################################################################

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
RADIUS_DB_NAME="radius"
RADIUS_DB_USER="radius"
RADIUS_DB_PASS="RadiusSecurePass2024!"  # Change this!
RADIUS_SECRET="testing123"  # Shared secret for MikroTik-RADIUS communication

echo -e "${GREEN}================================${NC}"
echo -e "${GREEN}FreeRADIUS Setup for MikroTik${NC}"
echo -e "${GREEN}================================${NC}\n"

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Please run as root (use sudo)${NC}"
    exit 1
fi

echo -e "${YELLOW}[1/8] Updating package lists...${NC}"
apt update

echo -e "\n${YELLOW}[2/8] Installing FreeRADIUS and dependencies...${NC}"
apt install -y freeradius freeradius-mysql freeradius-utils mysql-server

echo -e "\n${YELLOW}[3/8] Creating RADIUS database and user...${NC}"
mysql -e "CREATE DATABASE IF NOT EXISTS ${RADIUS_DB_NAME};" || true
mysql -e "CREATE USER IF NOT EXISTS '${RADIUS_DB_USER}'@'localhost' IDENTIFIED BY '${RADIUS_DB_PASS}';" || true
mysql -e "GRANT ALL PRIVILEGES ON ${RADIUS_DB_NAME}.* TO '${RADIUS_DB_USER}'@'localhost';" || true
mysql -e "FLUSH PRIVILEGES;"

echo -e "${GREEN}Database created: ${RADIUS_DB_NAME}${NC}"
echo -e "${GREEN}Database user: ${RADIUS_DB_USER}${NC}"

echo -e "\n${YELLOW}[4/8] Importing RADIUS schema...${NC}"
# Find the schema file (location may vary by Ubuntu version)
SCHEMA_FILE=""
if [ -f "/etc/freeradius/3.0/mods-config/sql/main/mysql/schema.sql" ]; then
    SCHEMA_FILE="/etc/freeradius/3.0/mods-config/sql/main/mysql/schema.sql"
elif [ -f "/etc/freeradius/3.2/mods-config/sql/main/mysql/schema.sql" ]; then
    SCHEMA_FILE="/etc/freeradius/3.2/mods-config/sql/main/mysql/schema.sql"
fi

if [ -z "$SCHEMA_FILE" ]; then
    echo -e "${RED}Could not find RADIUS schema file${NC}"
    exit 1
fi

mysql ${RADIUS_DB_NAME} < ${SCHEMA_FILE}
echo -e "${GREEN}Schema imported successfully${NC}"

echo -e "\n${YELLOW}[5/8] Configuring FreeRADIUS SQL module...${NC}"
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
cp ${SQL_CONF} ${SQL_CONF}.backup

# Update SQL configuration
sed -i "s/driver = \"rlm_sql_null\"/driver = \"rlm_sql_mysql\"/" ${SQL_CONF}
sed -i "s/dialect = \"sqlite\"/dialect = \"mysql\"/" ${SQL_CONF}
sed -i "s/^.*server = .*/\tserver = \"localhost\"/" ${SQL_CONF}
sed -i "s/^.*port = .*/\tport = 3306/" ${SQL_CONF}
sed -i "s/^.*login = .*/\tlogin = \"${RADIUS_DB_USER}\"/" ${SQL_CONF}
sed -i "s/^.*password = .*/\tpassword = \"${RADIUS_DB_PASS}\"/" ${SQL_CONF}
sed -i "s/^.*radius_db = .*/\tradius_db = \"${RADIUS_DB_NAME}\"/" ${SQL_CONF}

# Enable SQL client loading from nas table
sed -i 's/^[[:space:]]*#[[:space:]]*read_clients = yes/\tread_clients = yes/' ${SQL_CONF}
sed -i 's/^[[:space:]]*#[[:space:]]*client_table = "nas"/\tclient_table = "nas"/' ${SQL_CONF}

echo -e "${GREEN}SQL module configured (with SQL client loading enabled)${NC}"

echo -e "\n${YELLOW}[6/8] Adding MikroTik as RADIUS client...${NC}"
# Add client configuration
CLIENTS_CONF="${FREERADIUS_DIR}/clients.conf"

# NOTE: Catch-all client (0.0.0.0/0) removed to prevent conflicts
# Individual MikroTik devices should be added via the API with specific IPs
echo -e "${YELLOW}Skipping catch-all client - use API to add specific MikroTik devices${NC}"

echo -e "\n${YELLOW}[7/8] Creating custom RADIUS tables for multi-tenant packages...${NC}"
# Add custom table for bandwidth packages with username-based multi-tenancy
mysql ${RADIUS_DB_NAME} << 'EOF'
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

-- NAS table for dynamic RADIUS client loading from SQL
CREATE TABLE IF NOT EXISTS nas (
    id INT(10) NOT NULL AUTO_INCREMENT,
    nasname VARCHAR(128) NOT NULL COMMENT 'VPN IP address of router',
    shortname VARCHAR(32) COMMENT 'Router identity',
    type VARCHAR(30) DEFAULT 'other',
    ports INT(5),
    secret VARCHAR(60) NOT NULL DEFAULT 'testing123' COMMENT 'RADIUS shared secret',
    server VARCHAR(64),
    community VARCHAR(50),
    description VARCHAR(200) DEFAULT 'RADIUS Client',
    PRIMARY KEY (id),
    KEY nasname (nasname)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='RADIUS NAS clients for SQL client loading';

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
EOF

echo -e "${GREEN}Multi-tenant RADIUS tables created successfully${NC}"

echo -e "\n${YELLOW}[8/11] Deploying cache clearing script...${NC}"
# Deploy the Python script for automatic MikroTik cache clearing
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

if [ -f "${PROJECT_ROOT}/freeradius_scripts/clear_hotspot_cache.py" ]; then
    cp "${PROJECT_ROOT}/freeradius_scripts/clear_hotspot_cache.py" /usr/local/bin/
    chmod +x /usr/local/bin/clear_hotspot_cache.py
    echo -e "${GREEN}Cache clearing script deployed${NC}"
else
    echo -e "${YELLOW}Warning: clear_hotspot_cache.py not found. Skipping...${NC}"
fi

# Create log directory for cache clearing
mkdir -p /var/log/freeradius
touch /var/log/freeradius/cache_clear.log
chown freerad:freerad /var/log/freeradius/cache_clear.log
chmod 644 /var/log/freeradius/cache_clear.log
echo -e "${GREEN}Log directory created${NC}"

echo -e "\n${YELLOW}[9/11] Configuring exec module for cache clearing...${NC}"
# Create exec module config for accounting-stop cache clearing
cat > ${FREERADIUS_DIR}/mods-available/exec_on_accounting_stop << 'EXEC_EOF'
# Execute Python script to clear MikroTik cache on Accounting-Stop
exec exec_on_accounting_stop {
    wait = no
    program = "/usr/local/bin/clear_hotspot_cache.py"
    input_pairs = request
    shell_escape = yes
    timeout = 10
}
EXEC_EOF

# Enable the exec module
ln -sf ${FREERADIUS_DIR}/mods-available/exec_on_accounting_stop ${FREERADIUS_DIR}/mods-enabled/exec_on_accounting_stop
echo -e "${GREEN}Exec module configured${NC}"

echo -e "\n${YELLOW}[10/11] Updating accounting section...${NC}"
# Add exec_on_accounting_stop to accounting section in default site
SITES_DEFAULT="${FREERADIUS_DIR}/sites-available/default"
if grep -q "exec_on_accounting_stop" ${SITES_DEFAULT}; then
    echo -e "${YELLOW}Accounting section already configured${NC}"
else
    # Insert exec_on_accounting_stop after -sql in accounting section
    sed -i '/accounting {/,/}/ s/\(\s*-sql\)/\1\n\texec_on_accounting_stop/' ${SITES_DEFAULT}
    echo -e "${GREEN}Accounting section updated${NC}"
fi

echo -e "\n${YELLOW}[11/11] Starting FreeRADIUS service...${NC}"
# Stop FreeRADIUS if running
systemctl stop freeradius || true

# Test configuration
echo -e "${YELLOW}Testing RADIUS configuration...${NC}"
if freeradius -CX; then
    echo -e "${GREEN}Configuration valid!${NC}"
else
    echo -e "${RED}Configuration has errors. Please check.${NC}"
    exit 1
fi

# Start and enable FreeRADIUS
systemctl start freeradius
systemctl enable freeradius

# Check status
if systemctl is-active --quiet freeradius; then
    echo -e "\n${GREEN}================================${NC}"
    echo -e "${GREEN}FreeRADIUS Setup Complete!${NC}"
    echo -e "${GREEN}================================${NC}\n"

    echo -e "Database: ${GREEN}${RADIUS_DB_NAME}${NC}"
    echo -e "DB User: ${GREEN}${RADIUS_DB_USER}${NC}"
    echo -e "DB Password: ${GREEN}${RADIUS_DB_PASS}${NC}"
    echo -e "RADIUS Secret: ${GREEN}${RADIUS_SECRET}${NC}"
    echo -e "\nStatus: ${GREEN}Running${NC}"

    echo -e "\n${YELLOW}Next Steps:${NC}"
    echo "1. Update your .env file with RADIUS credentials"
    echo "2. Use the API to add users and assign packages"
    echo "3. Configure MikroTik to use this RADIUS server"

    echo -e "\n${YELLOW}Test Authentication:${NC}"
    echo "radtest testuser testpass localhost 0 ${RADIUS_SECRET}"
else
    echo -e "${RED}FreeRADIUS failed to start. Check logs:${NC}"
    echo "sudo journalctl -u freeradius -n 50"
    exit 1
fi
