#!/bin/bash

# Base directory
BASE_DIR="components"

# Ensure base directory exists
mkdir -p "$BASE_DIR/vpn"

# Top-level components
touch "$BASE_DIR/Layout.jsx"
touch "$BASE_DIR/VPNDashboard.jsx"

# VPN subcomponents
touch "$BASE_DIR/vpn/ServerStatus.jsx"
touch "$BASE_DIR/vpn/ClientsSection.jsx"
touch "$BASE_DIR/vpn/CreateClient.jsx"
touch "$BASE_DIR/vpn/UsageStats.jsx"
touch "$BASE_DIR/vpn/ServerLogs.jsx"
touch "$BASE_DIR/vpn/ServerConfig.jsx"

echo "Component files and directories created successfully."
