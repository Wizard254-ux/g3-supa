#!/usr/bin/env python3
"""
FreeRADIUS Accounting-Stop Script - Automatic MikroTik Cache Clearing
=====================================================================

This script is executed by FreeRADIUS when it receives an Accounting-Stop packet.
It automatically clears the MikroTik hotspot host cache entry for expired sessions.

Flow:
1. Session expires → MikroTik sends Accounting-Stop to RADIUS
2. FreeRADIUS executes this script
3. Script calls g3_super API to clear MikroTik cache for the MAC address
4. User's device loses "connected" status and gets redirected to packages page

Environment Variables (provided by FreeRADIUS):
- CALLING_STATION_ID: User's MAC address (AA:BB:CC:DD:EE:FF)
- NAS_IP_ADDRESS: MikroTik router IP (VPN IP like 10.8.0.45)
- ACCT_STATUS_TYPE: Should be "Stop"
- USER_NAME: The username (for PPPoE) or MAC (for hotspot)

Usage:
- Place this script in /usr/local/bin/clear_hotspot_cache.py
- Make it executable: chmod +x /usr/local/bin/clear_hotspot_cache.py
- Configure FreeRADIUS accounting section to call it
"""

import os
import sys
import requests
import json
import logging
from datetime import datetime

# Configuration
G3_SUPER_API_URL = os.getenv('G3_SUPER_API_URL', 'http://localhost:5000/api')
API_KEY = os.getenv('MTK_API_KEY', '')  # Same API key used by Django

# Logging
LOG_FILE = '/var/log/freeradius/cache_clear.log'
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)


def log_accounting_stop():
    """Log the accounting stop event with all RADIUS attributes"""
    logger.info("="*80)
    logger.info("ACCOUNTING STOP - Cache Clear Trigger")
    logger.info("="*80)

    # Log all relevant RADIUS attributes from environment
    attrs = {
        'CALLING_STATION_ID': os.getenv('CALLING_STATION_ID', 'N/A'),
        'NAS_IP_ADDRESS': os.getenv('NAS_IP_ADDRESS', 'N/A'),
        'ACCT_STATUS_TYPE': os.getenv('ACCT_STATUS_TYPE', 'N/A'),
        'USER_NAME': os.getenv('USER_NAME', 'N/A'),
        'ACCT_SESSION_ID': os.getenv('ACCT_SESSION_ID', 'N/A'),
        'ACCT_SESSION_TIME': os.getenv('ACCT_SESSION_TIME', 'N/A'),
        'ACCT_INPUT_OCTETS': os.getenv('ACCT_INPUT_OCTETS', 'N/A'),
        'ACCT_OUTPUT_OCTETS': os.getenv('ACCT_OUTPUT_OCTETS', 'N/A'),
        'ACCT_TERMINATE_CAUSE': os.getenv('ACCT_TERMINATE_CAUSE', 'N/A'),
    }

    for key, value in attrs.items():
        logger.info(f"{key}: {value}")

    return attrs


def get_device_details(nas_ip):
    """
    Get device details from g3_super to find router identity and credentials.

    Args:
        nas_ip (str): NAS IP address (VPN IP like 10.8.0.45)

    Returns:
        dict: Device details including identity, username, password
    """
    try:
        # Query nas table via g3_super to get router identity
        url = f"{G3_SUPER_API_URL}/radius/nas/lookup"
        headers = {
            'Content-Type': 'application/json',
            'X-API-Key': API_KEY
        }
        payload = {'nas_ip': nas_ip}

        logger.info(f"Looking up device details for NAS IP: {nas_ip}")
        response = requests.post(url, json=payload, headers=headers, timeout=5)

        if response.status_code == 200:
            data = response.json()
            logger.info(f"Device found: {data.get('shortname', 'N/A')}")
            return data
        else:
            logger.error(f"Failed to lookup device: {response.status_code} - {response.text}")
            return None

    except Exception as e:
        logger.error(f"Error looking up device: {e}")
        return None


def clear_mikrotik_cache(mac_address, nas_ip, device_identity):
    """
    Clear MikroTik hotspot host cache for the given MAC address.

    Args:
        mac_address (str): User's MAC address
        nas_ip (str): Router's VPN IP
        device_identity (str): Router identity/client_name

    Returns:
        bool: True if cache cleared successfully
    """
    try:
        # First, get router credentials from Django database via device status
        status_url = f"{G3_SUPER_API_URL}/mikrotik/devices/{device_identity}/currentstatus"
        headers = {
            'Content-Type': 'application/json',
            'X-API-Key': API_KEY
        }

        logger.info(f"Getting router status for: {device_identity}")
        status_response = requests.get(status_url, headers=headers, timeout=5)

        if status_response.status_code != 200:
            logger.error(f"Failed to get router status: {status_response.text}")
            return False

        status_data = status_response.json()
        data = status_data.get('data', {})

        if not (data.get('connected') or data.get('vpn_connected')):
            logger.warning(f"Router {device_identity} is not connected to VPN")
            return False

        # Get VPN IP from connection info
        vpn_info = data.get('vpn_connection_info', {})
        vpn_ip = vpn_info.get('virtual_address')

        if not vpn_ip:
            logger.error(f"No VPN IP found for router {device_identity}")
            return False

        logger.info(f"Router VPN IP: {vpn_ip}")

        # Get router credentials (this would need to be passed from Django)
        # For now, we'll use default credentials or get from database
        # TODO: Implement credential lookup from Django database
        username = os.getenv('MIKROTIK_DEFAULT_USER', 'admin')
        password = os.getenv('MIKROTIK_DEFAULT_PASS', '')  # Get from env or database

        # Call g3_super API to clear cache
        clear_url = f"{G3_SUPER_API_URL}/mikrotik/hotspot/host/clear"
        payload = {
            'username': username,
            'password': password,
            'host': vpn_ip,
            'port': 8728,
            'mac_address': mac_address
        }

        logger.info(f"Clearing cache for MAC: {mac_address} on {vpn_ip}")
        clear_response = requests.post(clear_url, json=payload, headers=headers, timeout=10)

        if clear_response.status_code == 200:
            result = clear_response.json()
            if result.get('success'):
                logger.info(f"✓ Cache cleared successfully! Entries cleared: {result.get('entries_cleared', 0)}")
                return True
            else:
                logger.error(f"✗ Cache clear failed: {result.get('error', 'Unknown error')}")
                return False
        else:
            logger.error(f"✗ API call failed: {clear_response.status_code} - {clear_response.text}")
            return False

    except Exception as e:
        logger.error(f"Error clearing cache: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return False


def main():
    """Main execution function"""
    try:
        # Log the accounting stop event
        attrs = log_accounting_stop()

        # Extract required attributes
        mac_address = attrs.get('CALLING_STATION_ID')
        nas_ip = attrs.get('NAS_IP_ADDRESS')
        acct_type = attrs.get('ACCT_STATUS_TYPE')
        terminate_cause = attrs.get('ACCT_TERMINATE_CAUSE')

        # Validate this is an accounting stop
        if acct_type != 'Stop':
            logger.info(f"Not an accounting stop event (Type: {acct_type}), skipping cache clear")
            sys.exit(0)

        # Validate MAC address
        if not mac_address or mac_address == 'N/A':
            logger.error("No MAC address found in CALLING_STATION_ID, cannot clear cache")
            sys.exit(1)

        # Validate NAS IP
        if not nas_ip or nas_ip == 'N/A':
            logger.error("No NAS IP address found, cannot determine router")
            sys.exit(1)

        logger.info(f"Processing cache clear for MAC: {mac_address} on NAS: {nas_ip}")
        logger.info(f"Termination cause: {terminate_cause}")

        # Get device details from g3_super
        device = get_device_details(nas_ip)
        if not device:
            logger.error("Could not get device details, skipping cache clear")
            sys.exit(1)

        device_identity = device.get('shortname') or device.get('client_name')
        if not device_identity:
            logger.error("No device identity found, skipping cache clear")
            sys.exit(1)

        # Clear MikroTik cache
        success = clear_mikrotik_cache(mac_address, nas_ip, device_identity)

        if success:
            logger.info("="*80)
            logger.info("✓ ACCOUNTING STOP PROCESSED - CACHE CLEARED SUCCESSFULLY")
            logger.info("="*80)
            sys.exit(0)
        else:
            logger.error("="*80)
            logger.error("✗ ACCOUNTING STOP PROCESSED - CACHE CLEAR FAILED")
            logger.error("="*80)
            sys.exit(1)

    except Exception as e:
        logger.error(f"Unexpected error in main: {e}")
        import traceback
        logger.error(traceback.format_exc())
        sys.exit(1)


if __name__ == '__main__':
    main()
