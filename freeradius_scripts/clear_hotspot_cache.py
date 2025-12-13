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
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

# Configuration
G3_SUPER_API_URL = os.getenv('G3_SUPER_API_URL', 'http://localhost:5000/api')
API_KEY = os.getenv('MTK_API_KEY', 'your-django-api-key-for-authentication')  # Same API key used by Django

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

# Database configuration for RADIUS (from environment variables)
def get_radius_db_url():
    """Build database URL from environment variables"""
    host = os.getenv('RADIUS_DB_HOST', 'localhost')
    user = os.getenv('RADIUS_DB_USER', 'radius')
    password = os.getenv('RADIUS_DB_PASS', 'RadiusSecurePass2024!')
    database = os.getenv('RADIUS_DB_NAME', 'radius')
    return f"mysql+pymysql://{user}:{password}@{host}/{database}"

def get_mikrotik_credentials_from_db(nas_ip):
    """Get MikroTik credentials from RADIUS database using SQLAlchemy"""
    engine = None
    session = None
    
    try:
        logger.info(f"[DB] Connecting to RADIUS database for NAS: {nas_ip}")
        
        # Create database engine with production settings
        db_url = get_radius_db_url()
        engine = create_engine(
            db_url,
            pool_size=5,
            pool_timeout=5,
            pool_recycle=3600,
            pool_pre_ping=True,
            connect_args={
                'connect_timeout': 5,
                'read_timeout': 10,
                'write_timeout': 10
            }
        )
        
        logger.info(f"[DB] Database connection established")
        
        # Create session
        Session = sessionmaker(bind=engine)
        session = Session()
        
        logger.info(f"[DB] Querying nas table for router: {nas_ip}")
        
        # Query nas table for router credentials
        result = session.execute(
            text("SELECT shortname, secret FROM nas WHERE nasname = :nas_ip"),
            {'nas_ip': nas_ip}
        ).fetchone()
        
        if result:
            logger.info(f"[DB] ✓ Found router credentials - Identity: {result.shortname}")
            return {
                'username': os.getenv('MIKROTIK_DEFAULT_USER', 'f2net_user'),
                'password': result.secret,  # RADIUS secret is MikroTik password
                'identity': result.shortname  # Router identity
            }
        
        logger.warning(f"[DB] ✗ No credentials found for NAS IP: {nas_ip}")
        return None
        
    except Exception as e:
        logger.error(f"[DB] ✗ Database error getting credentials for {nas_ip}: {e}")
        return None
        
    finally:
        # Always cleanup resources
        if session:
            try:
                session.close()
                logger.debug(f"[DB] Session closed")
            except:
                pass
        if engine:
            try:
                engine.dispose()
                logger.debug(f"[DB] Engine disposed")
            except:
                pass


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





def clear_mikrotik_cache(mac_address, nas_ip):
    """
    Clear MikroTik hotspot host cache for the given MAC address.

    Args:
        mac_address (str): User's MAC address
        nas_ip (str): Router's NAS IP

    Returns:
        bool: True if cache cleared successfully
    """
    try:
        logger.info(f"[CACHE] Starting cache clear process for MAC: {mac_address}")
        
        # Get router credentials from RADIUS database
        logger.info(f"[CACHE] Getting router credentials from database...")
        router_credentials = get_mikrotik_credentials_from_db(nas_ip)
        if not router_credentials:
            logger.error(f"[CACHE] ✗ No credentials found for router at {nas_ip}")
            return False
            
        username = router_credentials['username']
        password = router_credentials['password']
        identity = router_credentials['identity']
        
        logger.info(f"[CACHE] ✓ Got credentials - Router: {identity}, Username: {username}")

        # Call g3_super API to clear cache
        clear_url = f"{G3_SUPER_API_URL}/mikrotik/hotspot/host/clear"
        headers = {
            'Content-Type': 'application/json',
            'X-API-Key': API_KEY
        }
        payload = {
            'username': username,
            'password': password,
            'host': nas_ip,  # Use NAS IP directly
            'port': 8728,
            'mac_address': mac_address
        }

        logger.info(f"[API] Calling cache clear API: {clear_url}")
        logger.info(f"[API] Target: {nas_ip}:8728, MAC: {mac_address}")
        
        clear_response = requests.post(clear_url, json=payload, headers=headers, timeout=10)
        
        logger.info(f"[API] Response status: {clear_response.status_code}")

        if clear_response.status_code == 200:
            result = clear_response.json()
            logger.info(f"[API] Response data: {result}")
            
            if result.get('success'):
                entries_cleared = result.get('entries_cleared', 0)
                logger.info(f"[CACHE] ✓ SUCCESS! Cache cleared - Entries removed: {entries_cleared}")
                return True
            else:
                error_msg = result.get('error', 'Unknown error')
                logger.error(f"[CACHE] ✗ FAILED! API returned error: {error_msg}")
                return False
        else:
            logger.error(f"[API] ✗ HTTP ERROR! Status: {clear_response.status_code}")
            logger.error(f"[API] Response: {clear_response.text}")
            return False

    except requests.exceptions.Timeout:
        logger.error(f"[API] ✗ TIMEOUT! Cache clear API took longer than 10 seconds")
        return False
    except requests.exceptions.ConnectionError:
        logger.error(f"[API] ✗ CONNECTION ERROR! Cannot reach g3_super API at {G3_SUPER_API_URL}")
        return False
    except Exception as e:
        logger.error(f"[CACHE] ✗ UNEXPECTED ERROR! {e}")
        import traceback
        logger.error(f"[CACHE] Traceback: {traceback.format_exc()}")
        return False


def main():
    """Main execution function"""
    start_time = datetime.now()
    logger.info(f"[MAIN] ⚡ SCRIPT STARTED at {start_time.strftime('%Y-%m-%d %H:%M:%S')}")
    
    try:
        # Log the accounting stop event
        logger.info(f"[MAIN] Reading RADIUS environment variables...")
        attrs = log_accounting_stop()

        # Extract required attributes
        mac_address = attrs.get('CALLING_STATION_ID')
        nas_ip = attrs.get('NAS_IP_ADDRESS')
        acct_type = attrs.get('ACCT_STATUS_TYPE')
        terminate_cause = attrs.get('ACCT_TERMINATE_CAUSE')
        session_time = attrs.get('ACCT_SESSION_TIME')

        logger.info(f"[MAIN] Extracted data - MAC: {mac_address}, NAS: {nas_ip}, Type: {acct_type}")

        # Validate this is an accounting stop
        if acct_type != 'Stop':
            logger.info(f"[MAIN] ⏭️  Not an accounting stop event (Type: {acct_type}), skipping cache clear")
            logger.info(f"[MAIN] ✅ Script completed in {(datetime.now() - start_time).total_seconds():.2f}s")
            sys.exit(0)

        # Validate MAC address
        if not mac_address or mac_address == 'N/A':
            logger.error(f"[MAIN] ❌ VALIDATION FAILED! No MAC address found in CALLING_STATION_ID")
            logger.error(f"[MAIN] ❌ Script failed in {(datetime.now() - start_time).total_seconds():.2f}s")
            sys.exit(1)

        # Validate NAS IP
        if not nas_ip or nas_ip == 'N/A':
            logger.error(f"[MAIN] ❌ VALIDATION FAILED! No NAS IP address found")
            logger.error(f"[MAIN] ❌ Script failed in {(datetime.now() - start_time).total_seconds():.2f}s")
            sys.exit(1)

        logger.info(f"[MAIN] ✅ Validation passed - Processing cache clear...")
        logger.info(f"[MAIN] 📊 Session details - Duration: {session_time}s, Cause: {terminate_cause}")

        # Clear MikroTik cache
        logger.info(f"[MAIN] 🚀 Starting cache clear operation...")
        success = clear_mikrotik_cache(mac_address, nas_ip)
        
        execution_time = (datetime.now() - start_time).total_seconds()

        if success:
            logger.info("="*80)
            logger.info(f"[MAIN] 🎉 SUCCESS! CACHE CLEARED SUCCESSFULLY")
            logger.info(f"[MAIN] 📈 User {mac_address} will be redirected to packages page")
            logger.info(f"[MAIN] ⏱️  Total execution time: {execution_time:.2f} seconds")
            logger.info("="*80)
            sys.exit(0)
        else:
            logger.error("="*80)
            logger.error(f"[MAIN] ⚠️  CACHE CLEAR FAILED (but session terminated normally)")
            logger.error(f"[MAIN] 🔄 User will still be disconnected by MikroTik timeout")
            logger.error(f"[MAIN] 🔧 Cache may clear automatically on next connection attempt")
            logger.error(f"[MAIN] ⏱️  Total execution time: {execution_time:.2f} seconds")
            logger.error("="*80)
            # Exit with 0 to not block FreeRADIUS accounting
            sys.exit(0)

    except Exception as e:
        execution_time = (datetime.now() - start_time).total_seconds()
        logger.error(f"[MAIN] 💥 CRITICAL ERROR! Unexpected exception: {e}")
        logger.error(f"[MAIN] ⏱️  Failed after {execution_time:.2f} seconds")
        import traceback
        logger.error(f"[MAIN] 🔍 Full traceback: {traceback.format_exc()}")
        sys.exit(1)


if __name__ == '__main__':
    logger.info(f"[INIT] 🔥 FreeRADIUS Cache Clear Script v1.0")
    logger.info(f"[INIT] 📍 PID: {os.getpid()}, User: {os.getenv('USER', 'unknown')}")
    logger.info(f"[INIT] 🌐 API URL: {G3_SUPER_API_URL}")
    main()
