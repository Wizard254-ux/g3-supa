"""
MikroTik Service for ISP Middleware
Handles all MikroTik RouterOS API communications
"""

import librouteros
from librouteros.exceptions import LibRouterosError as LibError, ConnectionClosed as ConnectionError
import structlog
import time
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
import threading
import ipaddress
from dataclasses import dataclass

logger = structlog.get_logger()


@dataclass
class MikroTikDevice:
    """MikroTik device configuration"""
    name: str
    host: str
    username: str
    password: str
    port: int = 8728
    use_ssl: bool = False
    timeout: int = 10


class MikroTikService:
    """Service for managing MikroTik RouterOS devices"""

    def __init__(self, app=None):
        self.app = app
        self.devices = {}
        self.connections = {}
        self.connection_lock = threading.Lock()

        if app:
            self.init_app(app)

    def init_app(self, app):
        """Initialize the service with Flask app"""
        self.app = app

        # Load MikroTik devices from config
        devices_config = app.config.get('MIKROTIK_DEVICES', [])
        for device_config in devices_config:
            device = MikroTikDevice(**device_config)
            self.devices[device.name] = device

        logger.info(f"Initialized MikroTik service with {len(self.devices)} devices")

    def get_connection(self, device_name: str = 'core_router'):
        """Get or create connection to MikroTik device"""
        with self.connection_lock:
            if device_name not in self.devices:
                raise ValueError(f"Device '{device_name}' not configured")

            device = self.devices[device_name]

            # Check if connection exists and is alive
            if device_name in self.connections:
                try:
                    # Test connection with a simple command
                    self.connections[device_name].path('/system/identity').get()
                    return self.connections[device_name]
                except Exception:
                    # Connection is dead, remove it
                    del self.connections[device_name]

            # Create new connection
            try:
                api = librouteros.connect(
                    host=device.host,
                    username=device.username,
                    password=device.password,
                    port=device.port,
                    timeout=device.timeout,
                    ssl=device.use_ssl
                )
                self.connections[device_name] = api
                logger.info(f"Connected to MikroTik device: {device_name}")
                return api

            except Exception as e:
                logger.error(f"Failed to connect to MikroTik device {device_name}", error=str(e))
                raise

    def check_connection(self, device_name: str = 'core_router') -> bool:
        """Check if connection to MikroTik device is working"""
        try:
            api = self.get_connection(device_name)
            identity = api.path('/system/identity').get()
            return True
        except Exception as e:
            logger.warning(f"MikroTik connection check failed for {device_name}", error=str(e))
            return False

    def create_user_queue(self, username: str, package_info: Dict, device_name: str = 'core_router') -> Dict:
        """Create simple queue for user bandwidth management"""
        try:
            api = self.get_connection(device_name)

            # Calculate speeds (convert Mbps to bps for MikroTik)
            download_speed = package_info.get('download_speed', 1) * 1000000  # Mbps to bps
            upload_speed = package_info.get('upload_speed', 1) * 1000000  # Mbps to bps

            # Queue configuration
            queue_config = {
                'name': f"queue_{username}",
                'target': f"user_{username}",  # This would be user's IP or IP range
                'max-limit': f"{upload_speed}/{download_speed}",
                'burst-limit': f"{upload_speed * 2}/{download_speed * 2}",
                'burst-threshold': f"{upload_speed // 2}/{download_speed // 2}",
                'burst-time': "8s/8s",
                'priority': str(package_info.get('priority_level', 8)),
                'comment': f"Auto-created for {username} - {package_info.get('package_name', 'Unknown Package')}"
            }

            # Check if queue already exists
            queues = api.path('/queue/simple')
            existing = list(queues.select('name').where('name', f"queue_{username}"))

            if existing:
                # Update existing queue
                queue_id = existing[0]['id']
                queues.update(**queue_config, **{'.id': queue_id})
                logger.info(f"Updated MikroTik queue for user: {username}")
            else:
                # Create new queue
                queues.add(**queue_config)
                logger.info(f"Created MikroTik queue for user: {username}")

            return {
                'success': True,
                'queue_name': f"queue_{username}",
                'download_speed': download_speed,
                'upload_speed': upload_speed
            }

        except Exception as e:
            logger.error(f"Failed to create MikroTik queue for {username}", error=str(e))
            return {
                'success': False,
                'error': str(e)
            }

    def remove_user_queue(self, username: str, device_name: str = 'core_router') -> bool:
        """Remove user's simple queue"""
        try:
            api = self.get_connection(device_name)
            queues = api.path('/queue/simple')

            # Find and remove the queue
            existing = list(queues.select('.id', 'name').where('name', f"queue_{username}"))

            if existing:
                queue_id = existing[0]['.id']
                queues.remove(queue_id)
                logger.info(f"Removed MikroTik queue for user: {username}")
                return True
            else:
                logger.warning(f"Queue not found for user: {username}")
                return False

        except Exception as e:
            logger.error(f"Failed to remove MikroTik queue for {username}", error=str(e))
            return False

    def update_user_bandwidth(self, username: str, new_package_info: Dict, device_name: str = 'core_router') -> bool:
        """Update user's bandwidth limits"""
        try:
            # Remove old queue and create new one
            self.remove_user_queue(username, device_name)
            result = self.create_user_queue(username, new_package_info, device_name)
            return result['success']

        except Exception as e:
            logger.error(f"Failed to update bandwidth for {username}", error=str(e))
            return False

    def get_user_traffic_stats(self, username: str, device_name: str = 'core_router') -> Dict:
        """Get traffic statistics for a user"""
        try:
            api = self.get_connection(device_name)
            queues = api.path('/queue/simple')

            # Get queue statistics
            queue_stats = list(queues.select(
                'name', 'bytes', 'packets', 'dropped', 'rate'
            ).where('name', f"queue_{username}"))

            if queue_stats:
                stats = queue_stats[0]
                return {
                    'success': True,
                    'username': username,
                    'bytes_total': stats.get('bytes', '0/0'),
                    'packets_total': stats.get('packets', '0/0'),
                    'dropped_packets': stats.get('dropped', '0/0'),
                    'current_rate': stats.get('rate', '0/0'),
                    'timestamp': datetime.utcnow().isoformat()
                }
            else:
                return {
                    'success': False,
                    'error': 'Queue not found'
                }

        except Exception as e:
            logger.error(f"Failed to get traffic stats for {username}", error=str(e))
            return {
                'success': False,
                'error': str(e)
            }

    def get_all_active_users(self, device_name: str = 'core_router') -> List[Dict]:
        """Get all active users from simple queues"""
        try:
            api = self.get_connection(device_name)
            queues = api.path('/queue/simple')

            # Get all queues that start with "queue_"
            all_queues = list(queues.select(
                'name', 'target', 'max-limit', 'bytes', 'rate', 'comment'
            ))

            active_users = []
            for queue in all_queues:
                if queue['name'].startswith('queue_'):
                    username = queue['name'].replace('queue_', '')
                    active_users.append({
                        'username': username,
                        'target': queue.get('target', ''),
                        'max_limit': queue.get('max-limit', ''),
                        'bytes': queue.get('bytes', '0/0'),
                        'current_rate': queue.get('rate', '0/0'),
                        'comment': queue.get('comment', '')
                    })

            return active_users

        except Exception as e:
            logger.error(f"Failed to get active users from {device_name}", error=str(e))
            return []

    def hotspot_authorize(self, username: str, mac_address: str, ip_address: str,
                          package_info: Dict, device_name: str = 'core_router') -> Dict:
        """Authorize user on MikroTik hotspot"""
        try:
            api = self.get_connection(device_name)

            # Create hotspot user
            hotspot_users = api.path('/ip/hotspot/user')

            # Check if user already exists
            existing = list(hotspot_users.select('name').where('name', username))

            user_config = {
                'name': username,
                'password': '',  # Password already verified by RADIUS
                'profile': package_info.get('hotspot_profile', 'default'),
                'mac-address': mac_address,
                'address': ip_address,
                'limit-uptime': f"{package_info.get('session_timeout', 3600)}s",
                'comment': f"Auto-created {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')}"
            }

            if existing:
                # Update existing user
                user_id = existing[0]['id']
                hotspot_users.update(**user_config, **{'.id': user_id})
                logger.info(f"Updated hotspot user: {username}")
            else:
                # Create new user
                hotspot_users.add(**user_config)
                logger.info(f"Created hotspot user: {username}")

            # Create bandwidth queue
            queue_result = self.create_user_queue(username, package_info, device_name)

            return {
                'success': True,
                'username': username,
                'mac_address': mac_address,
                'ip_address': ip_address,
                'queue_created': queue_result['success']
            }

        except Exception as e:
            logger.error(f"Failed to authorize hotspot user {username}", error=str(e))
            return {
                'success': False,
                'error': str(e)
            }

    def hotspot_deauthorize(self, username: str, device_name: str = 'core_router') -> bool:
        """Deauthorize user from MikroTik hotspot"""
        try:
            api = self.get_connection(device_name)

            # Remove from hotspot users
            hotspot_users = api.path('/ip/hotspot/user')
            existing = list(hotspot_users.select('.id').where('name', username))

            if existing:
                user_id = existing[0]['.id']
                hotspot_users.remove(user_id)
                logger.info(f"Removed hotspot user: {username}")

            # Remove bandwidth queue
            self.remove_user_queue(username, device_name)

            return True

        except Exception as e:
            logger.error(f"Failed to deauthorize hotspot user {username}", error=str(e))
            return False

    def create_pppoe_secret(self, username: str, password: str, package_info: Dict,
                            device_name: str = 'core_router') -> Dict:
        """Create PPPoE secret for user"""
        try:
            api = self.get_connection(device_name)
            ppp_secrets = api.path('/ppp/secret')

            # Check if secret already exists
            existing = list(ppp_secrets.select('name').where('name', username))

            secret_config = {
                'name': username,
                'password': password,
                'service': 'pppoe',
                'profile': package_info.get('pppoe_profile', 'default'),
                'local-address': package_info.get('local_address', ''),
                'remote-address': package_info.get('remote_address', ''),
                'comment': f"Auto-created {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')}"
            }

            if existing:
                # Update existing secret
                secret_id = existing[0]['id']
                ppp_secrets.update(**secret_config, **{'.id': secret_id})
                logger.info(f"Updated PPPoE secret for: {username}")
            else:
                # Create new secret
                ppp_secrets.add(**secret_config)
                logger.info(f"Created PPPoE secret for: {username}")

            # Create bandwidth queue
            queue_result = self.create_user_queue(username, package_info, device_name)

            return {
                'success': True,
                'username': username,
                'queue_created': queue_result['success']
            }

        except Exception as e:
            logger.error(f"Failed to create PPPoE secret for {username}", error=str(e))
            return {
                'success': False,
                'error': str(e)
            }

    def remove_pppoe_secret(self, username: str, device_name: str = 'core_router') -> bool:
        """Remove PPPoE secret for user"""
        try:
            api = self.get_connection(device_name)
            ppp_secrets = api.path('/ppp/secret')

            # Find and remove the secret
            existing = list(ppp_secrets.select('.id').where('name', username))

            if existing:
                secret_id = existing[0]['.id']
                ppp_secrets.remove(secret_id)
                logger.info(f"Removed PPPoE secret for: {username}")

            # Remove bandwidth queue
            self.remove_user_queue(username, device_name)

            return True

        except Exception as e:
            logger.error(f"Failed to remove PPPoE secret for {username}", error=str(e))
            return False

    def get_system_resources(self, device_name: str = 'core_router') -> Dict:
        """Get system resource information"""
        try:
            api = self.get_connection(device_name)
            resources = api.path('/system/resource')

            resource_data = list(resources.select(
                'uptime', 'version', 'cpu-load', 'free-memory', 'total-memory',
                'free-hdd-space', 'total-hdd-space'
            ))[0]

            return {
                'success': True,
                'device': device_name,
                'uptime': resource_data.get('uptime', ''),
                'version': resource_data.get('version', ''),
                'cpu_load': resource_data.get('cpu-load', ''),
                'free_memory': resource_data.get('free-memory', ''),
                'total_memory': resource_data.get('total-memory', ''),
                'free_hdd_space': resource_data.get('free-hdd-space', ''),
                'total_hdd_space': resource_data.get('total-hdd-space', ''),
                'timestamp': datetime.utcnow().isoformat()
            }

        except Exception as e:
            logger.error(f"Failed to get system resources for {device_name}", error=str(e))
            return {
                'success': False,
                'error': str(e)
            }

    def get_interface_stats(self, device_name: str = 'core_router') -> List[Dict]:
        """Get network interface statistics"""
        try:
            api = self.get_connection(device_name)
            interfaces = api.path('/interface')

            interface_data = list(interfaces.select(
                'name', 'type', 'rx-byte', 'tx-byte', 'rx-packet',
                'tx-packet', 'rx-drop', 'tx-drop', 'running'
            ))

            return [
                {
                    'device': device_name,
                    'name': iface.get('name', ''),
                    'type': iface.get('type', ''),
                    'running': iface.get('running', False),
                    'rx_bytes': iface.get('rx-byte', '0'),
                    'tx_bytes': iface.get('tx-byte', '0'),
                    'rx_packets': iface.get('rx-packet', '0'),
                    'tx_packets': iface.get('tx-packet', '0'),
                    'rx_drops': iface.get('rx-drop', '0'),
                    'tx_drops': iface.get('tx-drop', '0'),
                    'timestamp': datetime.utcnow().isoformat()
                }
                for iface in interface_data
            ]

        except Exception as e:
            logger.error(f"Failed to get interface stats for {device_name}", error=str(e))
            return []

    def backup_configuration(self, device_name: str = 'core_router') -> Dict:
        """Create configuration backup"""
        try:
            api = self.get_connection(device_name)

            # Export configuration
            export_result = api.path('/export').call('file', {
                'file': f"backup_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"
            })

            logger.info(f"Configuration backup created for {device_name}")

            return {
                'success': True,
                'device': device_name,
                'backup_file': export_result,
                'timestamp': datetime.utcnow().isoformat()
            }

        except Exception as e:
            logger.error(f"Failed to backup configuration for {device_name}", error=str(e))
            return {
                'success': False,
                'error': str(e)
            }

    def close_connections(self):
        """Close all MikroTik connections"""
        with self.connection_lock:
            for device_name, connection in self.connections.items():
                try:
                    connection.close()
                    logger.info(f"Closed connection to {device_name}")
                except Exception as e:
                    logger.warning(f"Error closing connection to {device_name}", error=str(e))

            self.connections.clear()