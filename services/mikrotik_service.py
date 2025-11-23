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

    def create_bridge(self, bridge_name: str, auto_mac: bool = False, 
                     admin_mac: str = '00:00:00:00:00:00', device_name: str = 'core_router') -> Dict:
        """Create bridge interface"""
        try:
            api = self.get_connection(device_name)
            bridge_interface = api.path('/interface/bridge')
            
            # Check if bridge already exists
            existing = list(bridge_interface.select('name').where('name', bridge_name))
            
            if existing:
                return {
                    'success': False,
                    'error': f'Bridge {bridge_name} already exists'
                }
            
            bridge_config = {
                'name': bridge_name,
                'auto-mac': 'yes' if auto_mac else 'no',
                'admin-mac': admin_mac if not auto_mac else ''
            }
            
            bridge_interface.add(**bridge_config)
            logger.info(f"Created bridge: {bridge_name}")
            
            return {
                'success': True,
                'bridge_name': bridge_name,
                'auto_mac': auto_mac,
                'admin_mac': admin_mac
            }
            
        except Exception as e:
            logger.error(f"Failed to create bridge {bridge_name}", error=str(e))
            return {
                'success': False,
                'error': str(e)
            }
    
    def add_bridge_port(self, bridge_name: str, interface: str, device_name: str = 'core_router') -> Dict:
        """Add interface to bridge"""
        try:
            api = self.get_connection(device_name)
            bridge_port = api.path('/interface/bridge/port')
            
            # Check if port already exists in bridge
            existing = list(bridge_port.select('interface').where('interface', interface))
            
            if existing:
                return {
                    'success': False,
                    'error': f'Interface {interface} already in a bridge'
                }
            
            bridge_port.add(interface=interface, bridge=bridge_name)
            logger.info(f"Added interface {interface} to bridge {bridge_name}")
            
            return {
                'success': True,
                'interface': interface,
                'bridge': bridge_name
            }
            
        except Exception as e:
            logger.error(f"Failed to add interface {interface} to bridge {bridge_name}", error=str(e))
            return {
                'success': False,
                'error': str(e)
            }
    
    def configure_pppoe_server(self, interface: str, service_name: str, config: Dict, 
                              device_name: str = 'core_router') -> Dict:
        """Configure PPPoE server"""
        try:
            api = self.get_connection(device_name)
            
            # Create PPPoE profile first
            pppoe_profile = api.path('/ppp/profile')
            profile_config = {
                'name': 'pppoe-profile',
                'local-address': config['local_address'],
                'remote-address': config['remote_address'],
                'use-encryption': 'yes' if config['use_encryption'] else 'no'
            }
            
            # Check if profile exists
            existing_profile = list(pppoe_profile.select('name').where('name', 'pppoe-profile'))
            if not existing_profile:
                pppoe_profile.add(**profile_config)
                logger.info("Created PPPoE profile")
            
            # Configure PPPoE server
            pppoe_server = api.path('/interface/pppoe-server/server')
            server_config = {
                'service-name': service_name,
                'interface': interface,
                'default-profile': 'pppoe-profile',
                'authentication': config['authentication'],
                'keepalive-timeout': str(config['keepalive_timeout'])
            }
            
            # Check if server already exists
            existing_server = list(pppoe_server.select('service-name').where('service-name', service_name))
            if existing_server:
                return {
                    'success': False,
                    'error': f'PPPoE server with service name {service_name} already exists'
                }
            
            pppoe_server.add(**server_config)
            logger.info(f"Configured PPPoE server on {interface}")
            
            return {
                'success': True,
                'interface': interface,
                'service_name': service_name,
                'profile': 'pppoe-profile'
            }
            
        except Exception as e:
            logger.error(f"Failed to configure PPPoE server on {interface}", error=str(e))
            return {
                'success': False,
                'error': str(e)
            }
    
    def configure_hotspot_server(self, interface: str, hotspot_name: str, config: Dict,
                                device_name: str = 'core_router') -> Dict:
        """Configure hotspot server"""
        try:
            api = self.get_connection(device_name)
            
            # Create hotspot profile first
            hotspot_profile = api.path('/ip/hotspot/profile')
            profile_config = {
                'name': 'hotspot-profile',
                'hotspot-address': '172.31.0.1',
                'dns-name': 'router.local',
                'html-directory': 'hotspot',
                'login-by': 'http-chap,http-pap'
            }
            
            existing_profile = list(hotspot_profile.select('name').where('name', 'hotspot-profile'))
            if not existing_profile:
                hotspot_profile.add(**profile_config)
                logger.info("Created hotspot profile")
            
            # Create hotspot user profile
            hotspot_user_profile = api.path('/ip/hotspot/user/profile')
            user_profile_config = {
                'name': 'default-user-profile',
                'address-pool': config['address_pool'],
                'idle-timeout': config['idle_timeout'],
                'keepalive-timeout': config['keepalive_timeout'],
                'shared-users': 1
            }
            
            existing_user_profile = list(hotspot_user_profile.select('name').where('name', 'default-user-profile'))
            if not existing_user_profile:
                hotspot_user_profile.add(**user_profile_config)
                logger.info("Created hotspot user profile")
            
            # Add hotspot server
            hotspot = api.path('/ip/hotspot')
            hotspot_config = {
                'name': hotspot_name,
                'interface': interface,
                'address-pool': config['address_pool'],
                'profile': 'hotspot-profile',
                'addresses-per-mac': config['addresses_per_mac']
            }
            
            existing_hotspot = list(hotspot.select('name').where('name', hotspot_name))
            if existing_hotspot:
                return {
                    'success': False,
                    'error': f'Hotspot {hotspot_name} already exists'
                }
            
            hotspot.add(**hotspot_config)
            logger.info(f"Configured hotspot server {hotspot_name} on {interface}")
            
            return {
                'success': True,
                'hotspot_name': hotspot_name,
                'interface': interface,
                'address_pool': config['address_pool']
            }
            
        except Exception as e:
            logger.error(f"Failed to configure hotspot server {hotspot_name} on {interface}", error=str(e))
            return {
                'success': False,
                'error': str(e)
            }
    
    def setup_complete_network(self, bridge_name: str, ports: List[str], ip_pool_range: str,
                              network_address: str, enable_pppoe: bool = False, 
                              enable_hotspot: bool = False, enable_anti_sharing: bool = False,
                              device_name: str = 'core_router') -> Dict:
        """Complete network setup based on the provided script"""
        try:
            api = self.get_connection(device_name)
            setup_results = []
            
            # 1. Create bridge
            bridge_result = self.create_bridge(bridge_name, False, '00:00:00:00:00:00', device_name)
            setup_results.append(f"Bridge: {bridge_result['success']}")
            
            # 2. Add ports to bridge
            for port in ports:
                port_result = self.add_bridge_port(bridge_name, port, device_name)
                setup_results.append(f"Port {port}: {port_result['success']}")
            
            # 3. Configure IP pool
            ip_pool = api.path('/ip/pool')
            pool_config = {
                'name': 'hotspot-pool',
                'ranges': ip_pool_range
            }
            
            existing_pool = list(ip_pool.select('name').where('name', 'hotspot-pool'))
            if not existing_pool:
                ip_pool.add(**pool_config)
                setup_results.append("IP Pool: True")
            
            # 4. Add IP address to bridge
            ip_address = api.path('/ip/address')
            network_parts = network_address.split('/')
            address_config = {
                'address': network_address,
                'interface': bridge_name,
                'network': f"{network_parts[0].rsplit('.', 1)[0]}.0.0"
            }
            
            existing_address = list(ip_address.select('address').where('interface', bridge_name))
            if not existing_address:
                ip_address.add(**address_config)
                setup_results.append("IP Address: True")
            
            # 5. Configure PPPoE server if enabled
            if enable_pppoe:
                pppoe_config = {
                    'local_address': network_parts[0],
                    'remote_address': 'hotspot-pool',
                    'use_encryption': True,
                    'authentication': 'pap,chap,mschap1,mschap2',
                    'keepalive_timeout': 60
                }
                pppoe_result = self.configure_pppoe_server(bridge_name, 'service', pppoe_config, device_name)
                setup_results.append(f"PPPoE Server: {pppoe_result['success']}")
            
            # 6. Configure Hotspot if enabled
            if enable_hotspot:
                hotspot_config = {
                    'address_pool': 'hotspot-pool',
                    'profile': 'hotspot-profile',
                    'addresses_per_mac': 1,
                    'idle_timeout': 'none',
                    'keepalive_timeout': '2m'
                }
                hotspot_result = self.configure_hotspot_server(bridge_name, 'hotspot1', hotspot_config, device_name)
                setup_results.append(f"Hotspot Server: {hotspot_result['success']}")
            
            # 7. Enable anti-sharing protection if requested
            if enable_anti_sharing:
                anti_sharing_result = self.enable_anti_sharing_protection(bridge_name, device_name)
                setup_results.append(f"Anti-sharing: {anti_sharing_result['success']}")
            
            # 8. Configure DHCP server
            dhcp_pool = api.path('/ip/dhcp-server')
            dhcp_config = {
                'name': 'dhcp-hotspot',
                'interface': bridge_name,
                'address-pool': 'hotspot-pool',
                'lease-time': '1h'
            }
            
            existing_dhcp = list(dhcp_pool.select('name').where('name', 'dhcp-hotspot'))
            if not existing_dhcp:
                dhcp_pool.add(**dhcp_config)
                
                # Add DHCP network
                dhcp_network = api.path('/ip/dhcp-server/network')
                dhcp_network.add(
                    address=f"{network_parts[0].rsplit('.', 2)[0]}.0.0/{network_parts[1]}",
                    gateway=network_parts[0],
                    **{'dns-server': network_parts[0]}
                )
                setup_results.append("DHCP Server: True")
            
            logger.info(f"Network setup completed for {bridge_name}")
            
            return {
                'success': True,
                'bridge_name': bridge_name,
                'ports_added': ports,
                'setup_results': setup_results,
                'pppoe_enabled': enable_pppoe,
                'hotspot_enabled': enable_hotspot,
                'anti_sharing_enabled': enable_anti_sharing
            }
            
        except Exception as e:
            logger.error(f"Failed to setup network {bridge_name}", error=str(e))
            return {
                'success': False,
                'error': str(e)
            }
    
    def enable_anti_sharing_protection(self, interface: str, device_name: str = 'core_router') -> Dict:
        """Enable hotspot anti-sharing protection using TTL modification"""
        try:
            api = self.get_connection(device_name)
            rules_created = []
            
            # Create mangle rule to mark packets with TTL > 1
            firewall_mangle = api.path('/ip/firewall/mangle')
            mangle_config = {
                'chain': 'prerouting',
                'in-interface': interface,
                'ttl': 'greater-than=1',
                'action': 'mark-connection',
                'new-connection-mark': 'shared_conn',
                'comment': 'Mark shared connections (TTL > 1)'
            }
            
            # Check if rule already exists
            existing_mangle = list(firewall_mangle.select('comment').where('comment', 'Mark shared connections (TTL > 1)'))
            if not existing_mangle:
                firewall_mangle.add(**mangle_config)
                rules_created.append('TTL marking rule')
            
            # Create filter rule to drop shared connections
            firewall_filter = api.path('/ip/firewall/filter')
            filter_config = {
                'chain': 'forward',
                'connection-mark': 'shared_conn',
                'action': 'drop',
                'comment': 'Block connection sharing'
            }
            
            existing_filter = list(firewall_filter.select('comment').where('comment', 'Block connection sharing'))
            if not existing_filter:
                firewall_filter.add(**filter_config)
                rules_created.append('Connection blocking rule')
            
            logger.info(f"Anti-sharing protection enabled on {interface}")
            
            return {
                'success': True,
                'interface': interface,
                'rules_created': rules_created
            }
            
        except Exception as e:
            logger.error(f"Failed to enable anti-sharing protection on {interface}", error=str(e))
            return {
                'success': False,
                'error': str(e)
            }

    def setup_f2net_bridge(self, username: str, password: str, host: str, port: int,
                           ip_pool_range: str, network_address: str) -> Dict:
        """Create ISP bridge and address pool with dynamic credentials"""
        try:
            import librouteros
            
            # Get ISP brand from config
            isp_brand = self.app.config.get('ISP_BRAND', 'f2net')
            bridge_name = self.app.config.get('ISP_BRIDGE_NAME', f'{isp_brand}_bridge')
            pool_name = self.app.config.get('ISP_POOL_NAME', f'{isp_brand}_pool')
            
            # Connect with provided credentials
            api = librouteros.connect(
                host=host,
                username=username,
                password=password,
                port=port,
                timeout=10
            )
            
            setup_results = []
            
            # 1. Create bridge - Fixed logic
            bridge_interface = api.path('/interface/bridge')
            try:
                # Get all bridges first
                all_bridges = list(bridge_interface.select('name'))
                bridge_names = [b.get('name', '') for b in all_bridges]
                logger.info(f"Existing bridges: {bridge_names}")
                
                if bridge_name not in bridge_names:
                    bridge_interface.add(
                        name=bridge_name,
                        **{'auto-mac': 'yes'},
                        comment=f'Created by {isp_brand}'
                    )
                    setup_results.append("Bridge created")
                    logger.info(f"Created bridge: {bridge_name}")
                else:
                    setup_results.append("Bridge already exists")
                    logger.info(f"Bridge {bridge_name} already exists")
            except Exception as bridge_error:
                logger.error(f"Bridge creation error: {str(bridge_error)}")
                setup_results.append(f"Bridge error: {str(bridge_error)}")
            
            # 2. Create IP pool - Fixed logic
            ip_pool = api.path('/ip/pool')
            try:
                all_pools = list(ip_pool.select('name'))
                pool_names = [p.get('name', '') for p in all_pools]
                logger.info(f"Existing pools: {pool_names}")
                
                if pool_name not in pool_names:
                    ip_pool.add(
                        name=pool_name,
                        ranges=ip_pool_range
                    )
                    setup_results.append("IP Pool created")
                    logger.info(f"Created pool: {pool_name}")
                else:
                    setup_results.append("IP Pool already exists")
                    logger.info(f"Pool {pool_name} already exists")
            except Exception as pool_error:
                logger.error(f"Pool creation error: {str(pool_error)}")
                setup_results.append(f"Pool error: {str(pool_error)}")
            
            # 3. Add IP address to bridge - Fixed logic
            ip_address = api.path('/ip/address')
            try:
                all_addresses = list(ip_address.select('address', 'interface'))
                bridge_addresses = [a for a in all_addresses if a.get('interface') == bridge_name]
                logger.info(f"Existing addresses on {bridge_name}: {bridge_addresses}")
                
                if not bridge_addresses:
                    network_parts = network_address.split('/')
                    # For 172.31.0.1/16, network should be 172.31.0.0
                    ip_parts = network_parts[0].split('.')
                    network = f"{ip_parts[0]}.{ip_parts[1]}.0.0"
                    
                    ip_address.add(
                        address=network_address,
                        interface=bridge_name,
                        network=network,
                        comment=f'{isp_brand} bridge IP'
                    )
                    setup_results.append("IP Address assigned")
                    logger.info(f"Assigned IP {network_address} to {bridge_name}")
                else:
                    setup_results.append("IP Address already assigned")
                    logger.info(f"IP already assigned to {bridge_name}")
            except Exception as ip_error:
                logger.error(f"IP assignment error: {str(ip_error)}")
                setup_results.append(f"IP error: {str(ip_error)}")
            
            api.close()
            logger.info(f"f2net_bridge setup completed")
            
            return {
                'success': True,
                'bridge_name': bridge_name,
                'pool_name': pool_name,
                'ip_pool_range': ip_pool_range,
                'network_address': network_address,
                'setup_results': setup_results
            }
            
        except Exception as e:
            logger.error(f"Failed to setup f2net_bridge", error=str(e))
            return {
                'success': False,
                'error': str(e)
            }

    def add_bridge_port_dynamic(self, username: str, password: str, host: str, port: int,
                               bridge_name: str, interface: str) -> Dict:
        """Add interface to bridge with dynamic credentials - removes from existing bridge first"""
        try:
            import librouteros
            
            api = librouteros.connect(
                host=host, username=username, password=password, port=port, timeout=10
            )
            
            bridge_port = api.path('/interface/bridge/port')
            
            # Check if port already exists in any bridge
            existing = list(bridge_port.select('.id', 'interface', 'bridge').where('interface', interface))
            
            if existing:
                current_bridge = existing[0].get('bridge')
                if current_bridge == bridge_name:
                    api.close()
                    return {
                        'success': True,
                        'interface': interface,
                        'bridge': bridge_name,
                        'message': f'Interface {interface} already in target bridge {bridge_name}'
                    }
                
                # Remove from current bridge
                port_id = existing[0]['.id']
                bridge_port.remove(port_id)
                logger.info(f"Removed interface {interface} from bridge {current_bridge}")
            
            # Get ISP brand for comment
            isp_brand = self.app.config.get('ISP_BRAND', 'f2net')
            
            bridge_port.add(
                interface=interface, 
                bridge=bridge_name,
                comment=f'Added by {isp_brand}'
            )
            
            api.close()
            logger.info(f"Added interface {interface} to bridge {bridge_name}")
            
            return {
                'success': True,
                'interface': interface,
                'bridge': bridge_name
            }
            
        except Exception as e:
            logger.error(f"Failed to add interface {interface} to bridge {bridge_name}", error=str(e))
            return {
                'success': False,
                'error': str(e)
            }
    
    def configure_pppoe_server_dynamic(self, username: str, password: str, host: str, port: int,
                                      interface: str, service_name: str, config: Dict) -> Dict:
        """Configure PPPoE server with all prerequisites (bridge, pool, port assignment)"""
        try:
            import librouteros
            
            api = librouteros.connect(
                host=host, username=username, password=password, port=port, timeout=10
            )
            
            isp_brand = self.app.config.get('ISP_BRAND', 'f2net')
            bridge_name = self.app.config.get('ISP_BRIDGE_NAME', f'{isp_brand}_bridge')
            pool_name = self.app.config.get('ISP_POOL_NAME', f'{isp_brand}_pool')
            
            setup_results = []
            
            # 1. Ensure bridge exists
            bridge_interface = api.path('/interface/bridge')
            all_bridges = list(bridge_interface.select('name'))
            bridge_names = [b.get('name', '') for b in all_bridges]
            
            if bridge_name not in bridge_names:
                bridge_interface.add(
                    name=bridge_name,
                    **{'auto-mac': 'yes'},
                    comment=f'Created by {isp_brand}'
                )
                setup_results.append(f"Created bridge {bridge_name}")
            else:
                setup_results.append(f"Bridge {bridge_name} exists")
            
            # 2. Ensure IP pool exists
            ip_pool = api.path('/ip/pool')
            all_pools = list(ip_pool.select('name'))
            pool_names = [p.get('name', '') for p in all_pools]
            
            if pool_name not in pool_names:
                ip_pool.add(
                    name=pool_name,
                    ranges='172.31.0.2-172.31.255.254'
                )
                setup_results.append(f"Created pool {pool_name}")
            else:
                setup_results.append(f"Pool {pool_name} exists")
            
            # 3. Ensure bridge has IP address
            ip_address = api.path('/ip/address')
            all_addresses = list(ip_address.select('address', 'interface'))
            bridge_addresses = [a for a in all_addresses if a.get('interface') == bridge_name]
            
            if not bridge_addresses:
                ip_address.add(
                    address='172.31.0.1/16',
                    interface=bridge_name,
                    network='172.31.0.0',
                    comment=f'{isp_brand} bridge IP'
                )
                setup_results.append(f"Assigned IP to {bridge_name}")
            else:
                setup_results.append(f"IP already assigned to {bridge_name}")
            
            # 4. Remove interface from any existing bridge first
            bridge_port = api.path('/interface/bridge/port')
            all_ports = list(bridge_port.select('.id', 'interface', 'bridge'))
            
            for port in all_ports:
                if port.get('interface') == interface:
                    current_bridge = port.get('bridge')
                    if current_bridge != bridge_name:
                        bridge_port.remove(port['.id'])
                        setup_results.append(f"Removed {interface} from {current_bridge}")
                        logger.info(f"Removed {interface} from {current_bridge}")
                    break
            
            # 5. Add interface to target bridge
            try:
                bridge_port.add(
                    interface=interface,
                    bridge=bridge_name,
                    comment=f'Added by {isp_brand}'
                )
                setup_results.append(f"Added {interface} to {bridge_name}")
                logger.info(f"Added {interface} to {bridge_name}")
            except Exception as e:
                if 'already added' not in str(e):
                    raise e
                setup_results.append(f"{interface} already in {bridge_name}")
            
            # 5. Create PPPoE profile
            pppoe_profile = api.path('/ppp/profile')
            profile_name = f'{isp_brand}-pppoe-profile'
            
            # Get all profiles first
            all_profiles = list(pppoe_profile.select('name'))
            profile_names = [p.get('name', '') for p in all_profiles]
            
            if profile_name not in profile_names:
                profile_config = {
                    'name': profile_name,
                    'local-address': config['local_address'],
                    'remote-address': pool_name,
                    'use-encryption': 'yes' if config['use_encryption'] else 'no',
                    'comment': f'Created by {isp_brand}'
                }
                pppoe_profile.add(**profile_config)
                setup_results.append(f"Created PPPoE profile {profile_name}")
            else:
                setup_results.append(f"PPPoE profile {profile_name} exists")
            
            # 6. Configure PPPoE server on bridge
            pppoe_server = api.path('/interface/pppoe-server/server')
            
            existing_server = list(pppoe_server.select('.id', 'service-name').where('service-name', service_name))
            if existing_server:
                # Update existing server to use bridge
                pppoe_server.update(
                    **{'.id': existing_server[0]['.id']},
                    interface=bridge_name
                )
                setup_results.append(f"Updated PPPoE server {service_name} to use bridge {bridge_name}")
            else:
                # Create new server on bridge
                server_config = {
                    'service-name': service_name,
                    'interface': bridge_name,
                    'default-profile': f'{isp_brand}-pppoe-profile',
                    'authentication': config['authentication'],
                    'keepalive-timeout': str(config['keepalive_timeout']),
                    'comment': f'Created by {isp_brand}'
                }
                pppoe_server.add(**server_config)
                if config.get('auto_enable', False):
                    pppoe_server.update(**{'.id': '*last'}, disabled='no')
                    setup_results.append(f"Created and enabled PPPoE server {service_name} on bridge {bridge_name}")
                else:
                    setup_results.append(f"Created PPPoE server {service_name} on bridge {bridge_name} (disabled)")
            
            api.close()
            
            return {
                'success': True,
                'interface': interface,
                'service_name': service_name,
                'bridge_name': bridge_name,
                'pool_name': pool_name,
                'setup_results': setup_results
            }
            
        except Exception as e:
            logger.error(f"Failed to configure PPPoE server on {interface}", error=str(e))
            return {
                'success': False,
                'error': str(e)
            }
    
    def configure_hotspot_server_dynamic(self, username: str, password: str, host: str, port: int,
                                        interface: str, hotspot_name: str, config: Dict) -> Dict:
        """Configure hotspot server with all prerequisites (bridge, pool, port assignment)"""
        try:
            logger.info(f"=== configure_hotspot_server_dynamic called ===")
            logger.info(f"Parameters - Host: {host}, Port: {port}, User: {username}")
            logger.info(f"Interface: {interface}, Hotspot name: {hotspot_name}")
            logger.info(f"Config: {config}")

            import librouteros

            logger.info(f"Connecting to {host}:{port}...")
            api = librouteros.connect(
                host=host, username=username, password=password, port=port, timeout=10
            )
            logger.info("Connection established")

            isp_brand = self.app.config.get('ISP_BRAND', 'f2net')
            bridge_name = self.app.config.get('ISP_BRIDGE_NAME', f'{isp_brand}_bridge')
            pool_name = self.app.config.get('ISP_POOL_NAME', f'{isp_brand}_pool')

            logger.info(f"ISP: {isp_brand}, Bridge: {bridge_name}, Pool: {pool_name}")
            setup_results = []

            # 1. Ensure bridge exists
            logger.info("Step 1: Checking/creating bridge...")
            bridge_interface = api.path('/interface/bridge')
            all_bridges = list(bridge_interface.select('name'))
            bridge_names = [b.get('name', '') for b in all_bridges]
            logger.info(f"Existing bridges: {bridge_names}")

            if bridge_name not in bridge_names:
                logger.info(f"Creating bridge {bridge_name}...")
                bridge_interface.add(
                    name=bridge_name,
                    **{'auto-mac': 'yes'},
                    comment=f'Created by {isp_brand}'
                )
                setup_results.append(f"Created bridge {bridge_name}")
                logger.info("Bridge created")
            else:
                setup_results.append(f"Bridge {bridge_name} exists")
                logger.info("Bridge already exists")

            # 2. Ensure IP pool exists
            logger.info("Step 2: Checking/creating IP pool...")
            ip_pool = api.path('/ip/pool')
            all_pools = list(ip_pool.select('name'))
            pool_names = [p.get('name', '') for p in all_pools]
            logger.info(f"Existing pools: {pool_names}")

            if pool_name not in pool_names:
                logger.info(f"Creating pool {pool_name}...")
                ip_pool.add(
                    name=pool_name,
                    ranges='172.31.0.2-172.31.255.254'
                )
                setup_results.append(f"Created pool {pool_name}")
                logger.info("Pool created")
            else:
                setup_results.append(f"Pool {pool_name} exists")
                logger.info("Pool already exists")

            # 3. Ensure bridge has IP address
            logger.info("Step 3: Checking/assigning bridge IP...")
            ip_address = api.path('/ip/address')
            all_addresses = list(ip_address.select('address', 'interface'))
            bridge_addresses = [a for a in all_addresses if a.get('interface') == bridge_name]
            logger.info(f"Bridge addresses: {bridge_addresses}")

            if not bridge_addresses:
                logger.info("Assigning IP to bridge...")
                ip_address.add(
                    address='172.31.0.1/16',
                    interface=bridge_name,
                    network='172.31.0.0',
                    comment=f'{isp_brand} bridge IP'
                )
                setup_results.append(f"Assigned IP to {bridge_name}")
                logger.info("IP assigned")
            else:
                setup_results.append(f"IP already assigned to {bridge_name}")
                logger.info("IP already assigned")

            # 4. Remove interface from any existing bridge first
            logger.info(f"Step 4: Checking if {interface} is in another bridge...")
            bridge_port = api.path('/interface/bridge/port')
            all_ports = list(bridge_port.select('.id', 'interface', 'bridge'))

            for port in all_ports:
                if port.get('interface') == interface:
                    current_bridge = port.get('bridge')
                    logger.info(f"{interface} is in bridge: {current_bridge}")
                    if current_bridge != bridge_name:
                        logger.info(f"Removing {interface} from {current_bridge}...")
                        bridge_port.remove(port['.id'])
                        setup_results.append(f"Removed {interface} from {current_bridge}")
                        logger.info(f"Removed {interface} from bridge")
                    break

            # 5. Add interface to target bridge
            logger.info(f"Step 5: Adding {interface} to {bridge_name}...")
            try:
                bridge_port.add(
                    interface=interface,
                    bridge=bridge_name,
                    comment=f'Added by {isp_brand}'
                )
                setup_results.append(f"Added {interface} to {bridge_name}")
                logger.info(f"Added {interface} to {bridge_name}")
            except Exception as e:
                if 'already added' not in str(e):
                    logger.error(f"Error adding to bridge: {str(e)}")
                    raise e
                setup_results.append(f"{interface} already in {bridge_name}")
                logger.info(f"{interface} already in {bridge_name}")

            # 6. Create hotspot profile
            logger.info("Step 6: Checking/creating hotspot profile...")
            hotspot_profile = api.path('/ip/hotspot/profile')
            profile_name = f'{isp_brand}-hotspot-profile'

            logger.info("Getting existing hotspot profiles...")
            all_profiles = list(hotspot_profile.select('name'))
            profile_names = [p.get('name', '') for p in all_profiles]
            logger.info(f"Existing hotspot profiles: {profile_names}")

            if profile_name not in profile_names:
                logger.info(f"Creating hotspot profile {profile_name}...")
                profile_config = {
                    'name': profile_name,
                    'hotspot-address': '172.31.0.1',
                    'dns-name': 'router.local',
                    'html-directory': 'hotspot',
                    'login-by': 'http-chap,http-pap'
                }
                logger.info(f"Profile config: {profile_config}")
                hotspot_profile.add(**profile_config)
                setup_results.append(f"Created hotspot profile {profile_name}")
                logger.info("Hotspot profile created")
            else:
                setup_results.append(f"Hotspot profile {profile_name} exists")
                logger.info("Hotspot profile already exists")

            # 7. Configure hotspot server on bridge
            logger.info("Step 7: Configuring hotspot server...")
            hotspot = api.path('/ip/hotspot')

            logger.info(f"Checking if hotspot {hotspot_name} exists...")
            existing_hotspot = list(hotspot.select('.id', 'name').where('name', hotspot_name))
            logger.info(f"Existing hotspot search result: {existing_hotspot}")

            if existing_hotspot:
                logger.info(f"Hotspot {hotspot_name} exists, updating...")
                hotspot.update(
                    **{'.id': existing_hotspot[0]['.id']},
                    interface=bridge_name
                )
                setup_results.append(f"Updated hotspot {hotspot_name} to use bridge {bridge_name}")
                logger.info("Hotspot updated")
            else:
                logger.info(f"Creating new hotspot {hotspot_name}...")
                hotspot_config = {
                    'name': hotspot_name,
                    'interface': bridge_name,
                    'address-pool': pool_name,
                    'profile': profile_name,
                    'addresses-per-mac': config.get('addresses_per_mac', 1)
                }
                logger.info(f"Hotspot config: {hotspot_config}")
                logger.info("Calling hotspot.add()...")
                hotspot.add(**hotspot_config)
                logger.info("Hotspot.add() completed")

                if config.get('auto_enable', False):
                    logger.info("Enabling hotspot server...")
                    hotspot.update(**{'.id': '*last'}, disabled='no')
                    setup_results.append(f"Created and enabled hotspot server {hotspot_name} on bridge {bridge_name}")
                    logger.info("Hotspot enabled")
                else:
                    setup_results.append(f"Created hotspot server {hotspot_name} on bridge {bridge_name} (disabled)")
                    logger.info("Hotspot created (disabled)")

            logger.info("Closing connection...")
            api.close()
            logger.info("Connection closed")

            result = {
                'success': True,
                'hotspot_name': hotspot_name,
                'interface': interface,
                'bridge_name': bridge_name,
                'pool_name': pool_name,
                'setup_results': setup_results
            }
            logger.info(f"Returning success result: {result}")
            return result

        except Exception as e:
            logger.error(f"Failed to configure hotspot server {hotspot_name} on {interface}", error=str(e))
            logger.error(f"Exception type: {type(e).__name__}")
            logger.error(f"Exception details: {str(e)}", exc_info=True)
            return {
                'success': False,
                'error': str(e)
            }

    def configure_multiple_servers_dynamic(self, username: str, password: str, host: str, port: int,
                                          interfaces_config: List[Dict]) -> Dict:
        """Configure multiple interfaces as PPPoE or Hotspot servers in a single connection"""
        try:
            logger.info("=== configure_multiple_servers_dynamic called ===")
            logger.info(f"Host: {host}, Port: {port}, User: {username}")
            logger.info(f"Interfaces config: {interfaces_config}")

            import librouteros

            logger.info(f"Attempting connection to {host}:{port}...")
            api = librouteros.connect(
                host=host, username=username, password=password, port=port, timeout=10
            )
            logger.info("Connection established successfully")

            isp_brand = self.app.config.get('ISP_BRAND', 'f2net')
            bridge_name = self.app.config.get('ISP_BRIDGE_NAME', f'{isp_brand}_bridge')
            pool_name = self.app.config.get('ISP_POOL_NAME', f'{isp_brand}_pool')

            logger.info(f"ISP Brand: {isp_brand}, Bridge: {bridge_name}, Pool: {pool_name}")

            global_setup_results = []
            interface_results = []

            # ===== SHARED PREREQUISITES (Run Once) =====

            logger.info("Step 1: Checking/creating bridge...")
            # 1. Ensure bridge exists
            bridge_interface = api.path('/interface/bridge')
            all_bridges = list(bridge_interface.select('name'))
            bridge_names = [b.get('name', '') for b in all_bridges]
            logger.info(f"Existing bridges: {bridge_names}")

            if bridge_name not in bridge_names:
                logger.info(f"Creating bridge {bridge_name}...")
                bridge_interface.add(
                    name=bridge_name,
                    **{'auto-mac': 'yes'},
                    comment=f'Created by {isp_brand}'
                )
                global_setup_results.append(f"Created bridge {bridge_name}")
                logger.info(f"Bridge {bridge_name} created")
            else:
                global_setup_results.append(f"Bridge {bridge_name} exists")
                logger.info(f"Bridge {bridge_name} already exists")

            logger.info("Step 2: Checking/creating IP pool...")
            # 2. Ensure IP pool exists
            ip_pool = api.path('/ip/pool')
            all_pools = list(ip_pool.select('name'))
            pool_names_list = [p.get('name', '') for p in all_pools]
            logger.info(f"Existing pools: {pool_names_list}")

            if pool_name not in pool_names_list:
                logger.info(f"Creating pool {pool_name}...")
                ip_pool.add(
                    name=pool_name,
                    ranges='172.31.0.2-172.31.255.254'
                )
                global_setup_results.append(f"Created pool {pool_name}")
                logger.info(f"Pool {pool_name} created")
            else:
                global_setup_results.append(f"Pool {pool_name} exists")
                logger.info(f"Pool {pool_name} already exists")

            logger.info("Step 3: Checking/assigning bridge IP address...")
            # 3. Ensure bridge has IP address
            ip_address = api.path('/ip/address')
            all_addresses = list(ip_address.select('address', 'interface'))
            bridge_addresses = [a for a in all_addresses if a.get('interface') == bridge_name]
            logger.info(f"Bridge {bridge_name} addresses: {bridge_addresses}")

            if not bridge_addresses:
                logger.info(f"Assigning IP 172.31.0.1/16 to {bridge_name}...")
                ip_address.add(
                    address='172.31.0.1/16',
                    interface=bridge_name,
                    network='172.31.0.0',
                    comment=f'{isp_brand} bridge IP'
                )
                global_setup_results.append(f"Assigned IP to {bridge_name}")
                logger.info("IP assigned")
            else:
                global_setup_results.append(f"IP already assigned to {bridge_name}")
                logger.info("IP already assigned")

            logger.info(f"Global setup completed: {global_setup_results}")

            # ===== CONFIGURE EACH INTERFACE =====

            logger.info(f"Starting to configure {len(interfaces_config)} interfaces...")
            for idx, iface_config in enumerate(interfaces_config):
                logger.info(f"=== Processing interface {idx + 1}/{len(interfaces_config)} ===")
                logger.info(f"Interface config: {iface_config}")

                interface = iface_config['interface']
                server_type = iface_config['type'].lower()
                setup_steps = []

                logger.info(f"Interface: {interface}, Type: {server_type}")

                try:
                    logger.info(f"Checking bridge port assignment for {interface}...")
                    # Remove interface from any existing bridge first
                    bridge_port = api.path('/interface/bridge/port')
                    all_ports = list(bridge_port.select('.id', 'interface', 'bridge'))

                    for port in all_ports:
                        if port.get('interface') == interface:
                            current_bridge = port.get('bridge')
                            logger.info(f"{interface} is currently in bridge: {current_bridge}")
                            if current_bridge != bridge_name:
                                logger.info(f"Removing {interface} from {current_bridge}...")
                                bridge_port.remove(port['.id'])
                                setup_steps.append(f"Removed {interface} from {current_bridge}")
                                logger.info("Removed")
                            break

                    # Add interface to target bridge
                    logger.info(f"Adding {interface} to {bridge_name}...")
                    try:
                        bridge_port.add(
                            interface=interface,
                            bridge=bridge_name,
                            comment=f'Added by {isp_brand}'
                        )
                        setup_steps.append(f"Added {interface} to {bridge_name}")
                        logger.info(f"{interface} added to {bridge_name}")
                    except Exception as e:
                        if 'already added' not in str(e):
                            logger.error(f"Error adding {interface} to bridge: {str(e)}")
                            raise e
                        setup_steps.append(f"{interface} already in {bridge_name}")
                        logger.info(f"{interface} already in {bridge_name}")

                    # Configure based on type
                    logger.info(f"Configuring {server_type} server for {interface}...")
                    if server_type == 'pppoe':
                        logger.info("PPPoE configuration started")
                        service_name = iface_config['service_name']
                        config = iface_config.get('config', {})
                        logger.info(f"Service name: {service_name}, Config: {config}")

                        # Create PPPoE profile
                        logger.info("Checking/creating PPPoE profile...")
                        pppoe_profile = api.path('/ppp/profile')
                        profile_name = f'{isp_brand}-pppoe-profile'

                        all_profiles = list(pppoe_profile.select('name'))
                        profile_names_list = [p.get('name', '') for p in all_profiles]
                        logger.info(f"Existing PPPoE profiles: {profile_names_list}")

                        if profile_name not in profile_names_list:
                            logger.info(f"Creating PPPoE profile {profile_name}...")
                            profile_config = {
                                'name': profile_name,
                                'local-address': config.get('local_address', '172.31.0.1'),
                                'remote-address': pool_name,
                                'use-encryption': 'yes' if config.get('use_encryption', True) else 'no',
                                'comment': f'Created by {isp_brand}'
                            }
                            pppoe_profile.add(**profile_config)
                            setup_steps.append(f"Created PPPoE profile {profile_name}")
                        else:
                            setup_steps.append(f"PPPoE profile {profile_name} exists")

                        # Configure PPPoE server
                        logger.info("Configuring PPPoE server...")
                        pppoe_server = api.path('/interface/pppoe-server/server')
                        existing_server = list(pppoe_server.select('.id', 'service-name').where('service-name', service_name))

                        if existing_server:
                            logger.info(f"PPPoE server {service_name} exists, updating...")
                            server_id = existing_server[0]['.id']

                            # Update interface and disabled status
                            update_config = {
                                '.id': server_id,
                                'interface': bridge_name
                            }

                            # Handle auto_enable for existing servers
                            if iface_config.get('auto_enable', False):
                                update_config['disabled'] = 'no'
                                logger.info("Setting server to enabled")
                            else:
                                update_config['disabled'] = 'yes'
                                logger.info("Setting server to disabled")

                            pppoe_server.update(**update_config)

                            if iface_config.get('auto_enable', False):
                                setup_steps.append(f"Updated and enabled PPPoE server {service_name}")
                                logger.info("PPPoE server updated and enabled")
                            else:
                                setup_steps.append(f"Updated PPPoE server {service_name} (disabled)")
                                logger.info("PPPoE server updated (disabled)")
                        else:
                            logger.info(f"Creating new PPPoE server {service_name}...")
                            server_config = {
                                'service-name': service_name,
                                'interface': bridge_name,
                                'default-profile': profile_name,
                                'authentication': config.get('authentication', 'pap,chap,mschap1,mschap2'),
                                'keepalive-timeout': str(config.get('keepalive_timeout', 60)),
                                'comment': f'Created by {isp_brand}'
                            }
                            pppoe_server.add(**server_config)

                            if iface_config.get('auto_enable', False):
                                pppoe_server.update(**{'.id': '*last'}, disabled='no')
                                setup_steps.append(f"Created and enabled PPPoE server {service_name}")
                                logger.info("PPPoE server created and enabled")
                            else:
                                setup_steps.append(f"Created PPPoE server {service_name} (disabled)")
                                logger.info("PPPoE server created (disabled)")

                        interface_results.append({
                            'interface': interface,
                            'type': 'pppoe',
                            'service_name': service_name,
                            'success': True,
                            'message': f'PPPoE server {service_name} configured successfully',
                            'setup_steps': setup_steps
                        })

                    elif server_type == 'hotspot':
                        hotspot_name = iface_config['hotspot_name']
                        config = iface_config.get('config', {})

                        # Create hotspot profile
                        hotspot_profile = api.path('/ip/hotspot/profile')
                        profile_name = f'{isp_brand}-hotspot-profile'

                        all_profiles = list(hotspot_profile.select('name'))
                        profile_names_list = [p.get('name', '') for p in all_profiles]

                        if profile_name not in profile_names_list:
                            profile_config = {
                                'name': profile_name,
                                'hotspot-address': '172.31.0.1',
                                'dns-name': 'router.local',
                                'html-directory': 'hotspot',
                                'login-by': 'http-chap,http-pap'
                            }
                            hotspot_profile.add(**profile_config)
                            setup_steps.append(f"Created hotspot profile {profile_name}")
                        else:
                            setup_steps.append(f"Hotspot profile {profile_name} exists")

                        # Configure hotspot server
                        logger.info("Configuring hotspot server...")
                        hotspot = api.path('/ip/hotspot')
                        existing_hotspot = list(hotspot.select('.id', 'name').where('name', hotspot_name))

                        if existing_hotspot:
                            logger.info(f"Hotspot {hotspot_name} exists, updating...")
                            hotspot_id = existing_hotspot[0]['.id']

                            # Update interface and disabled status
                            update_config = {
                                '.id': hotspot_id,
                                'interface': bridge_name
                            }

                            # Handle auto_enable for existing hotspots
                            if iface_config.get('auto_enable', False):
                                update_config['disabled'] = 'no'
                                logger.info("Setting hotspot to enabled")
                            else:
                                update_config['disabled'] = 'yes'
                                logger.info("Setting hotspot to disabled")

                            hotspot.update(**update_config)

                            if iface_config.get('auto_enable', False):
                                setup_steps.append(f"Updated and enabled hotspot {hotspot_name}")
                                logger.info("Hotspot updated and enabled")
                            else:
                                setup_steps.append(f"Updated hotspot {hotspot_name} (disabled)")
                                logger.info("Hotspot updated (disabled)")
                        else:
                            logger.info(f"Creating new hotspot {hotspot_name}...")
                            hotspot_config = {
                                'name': hotspot_name,
                                'interface': bridge_name,
                                'address-pool': pool_name,
                                'profile': profile_name,
                                'addresses-per-mac': config.get('addresses_per_mac', 1)
                            }
                            hotspot.add(**hotspot_config)

                            if iface_config.get('auto_enable', False):
                                hotspot.update(**{'.id': '*last'}, disabled='no')
                                setup_steps.append(f"Created and enabled hotspot server {hotspot_name}")
                                logger.info("Hotspot created and enabled")
                            else:
                                setup_steps.append(f"Created hotspot server {hotspot_name} (disabled)")
                                logger.info("Hotspot created (disabled)")

                        interface_results.append({
                            'interface': interface,
                            'type': 'hotspot',
                            'hotspot_name': hotspot_name,
                            'success': True,
                            'message': f'Hotspot server {hotspot_name} configured successfully',
                            'setup_steps': setup_steps
                        })

                    else:
                        interface_results.append({
                            'interface': interface,
                            'type': server_type,
                            'success': False,
                            'message': f'Unknown server type: {server_type}',
                            'error': f'Supported types are: pppoe, hotspot'
                        })

                except Exception as e:
                    logger.error(f"Failed to configure {interface} as {server_type}", error=str(e))
                    logger.error(f"Exception type: {type(e).__name__}, Details: {str(e)}")
                    interface_results.append({
                        'interface': interface,
                        'type': server_type,
                        'success': False,
                        'message': f'Failed to configure {server_type} server',
                        'error': str(e)
                    })

            logger.info("All interfaces processed, closing connection...")
            api.close()
            logger.info("Connection closed")

            # Calculate summary
            successful = sum(1 for r in interface_results if r['success'])
            failed = len(interface_results) - successful

            logger.info(f"Summary: {successful} successful, {failed} failed out of {len(interface_results)} total")

            result = {
                'success': True,
                'bridge_name': bridge_name,
                'pool_name': pool_name,
                'global_setup': global_setup_results,
                'results': interface_results,
                'summary': {
                    'total': len(interface_results),
                    'successful': successful,
                    'failed': failed
                }
            }

            logger.info(f"Returning result: {result}")
            return result

        except Exception as e:
            logger.error(f"Failed to configure multiple servers - EXCEPTION IN MAIN TRY BLOCK", error=str(e))
            logger.error(f"Exception type: {type(e).__name__}")
            logger.error(f"Exception details: {str(e)}", exc_info=True)
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