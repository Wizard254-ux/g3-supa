"""
Enhanced OpenVPN Manager for ISP Middleware
Integrates with SystemService for secure operations with audit logging and validation
"""

import os
import traceback

import structlog
import socket
import re
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from pathlib import Path
import tempfile
import shutil
import json

from services.system_service import SystemServiceFactory, SystemOperationError
from security.audit_logger import AuditLogger, audit_system_operation
from security.validator import SecurityValidator

logger = structlog.get_logger()
audit_logger = AuditLogger()


class OpenVPNManager:
    """Enhanced OpenVPN management service with SystemService integration"""

    def __init__(self, app=None):
        self.app = app
        self.config_dir = None
        self.client_config_dir = None
        self.ca_cert = None
        self.server_cert = None
        self.server_key = None
        self.dh_params = None
        self.server_ip = None
        self.server_mask = None

        # Initialize system services
        self.openvpn_service = SystemServiceFactory.get_openvpn_service()
        self.cert_service = SystemServiceFactory.get_certificate_service()
        self.network_service = SystemServiceFactory.get_network_service()

        if app:
            self.init_app(app)

    def init_app(self, app):
        """Initialize the service with Flask app"""
        self.app = app
        self.config_dir = app.config.get('OPENVPN_CONFIG_DIR', '/etc/openvpn')
        self.client_config_dir = app.config.get('OPENVPN_CLIENT_CONFIG_DIR', '/etc/openvpn/clients')
        self.ca_cert = app.config.get('OPENVPN_CA_CERT', '/etc/openvpn/ca.crt')
        self.server_cert = app.config.get('OPENVPN_SERVER_CERT', '/etc/openvpn/server.crt')
        self.server_key = app.config.get('OPENVPN_SERVER_KEY', '/etc/openvpn/server.key')
        self.dh_params = app.config.get('OPENVPN_DH_PARAMS', '/etc/openvpn/dh2048.pem')
        self.server_ip = app.config.get('OPENVPN_SERVER_IP', '10.8.0.0')
        self.server_mask = app.config.get('OPENVPN_SERVER_MASK', '255.255.255.0')

        # Ensure directories exist
        self._ensure_directories()

        logger.info("Enhanced OpenVPN Manager initialized with SystemService integration")

    def _ensure_directories(self):
        """Ensure required directories exist"""
        try:
            Path(self.config_dir).mkdir(parents=True, exist_ok=True)
            Path(self.client_config_dir).mkdir(parents=True, exist_ok=True)
            Path(f"{self.config_dir}/keys").mkdir(parents=True, exist_ok=True)
            Path(f"{self.config_dir}/ccd").mkdir(parents=True, exist_ok=True)
            Path(f"{self.config_dir}/client_metadata").mkdir(parents=True, exist_ok=True)
        except PermissionError as e:
            logger.error("Permission denied creating OpenVPN directories. Run fix_openvpn_permissions.sh as root.", error=str(e))
            raise SystemOperationError(f"Directory creation failed due to permissions. Please ensure the application user has write access to {self.client_config_dir} and {self.config_dir}/client_metadata")
        except Exception as e:
            logger.error("Failed to create OpenVPN directories", error=str(e))
            raise SystemOperationError(f"Directory creation failed: {e}")

    @audit_system_operation('openvpn_status_check')
    def check_server_status(self, config_name: str = 'server') -> Dict[str, Any]:
        """Check OpenVPN server status using SystemService"""
        try:
            # Validate config name
            if not SecurityValidator.validate_config_name(f"f2net_{config_name}"):
                raise SystemOperationError("Invalid config name format")

            # Get service status using SystemService
            status_result = self.openvpn_service.get_service_status(f"f2net_{config_name}")

            # Check if OpenVPN process is listening
            listening = self._check_port_listening(1194)

            # Get connected clients
            connected_clients = self._get_connected_clients()

            # Get server statistics
            stats = self._get_server_stats()

            # Get additional metrics
            server_metrics = self._get_server_metrics()

            result = {
                'service_running': status_result.get('active', False),
                'service_status': status_result.get('status', 'unknown'),
                'port_listening': listening,
                'connected_clients': len(connected_clients),
                'client_list': connected_clients,
                'stats': stats,
                'metrics': server_metrics,
                'config_name': config_name,
                'timestamp': datetime.utcnow().isoformat(),
                'health_score': self._calculate_health_score(status_result.get('active', False), listening,
                                                             len(connected_clients))
            }

            logger.info(f"OpenVPN status checked for {config_name}", result=result)
            return result

        except Exception as e:
            logger.error(f"Failed to check OpenVPN server status for {config_name}", error=str(e))
            return {
                'service_running': False,
                'port_listening': False,
                'connected_clients': 0,
                'client_list': [],
                'error': str(e),
                'health_score': 0,
                'timestamp': datetime.utcnow().isoformat()
            }

    def _calculate_health_score(self, service_running: bool, port_listening: bool, client_count: int) -> int:
        """Calculate health score (0-100)"""
        score = 0
        if service_running:
            score += 50
        if port_listening:
            score += 30
        if client_count > 0:
            score += 20
        return score

    def _get_server_metrics(self) -> Dict[str, Any]:
        """Get additional server metrics"""
        try:
            metrics = {
                'uptime': self._get_service_uptime(),
                'memory_usage': self._get_process_memory(),
                'cpu_usage': self._get_process_cpu(),
                'network_interfaces': self._get_network_interfaces(),
                'certificate_expiry': self._get_certificate_expiry_days()
            }
            return metrics
        except Exception as e:
            logger.error("Failed to get server metrics", error=str(e))
            return {}

    def _get_service_uptime(self) -> str:
        """Get service uptime"""
        try:
            from services.system_service import SystemService
            system_service = SystemService()
            success, stdout, stderr = system_service._run_command([
                'systemctl', 'show', 'openvpn@f2net_server', '--property=ActiveEnterTimestamp'
            ])

            if success and stdout:
                timestamp_line = stdout.strip()
                if '=' in timestamp_line:
                    timestamp_str = timestamp_line.split('=')[1]
                    if timestamp_str and timestamp_str != 'n/a':
                        return timestamp_str

            return "Unknown"
        except Exception:
            return "Unknown"

    def _get_process_memory(self) -> Dict[str, Any]:
        """Get OpenVPN process memory usage"""
        try:
            import psutil
            for proc in psutil.process_iter(['pid', 'name', 'memory_info']):
                if 'openvpn' in proc.info['name'].lower():
                    memory_info = proc.info['memory_info']
                    return {
                        'rss_mb': round(memory_info.rss / 1024 / 1024, 2),
                        'vms_mb': round(memory_info.vms / 1024 / 1024, 2)
                    }
            return {'rss_mb': 0, 'vms_mb': 0}
        except Exception:
            return {'rss_mb': 0, 'vms_mb': 0}

    def _get_process_cpu(self) -> float:
        """Get OpenVPN process CPU usage"""
        try:
            import psutil
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent']):
                if 'openvpn' in proc.info['name'].lower():
                    return proc.info['cpu_percent']
            return 0.0
        except Exception:
            return 0.0

    def _get_network_interfaces(self) -> List[str]:
        """Get network interfaces used by OpenVPN"""
        try:
            import psutil
            interfaces = []
            for interface, addrs in psutil.net_if_addrs().items():
                if interface.startswith('tun') or interface.startswith('tap'):
                    interfaces.append(interface)
            return interfaces
        except Exception:
            return []

    def _get_certificate_expiry_days(self) -> int:
        """Get days until server certificate expires"""
        try:
            cert_info = self._get_certificate_info(self.server_cert)
            if 'not_after' in cert_info:
                expire_date = datetime.strptime(cert_info['not_after'], '%b %d %H:%M:%S %Y %Z')
                days_left = (expire_date - datetime.utcnow()).days
                return max(0, days_left)
            return -1
        except Exception:
            return -1

    @audit_system_operation('openvpn_client_certificate_generate')
    def generate_client_certificate(self, client_name: str, email: str = None,
                                    client_ip: str = None, user_id: str = None) -> Dict[str, Any]:
        """Generate client certificate using SystemService with enhanced validation"""
        try:
            # Enhanced validation
            if not SecurityValidator.validate_config_name(f"f2net_{client_name}"):
                raise SystemOperationError("Invalid client name format")

            if email and not self._validate_email(email):
                raise SystemOperationError("Invalid email format")
            if client_ip and not SecurityValidator.validate_ip_address(client_ip):
                raise SystemOperationError("Invalid client IP address")

            # Check if client already exists
            client_cert_path = f"{self.config_dir}/easy-rsa/pki/issued/f2net_{client_name}.crt"
            if os.path.exists(client_cert_path):
                raise SystemOperationError(f"Client 'f2net_{client_name}' already exists")

            # Generate certificate using SystemService
            cert_result = self.cert_service.generate_client_cert_reuse_request(f"f2net_{client_name}")

            if not cert_result.get('success'):
                raise SystemOperationError(f"Certificate generation failed: {cert_result.get('error')}")

            # Generate client configuration file with enhanced features
            config_content = self._generate_enhanced_client_config(
                client_name, email, client_ip, user_id
            )

            # Save client configuration
            config_file_path = f"{self.client_config_dir}/f2net_{client_name}.ovpn"
            with open(config_file_path, 'w') as f:
                f.write(config_content)
            # Create client-specific configuration if needed
            if client_ip:
                self._create_client_specific_config(client_name, client_ip)

            # Store client metadata
            metadata = {
                'client_name': client_name,
                'email': email,
                'assigned_ip': client_ip,
                'created_by': user_id,
                'created_at': datetime.utcnow().isoformat(),
                'status': 'active'
            }
            self._store_client_metadata(client_name, metadata)

            # logger.info(f"Generated client certificate for: f2net_{client_name}", metadata=metadata)

            return {
                'success': True,
                'client_name': client_name,
                'full_client_name': f"f2net_{client_name}",
                'config_file': config_file_path,
                'certificate_file': client_cert_path,
                'key_file': f"{self.config_dir}/easy-rsa/pki/private/f2net_{client_name}.key",
                'config_content': config_content,
                # 'metadata': metadata,
                'created_at': datetime.utcnow().isoformat()
            }

        except SystemOperationError as e:
            logger.error(f"Failed to generate client certificate for {client_name}", error=str(e))
            return {
                'success': False,
                'error': str(e),
                'client_name': client_name,
                'timestamp': datetime.utcnow().isoformat()
            }
        except Exception as e:
            logger.error(f"Failed to generate client certificate for {client_name}", error=str(e))
            return {
                'success': False,
                'error': f'Certificate generation failed: {str(e)}',
                'client_name': client_name,
                'timestamp': datetime.utcnow().isoformat()
            }

    def _validate_email(self, email: str) -> bool:
        """Validate email format"""
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
        return bool(re.match(email_pattern, email))

    def _store_client_metadata(self, client_name: str, metadata: Dict[str, Any]):
        """Store client metadata for tracking"""
        try:
            metadata_dir = f"{self.config_dir}/client_metadata"
            Path(metadata_dir).mkdir(exist_ok=True)

            metadata_file = f"{metadata_dir}/f2net_{client_name}.json"
            with open(metadata_file, 'w') as f:
                json.dump(metadata, f, indent=2)
        except Exception as e:
            logger.warning(f"Failed to store client metadata for {client_name}", error=str(e))

    def _load_client_metadata(self, client_name: str) -> Dict[str, Any]:
        """Load client metadata"""
        try:
            metadata_file = f"{self.config_dir}/client_metadata/f2net_{client_name}.json"
            if os.path.exists(metadata_file):
                with open(metadata_file, 'r') as f:
                    return json.load(f)
            return {}
        except Exception as e:
            logger.warning(f"Failed to load client metadata for {client_name}", error=str(e))
            return {}

    def _create_client_specific_config(self, client_name: str, client_ip: str):
        """Create client-specific configuration for static IP assignment"""
        try:
            ccd_file = f"{self.config_dir}/ccd/f2net_{client_name}"

            # Calculate network from client IP (assuming /30 subnet)
            ip_parts = client_ip.split('.')
            network_ip = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.{int(ip_parts[3]) & 0xFC}"

            config_content = f"ifconfig-push {client_ip} {network_ip}\n"

            with open(ccd_file, 'w') as f:
                f.write(config_content)

            logger.info(f"Created client-specific config for {client_name} with IP {client_ip}")

        except Exception as e:
            logger.error(f"Failed to create client-specific config for {client_name}", error=str(e))

    def _generate_enhanced_client_config(self, client_name: str, email: str = None,
                                         client_ip: str = None, user_id: str = None) -> str:
        """Generate enhanced OpenVPN client configuration file"""
        try:
            # Read certificate files
            with open(self.ca_cert, 'r') as f:
                ca_content = f.read()

            with open(f"{self.config_dir}/easy-rsa/pki/issued/f2net_{client_name}.crt", 'r') as f:
                cert_content = f.read()
            with open(f"{self.config_dir}/easy-rsa/pki/private/f2net_{client_name}.key", 'r') as f:
                key_content = f.read()

            # Get server configuration
            temp = self.parse_client_template()
            (server_host, server_port) = temp.get('config', {}).get("remote", "").split(None, 1)
            server_protocol = "tcp"

            # Enhanced configuration with security features
            config = f"""# OpenVPN Client Configuration
# Generated for: {client_name}
# Email: {email or 'N/A'}
# Created: {datetime.utcnow().isoformat()}
# User ID: {user_id or 'N/A'}

client
dev tun
proto {server_protocol}
remote {server_host} {server_port}

# Connection settings
resolv-retry infinite
nobind
persist-key
persist-tun

# Security settings
cipher AES-256-CBC
auth SHA1

# Logging and status
verb 3

# Reconnection settings
keepalive 10 120
comp-lzo

<ca>
{ca_content}
</ca>

<cert>
{cert_content}
</cert>

<key>
{key_content}
</key>
"""

            # Add TLS auth if available
            tls_auth_file = f"{self.config_dir}/ta.key"
            if os.path.exists(tls_auth_file):
                with open(tls_auth_file, 'r') as f:
                    tls_content = f.read()
                config += f"\n<tls-auth>\n{tls_content}\n</tls-auth>\n"

            return config

        except Exception as e:
            logger.error(f"Failed to generate enhanced client config for {client_name}", error=str(e))
            raise SystemOperationError(f"Config generation failed: {e}")

    @audit_system_operation('openvpn_client_certificate_revoke')
    def revoke_client_certificate(self, client_name: str, reason: str = None, user_id: str = None) -> Dict[str, Any]:
        """Revoke client certificate using SystemService with enhanced tracking"""
        try:
            # Validate client name
            if not SecurityValidator.validate_config_name(f"f2net_{client_name}"):
                raise SystemOperationError("Invalid client name format")

            # Check if client exists
            client_cert_path = f"{self.config_dir}/easy-rsa/pki/issued/f2net_{client_name}.crt"
            if not os.path.exists(client_cert_path):
                raise SystemOperationError(f"Client 'f2net_{client_name}' does not exist")

            # Disconnect client if connected
            disconnect_result = self.disconnect_client(client_name)

            # Revoke certificate using SystemService
            revoke_result = self.cert_service.revoke_client_cert(f"f2net_{client_name}")

            if not revoke_result.get('success'):
                raise SystemOperationError(f"Certificate revocation failed: {revoke_result.get('error')}")

            # Remove client files
            files_to_remove = [
                f"{self.config_dir}/easy-rsa/pki/issued/f2net_{client_name}.crt",
                f"{self.config_dir}/easy-rsa/pki/private/f2net_{client_name}.key",
                f"{self.client_config_dir}/f2net_{client_name}.ovpn",
                f"{self.config_dir}/ccd/f2net_{client_name}",
                f"{self.config_dir}/client_metadata/f2net_{client_name}.json"
            ]

            removed_files = []
            for file_path in files_to_remove:
                if os.path.exists(file_path):
                    os.remove(file_path)
                    removed_files.append(file_path)

            # Restart OpenVPN service to reload CRL using SystemService
            restart_result = self.openvpn_service.restart_service("f2net_server")

            # Log revocation with metadata
            revocation_data = {
                'client_name': client_name,
                'reason': reason,
                'revoked_by': user_id,
                'revoked_at': datetime.utcnow().isoformat(),
                'disconnect_result': disconnect_result,
                'removed_files': removed_files
            }

            logger.info(f"Revoked client certificate: f2net_{client_name}", data=revocation_data)

            return {
                'success': True,
                'client_name': client_name,
                'full_client_name': f"f2net_{client_name}",
                'revoked_at': datetime.utcnow().isoformat(),
                'reason': reason,
                'disconnect_result': disconnect_result,
                'service_restart': restart_result.get('success', False),
                'removed_files': removed_files
            }

        except SystemOperationError as e:
            logger.error(f"Failed to revoke client certificate for {client_name}", error=str(e))
            return {
                'success': False,
                'error': str(e),
                'client_name': client_name,
                'timestamp': datetime.utcnow().isoformat()
            }
        except Exception as e:
            logger.error(f"Failed to revoke client certificate for {client_name}", error=str(e))
            return {
                'success': False,
                'error': f'Certificate revocation failed: {str(e)}',
                'client_name': client_name,
                'timestamp': datetime.utcnow().isoformat()
            }

    @audit_system_operation('openvpn_client_disconnect')
    def disconnect_client(self, client_name: str, reason: str = None) -> Dict[str, Any]:
        """Disconnect a specific client with enhanced management interface support"""
        try:
            # Validate client name
            if not SecurityValidator.validate_config_name(f"f2net_{client_name}"):
                raise SystemOperationError("Invalid client name format")

            full_client_name = f"f2net_{client_name}"

            # Try management interface first
            management_result = self._disconnect_via_management(full_client_name)

            if management_result.get('success'):
                logger.info(f"Disconnected client via management interface: {full_client_name}")
                return {
                    'success': True,
                    'client_name': client_name,
                    'full_client_name': full_client_name,
                    'method': 'management_interface',
                    'reason': reason,
                    'disconnected_at': datetime.utcnow().isoformat()
                }

            # Fallback: Check if client is actually connected
            connected_clients = self._get_connected_clients()
            client_connected = any(
                client['common_name'] == full_client_name
                for client in connected_clients
            )

            if not client_connected:
                return {
                    'success': True,
                    'client_name': client_name,
                    'full_client_name': full_client_name,
                    'method': 'not_connected',
                    'message': 'Client was not connected',
                    'reason': reason
                }

            # Last resort: Log warning about management interface
            logger.warning(f"Could not disconnect client {full_client_name} - management interface not available")
            return {
                'success': False,
                'client_name': client_name,
                'full_client_name': full_client_name,
                'error': 'Management interface not available',
                'suggestion': 'Consider restarting OpenVPN service or enabling management interface'
            }

        except Exception as e:
            logger.error(f"Failed to disconnect client {client_name}", error=str(e))
            return {
                'success': False,
                'client_name': client_name,
                'error': str(e)
            }

    @audit_system_operation("openvpn_config_parse")
    def parse_openvpn_config(self):
        """Parse an OpenVPN configuration file into a structured format"""
        try:
            config_file = self.config_dir + "/server.conf"
            if not os.path.exists(config_file):
                return {}

            config = {}
            with open(config_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#') or line.startswith(';'):
                        continue

                    parts = line.split(None, 1)
                    directive = parts[0]
                    value = parts[1] if len(parts) > 1 else True

                    config[directive] = value

            return {
                "success": True,
                "config": config,
            }
        except Exception as e:
            logger.error("Failed to parse OpenVPN configuration", error=str(e))
            return {
                "success": False,
            }

    @audit_system_operation("client_template")
    def parse_client_template(self):
        """Parse an OpenVPN configuration file into a structured format"""
        try:
            config_file = self.config_dir + "/client-template.txt"
            if not os.path.exists(config_file):
                return {}

            config = {}
            with open(config_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#') or line.startswith(';'):
                        continue

                    parts = line.split(None, 1)
                    directive = parts[0]
                    value = parts[1] if len(parts) > 1 else True

                    config[directive] = value

            return {
                "success": True,
                "config": config,
            }
        except Exception as e:
            logger.error("Failed to parse client configuration", error=str(e))
            return {
                "success": False,
            }

    def _disconnect_via_management(self, client_name: str) -> Dict[str, Any]:
        """Disconnect client via OpenVPN management interface"""
        try:
            management_host = self.app.config.get('OPENVPN_MANAGEMENT_HOST', '127.0.0.1')
            management_port = self.app.config.get('OPENVPN_MANAGEMENT_PORT', 7505)
            management_socket = self.app.config.get('OPENVPN_MANAGEMENT_SOCKET')

            if management_socket and os.path.exists(management_socket):
                # Unix socket connection
                import socket
                sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                sock.settimeout(10)
                sock.connect(management_socket)

                # Send kill command
                command = f"kill {client_name}\n"
                sock.send(command.encode())
                response = sock.recv(1024).decode()
                sock.close()

                if "SUCCESS" in response:
                    return {'success': True, 'response': response}

            elif management_host and management_port:
                # TCP connection
                import socket
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(10)
                sock.connect((management_host, int(management_port)))

                # Send kill command
                command = f"kill {client_name}\n"
                sock.send(command.encode())
                response = sock.recv(1024).decode()
                sock.close()

                if "SUCCESS" in response:
                    return {'success': True, 'response': response}

            return {'success': False, 'error': 'Management interface not configured or available'}

        except Exception as e:
            logger.error(f"Management interface connection failed for {client_name}", error=str(e))
            return {'success': False, 'error': str(e)}

    def get_client_list(self) -> List[Dict[str, Any]]:
        """Get enhanced list of all client certificates with metadata"""
        try:
            clients = []
            keys_dir = f"{self.config_dir}/easy-rsa/pki/private"
            certs_dir = f"{self.config_dir}/easy-rsa/pki/issued"

            if not os.path.exists(keys_dir):
                return clients
            # List all client certificate files
            for file in os.listdir(certs_dir):
                if file.endswith('.crt') and file.startswith('f2net_') and file not in ['f2net_server.crt',
                                                                                        'f2net_ca.crt']:
                    full_client_name = file[:-4]  # Remove .crt extension
                    client_name = full_client_name.replace('f2net_', '', 1)  # Remove f2net_ prefix

                    cert_path = f"{certs_dir}/{file}"
                    key_path = f"{keys_dir}/{full_client_name}.key"
                    config_path = f"{self.client_config_dir}/{full_client_name}.ovpn"
                    ccd_path = f"{self.config_dir}/ccd/{full_client_name}"

                    # Get certificate info
                    cert_info = self._get_certificate_info(cert_path)

                    # Get client metadata
                    metadata = self._load_client_metadata(client_name)

                    # Get connection info
                    connection_info = self._get_client_connection_info(full_client_name)

                    clients.append({
                        'name': client_name,
                        'full_name': full_client_name,
                        'certificate_file': cert_path,
                        'key_file': key_path if os.path.exists(key_path) else None,
                        'config_file': config_path if os.path.exists(config_path) else None,
                        'ccd_file': ccd_path if os.path.exists(ccd_path) else None,
                        'created_at': cert_info.get('not_before'),
                        'expires_at': cert_info.get('not_after'),
                        'days_until_expiry': self._calculate_days_until_expiry(cert_info.get('not_after')),
                        'is_valid': cert_info.get('is_valid', False),
                        'serial_number': cert_info.get('serial_number'),
                        'is_connected': connection_info.get('is_connected', False),
                        'connection_info': connection_info,
                        'metadata': metadata,
                        'email': metadata.get('email'),
                        'assigned_ip': metadata.get('assigned_ip'),
                        'created_by': metadata.get('created_by'),
                        'status': metadata.get('status', 'unknown')
                    })
                else:
                    print(file)

            return sorted(clients, key=lambda x: x['name'])

        except Exception as e:
            logger.error("Failed to get enhanced client list", error=str(e))
            return []

    def _get_client_connection_info(self, full_client_name: str) -> Dict[str, Any]:
        """Get detailed connection information for a client"""
        try:
            connected_clients = self._get_connected_clients()

            for client in connected_clients:
                if client['common_name'] == full_client_name:
                    return {
                        'is_connected': True,
                        'real_address': client.get('real_address'),
                        'virtual_address': client.get('virtual_address'),
                        'bytes_received': client.get('bytes_received', 0),
                        'bytes_sent': client.get('bytes_sent', 0),
                        'connected_since': client.get('connected_since'),
                        'connection_duration': self._calculate_connection_duration(client.get('connected_since'))
                    }

            return {'is_connected': False}

        except Exception as e:
            logger.error(f"Failed to get connection info for {full_client_name}", error=str(e))
            return {'is_connected': False, 'error': str(e)}

    def _calculate_connection_duration(self, connected_since: str) -> str:
        """Calculate connection duration"""
        try:
            if not connected_since:
                return "Unknown"

            # Parse connection time (format may vary)
            # This is a simplified version - adjust based on your OpenVPN date format
            connect_time = datetime.strptime(connected_since, '%a %b %d %H:%M:%S %Y')
            duration = datetime.utcnow() - connect_time

            hours, remainder = divmod(duration.total_seconds(), 3600)
            minutes, seconds = divmod(remainder, 60)

            return f"{int(hours):02d}:{int(minutes):02d}:{int(seconds):02d}"

        except Exception:
            return "Unknown"

    def _calculate_days_until_expiry(self, not_after: str) -> int:
        """Calculate days until certificate expires"""
        try:
            if not not_after:
                return -1

            expire_date = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
            days_left = (expire_date - datetime.utcnow()).days
            return max(0, days_left)

        except Exception:
            return -1

    @audit_system_operation('openvpn_service_control')
    def control_service(self, action: str, config_name: str = 'server') -> Dict[str, Any]:
        """Control OpenVPN service using SystemService"""
        try:
            # Validate inputs
            allowed_actions = ['start', 'stop', 'restart', 'status']
            if action not in allowed_actions:
                raise SystemOperationError(f"Invalid action. Allowed: {allowed_actions}")

            if not SecurityValidator.validate_config_name(f"f2net_{config_name}"):
                raise SystemOperationError("Invalid config name format")

            full_config_name = f"f2net_{config_name}"

            # Execute action using SystemService
            if action == 'start':
                result = self.openvpn_service.start_service(full_config_name)
            elif action == 'stop':
                result = self.openvpn_service.stop_service(full_config_name)
            elif action == 'restart':
                result = self.openvpn_service.restart_service(full_config_name)
            elif action == 'status':
                result = self.openvpn_service.get_service_status(full_config_name)

            logger.info(f"OpenVPN service {action} executed", config=full_config_name, result=result)

            return {
                'success': result.get('success', True),
                'action': action,
                'config_name': config_name,
                'full_config_name': full_config_name,
                'result': result,
                'timestamp': datetime.utcnow().isoformat()
            }

        except SystemOperationError as e:
            logger.error(f"Failed to {action} OpenVPN service for {config_name}", error=str(e))
            return {
                'success': False,
                'error': str(e),
                'action': action,
                'config_name': config_name,
                'timestamp': datetime.utcnow().isoformat()
            }
        except Exception as e:
            logger.error(f"Failed to {action} OpenVPN service for {config_name}", error=str(e))
            return {
                'success': False,
                'error': f'Service control failed: {str(e)}',
                'action': action,
                'config_name': config_name,
                'timestamp': datetime.utcnow().isoformat()
            }

    # Keep existing methods with minimal changes
    def _check_port_listening(self, port: int) -> bool:
        """Check if a port is listening"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(1)
            result = sock.connect_ex(('localhost', port))
            sock.close()
            return result == 0
        except Exception:
            return False

    def _get_connected_clients(self) -> List[Dict[str, Any]]:
        """Get list of connected VPN clients (enhanced version)"""
        try:
            status_file = f"{self.config_dir}/openvpn-status.log"

            if not os.path.exists(status_file):
                return []

            clients = []

            with open(status_file, 'r') as f:
                lines = f.readlines()

            # Parse OpenVPN status file
            in_client_section = False

            for line in lines:
                line = line.strip()

                if line.startswith('Common Name,Real Address,Bytes Received,Bytes Sent,Connected Since'):
                    in_client_section = True
                    continue

                if line.startswith('ROUTING TABLE'):
                    in_client_section = False
                    break

                if in_client_section and line and not line.startswith('TITLE') and ',' in line:
                    parts = line.split(',')
                    if len(parts) >= 5:
                        clients.append({
                            'common_name': parts[0],
                            'real_address': parts[1],
                            'bytes_received': int(parts[2]) if parts[2].isdigit() else 0,
                            'bytes_sent': int(parts[3]) if parts[3].isdigit() else 0,
                            'connected_since': parts[4],
                            'virtual_address': self._get_client_virtual_ip(parts[0])
                        })

            return clients

        except Exception as e:
            logger.error("Failed to get connected clients", error=str(e))
            return []

    def _get_client_virtual_ip(self, common_name: str) -> str:
        """Get virtual IP address for a client"""
        try:
            status_file = f"{self.config_dir}/openvpn-status.log"

            with open(status_file, 'r') as f:
                content = f.read()

            # Find virtual IP in routing table section
            routing_section = content.split('ROUTING TABLE')[1].split('GLOBAL STATS')[
                0] if 'ROUTING TABLE' in content else ''

            for line in routing_section.split('\n'):
                if common_name in line and ',' in line:
                    parts = line.split(',')
                    if len(parts) >= 2:
                        return parts[0]

            return 'Unknown'

        except Exception:
            return 'Unknown'

    def _get_server_stats(self) -> Dict[str, Any]:
        """Get OpenVPN server statistics"""
        try:
            status_file = f"{self.config_dir}/openvpn-status.log"

            if not os.path.exists(status_file):
                return {}

            with open(status_file, 'r') as f:
                content = f.read()

            stats = {}

            # Parse global stats section
            if 'GLOBAL STATS' in content:
                global_section = content.split('GLOBAL STATS')[1] if 'GLOBAL STATS' in content else ''

                for line in global_section.split('\n'):
                    if ',' in line:
                        parts = line.split(',')
                        if len(parts) >= 2:
                            stats[parts[0]] = parts[1]

            return stats

        except Exception as e:
            logger.error("Failed to get server stats", error=str(e))
            return {}

    def _get_certificate_info(self, cert_path: str) -> Dict[str, Any]:
        """Get certificate information using openssl"""
        try:
            from services.system_service import SystemService
            system_service = SystemService()

            # Get certificate details
            success, stdout, stderr = system_service._run_command([
                'openssl', 'x509', '-in', cert_path, '-text', '-noout'
            ])

            if not success:
                return {}

            cert_text = stdout

            # Parse certificate info
            info = {}

            # Extract serial number
            serial_match = re.search(r'Serial Number:\s*(\w+)', cert_text)
            if serial_match:
                info['serial_number'] = serial_match.group(1)

            # Extract validity dates
            not_before_match = re.search(r'Not Before:\s*(.+)', cert_text)
            if not_before_match:
                info['not_before'] = not_before_match.group(1).strip()

            not_after_match = re.search(r'Not After\s*:\s*(.+)', cert_text)
            if not_after_match:
                info['not_after'] = not_after_match.group(1).strip()

            # Check if certificate is valid (not expired)
            if 'not_after' in info:
                try:
                    expire_date = datetime.strptime(info['not_after'], '%b %d %H:%M:%S %Y %Z')
                    info['is_valid'] = expire_date > datetime.utcnow()
                except:
                    info['is_valid'] = False

            return info

        except Exception as e:
            logger.error(f"Failed to get certificate info for {cert_path}", error=str(e))
            return {}

    @audit_system_operation('openvpn_backup')
    def backup_configuration(self) -> Dict[str, Any]:
        """Create backup of OpenVPN configuration with enhanced metadata"""
        try:
            timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
            backup_dir = f"/var/backups/f2net_openvpn_{timestamp}"

            # Create backup directory
            os.makedirs(backup_dir, exist_ok=True)

            # Copy configuration files
            shutil.copytree(self.config_dir, f"{backup_dir}/config", dirs_exist_ok=True)
            shutil.copytree(self.client_config_dir, f"{backup_dir}/clients", dirs_exist_ok=True)

            # Create backup metadata
            backup_metadata = {
                'timestamp': timestamp,
                'created_at': datetime.utcnow().isoformat(),
                'server_status': self.check_server_status(),
                'client_count': len(self.get_enhanced_client_list()),
                'backup_type': 'full_configuration'
            }

            with open(f"{backup_dir}/backup_metadata.json", 'w') as f:
                json.dump(backup_metadata, f, indent=2)

            # Create compressed archive
            archive_path = f"{backup_dir}.tar.gz"
            import subprocess
            subprocess.run(['tar', '-czf', archive_path, '-C', '/var/backups', f"f2net_openvpn_{timestamp}"],
                           check=True)

            # Remove uncompressed backup
            shutil.rmtree(backup_dir)

            logger.info(f"OpenVPN configuration backed up to: {archive_path}")

            return {
                'success': True,
                'backup_file': archive_path,
                'timestamp': timestamp,
                'size_mb': round(os.path.getsize(archive_path) / (1024 * 1024), 2),
                'metadata': backup_metadata
            }

        except Exception as e:
            logger.error("Failed to backup OpenVPN configuration", error=str(e))
            raise SystemOperationError(f"Backup failed: {e}")

    def get_server_logs(self, lines: int = 100, service_name: str = 'server') -> List[str]:
        """Get OpenVPN server logs using SystemService"""
        try:
            from services.system_service import SystemService
            system_service = SystemService()

            # Get logs from journalctl
            success, stdout, stderr = system_service._run_command([
                'journalctl', '-u', f'openvpn@server', '-n', str(lines), '--no-pager'
            ])

            if success and stdout:
                return stdout.split('\n')
            else:
                # Fallback to log file if available
                log_file = f"{self.config_dir}/openvpn.log"
                if os.path.exists(log_file):
                    with open(log_file, 'r') as f:
                        return f.readlines()[-lines:]

            return []

        except Exception as e:
            logger.error("Failed to get server logs", error=str(e))
            return []
