"""
OpenVPN Manager for ISP Middleware
Handles OpenVPN server management, client certificates, and connections
"""

import os
import subprocess
import structlog
import socket
import re
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from pathlib import Path
import tempfile
import shutil

logger = structlog.get_logger()


class OpenVPNManager:
    """OpenVPN management service"""

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

        logger.info("OpenVPN Manager initialized")

    def _ensure_directories(self):
        """Ensure required directories exist"""
        try:
            Path(self.config_dir).mkdir(parents=True, exist_ok=True)
            Path(self.client_config_dir).mkdir(parents=True, exist_ok=True)
            Path(f"{self.config_dir}/keys").mkdir(parents=True, exist_ok=True)
            Path(f"{self.config_dir}/ccd").mkdir(parents=True, exist_ok=True)  # Client-specific configs
        except Exception as e:
            logger.error("Failed to create OpenVPN directories", error=str(e))

    def check_server_status(self) -> Dict[str, Any]:
        """Check OpenVPN server status"""
        try:
            # Check if OpenVPN service is running
            result = subprocess.run(
                ['systemctl', 'is-active', 'openvpn@server'],
                capture_output=True,
                text=True
            )

            service_running = result.returncode == 0 and result.stdout.strip() == 'active'

            # Check if OpenVPN process is listening
            listening = self._check_port_listening(1194)

            # Get connected clients
            connected_clients = self._get_connected_clients()

            # Get server statistics
            stats = self._get_server_stats()

            return {
                'service_running': service_running,
                'port_listening': listening,
                'connected_clients': len(connected_clients),
                'client_list': connected_clients,
                'stats': stats,
                'timestamp': datetime.utcnow().isoformat()
            }

        except Exception as e:
            logger.error("Failed to check OpenVPN server status", error=str(e))
            return {
                'service_running': False,
                'port_listening': False,
                'connected_clients': 0,
                'client_list': [],
                'error': str(e),
                'timestamp': datetime.utcnow().isoformat()
            }

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
        """Get list of connected VPN clients"""
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

    def generate_client_certificate(self, client_name: str, email: str = None) -> Dict[str, Any]:
        """Generate client certificate and configuration"""
        try:
            # Validate client name
            if not re.match(r'^[a-zA-Z0-9_-]+$', client_name):
                raise ValueError("Client name must contain only alphanumeric characters, hyphens, and underscores")

            # Check if client already exists
            client_cert_path = f"{self.config_dir}/keys/{client_name}.crt"
            if os.path.exists(client_cert_path):
                raise ValueError(f"Client '{client_name}' already exists")

            # Generate client key and certificate using EasyRSA
            self._run_easyrsa_command(['build-client-full', client_name, 'nopass'])

            # Generate client configuration file
            config_content = self._generate_client_config(client_name)

            # Save client configuration
            config_file_path = f"{self.client_config_dir}/{client_name}.ovpn"
            with open(config_file_path, 'w') as f:
                f.write(config_content)

            logger.info(f"Generated client certificate for: {client_name}")

            return {
                'success': True,
                'client_name': client_name,
                'config_file': config_file_path,
                'certificate_file': client_cert_path,
                'key_file': f"{self.config_dir}/keys/{client_name}.key",
                'config_content': config_content,
                'created_at': datetime.utcnow().isoformat()
            }

        except Exception as e:
            logger.error(f"Failed to generate client certificate for {client_name}", error=str(e))
            return {
                'success': False,
                'error': str(e)
            }

    def _run_easyrsa_command(self, command: List[str]) -> str:
        """Run EasyRSA command"""
        try:
            # Change to EasyRSA directory
            easyrsa_dir = f"{self.config_dir}/easy-rsa"

            if not os.path.exists(easyrsa_dir):
                raise FileNotFoundError(f"EasyRSA directory not found: {easyrsa_dir}")

            # Run command
            print("started")
            result = subprocess.run(
                ['./easyrsa'] + command,
                cwd=easyrsa_dir,
                capture_output=True,
                text=True,
                check=True
            )
            print("done with command")

            return result.stdout

        except subprocess.CalledProcessError as e:
            logger.error(f"EasyRSA command failed: {' '.join(command)}", error=e.stderr)
            raise RuntimeError(f"EasyRSA command failed: {e.stderr}")

    def _generate_client_config(self, client_name: str) -> str:
        """Generate OpenVPN client configuration file"""
        try:
            # Read certificate files
            with open(self.ca_cert, 'r') as f:
                ca_content = f.read()

            with open(f"{self.config_dir}/keys/{client_name}.crt", 'r') as f:
                cert_content = f.read()

            with open(f"{self.config_dir}/keys/{client_name}.key", 'r') as f:
                key_content = f.read()

            # Get server public IP (you might want to configure this)
            server_host = self.app.config.get('OPENVPN_SERVER_HOST', 'your-server-ip')
            server_port = self.app.config.get('OPENVPN_SERVER_PORT', 1194)

            # Generate configuration
            config = f"""client
dev tun
proto udp
remote {server_host} {server_port}
resolv-retry infinite
nobind
persist-key
persist-tun
verb 3
cipher AES-256-CBC
auth SHA256

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
            logger.error(f"Failed to generate client config for {client_name}", error=str(e))
            raise

    def revoke_client_certificate(self, client_name: str) -> Dict[str, Any]:
        """Revoke client certificate"""
        try:
            # Revoke certificate using EasyRSA
            self._run_easyrsa_command(['revoke', client_name])

            # Generate new CRL
            self._run_easyrsa_command(['gen-crl'])

            # Remove client files
            files_to_remove = [
                f"{self.config_dir}/keys/{client_name}.crt",
                f"{self.config_dir}/keys/{client_name}.key",
                f"{self.client_config_dir}/{client_name}.ovpn"
            ]

            for file_path in files_to_remove:
                if os.path.exists(file_path):
                    os.remove(file_path)

            # Restart OpenVPN service to reload CRL
            self._restart_openvpn_service()

            logger.info(f"Revoked client certificate: {client_name}")

            return {
                'success': True,
                'client_name': client_name,
                'revoked_at': datetime.utcnow().isoformat()
            }

        except Exception as e:
            logger.error(f"Failed to revoke client certificate for {client_name}", error=str(e))
            return {
                'success': False,
                'error': str(e)
            }

    def disconnect_client(self, client_name: str) -> Dict[str, Any]:
        """Disconnect a specific client"""
        try:
            # Send command to OpenVPN management interface
            # This requires OpenVPN to be configured with management interface
            management_socket = self.app.config.get('OPENVPN_MANAGEMENT_SOCKET', '/var/run/openvpn/server.sock')

            if os.path.exists(management_socket):
                # Connect to management socket and send kill command
                import socket
                sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                sock.connect(management_socket)
                sock.send(f"kill {client_name}\n".encode())
                response = sock.recv(1024).decode()
                sock.close()

                if "SUCCESS" in response:
                    logger.info(f"Disconnected client: {client_name}")
                    return {
                        'success': True,
                        'client_name': client_name,
                        'message': 'Client disconnected successfully'
                    }

            # Fallback: restart service (more disruptive)
            logger.warning(f"Management interface not available, considering service restart")
            return {
                'success': False,
                'error': 'Management interface not available'
            }

        except Exception as e:
            logger.error(f"Failed to disconnect client {client_name}", error=str(e))
            return {
                'success': False,
                'error': str(e)
            }

    def get_client_list(self) -> List[Dict[str, Any]]:
        """Get list of all client certificates"""
        try:
            clients = []
            keys_dir = f"{self.config_dir}/keys"

            if not os.path.exists(keys_dir):
                return clients

            # List all client certificate files
            for file in os.listdir(keys_dir):
                if file.endswith('.crt') and file != 'server.crt' and file != 'ca.crt':
                    client_name = file[:-4]  # Remove .crt extension

                    cert_path = f"{keys_dir}/{file}"
                    key_path = f"{keys_dir}/{client_name}.key"
                    config_path = f"{self.client_config_dir}/{client_name}.ovpn"

                    # Get certificate info
                    cert_info = self._get_certificate_info(cert_path)

                    clients.append({
                        'name': client_name,
                        'certificate_file': cert_path,
                        'key_file': key_path if os.path.exists(key_path) else None,
                        'config_file': config_path if os.path.exists(config_path) else None,
                        'created_at': cert_info.get('not_before'),
                        'expires_at': cert_info.get('not_after'),
                        'is_valid': cert_info.get('is_valid', False),
                        'serial_number': cert_info.get('serial_number'),
                        'is_connected': self._is_client_connected(client_name)
                    })

            return sorted(clients, key=lambda x: x['name'])

        except Exception as e:
            logger.error("Failed to get client list", error=str(e))
            return []

    def _get_certificate_info(self, cert_path: str) -> Dict[str, Any]:
        """Get certificate information using openssl"""
        try:
            # Get certificate details
            result = subprocess.run(
                ['openssl', 'x509', '-in', cert_path, '-text', '-noout'],
                capture_output=True,
                text=True
            )

            if result.returncode != 0:
                return {}

            cert_text = result.stdout

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
                    # Parse the date and check if it's in the future
                    # OpenSSL date format: "MMM DD HH:MM:SS YYYY GMT"
                    from datetime import datetime
                    expire_date = datetime.strptime(info['not_after'], '%b %d %H:%M:%S %Y %Z')
                    info['is_valid'] = expire_date > datetime.utcnow()
                except:
                    info['is_valid'] = False

            return info

        except Exception as e:
            logger.error(f"Failed to get certificate info for {cert_path}", error=str(e))
            return {}

    def _is_client_connected(self, client_name: str) -> bool:
        """Check if client is currently connected"""
        try:
            connected_clients = self._get_connected_clients()
            return any(client['common_name'] == client_name for client in connected_clients)
        except Exception:
            return False

    def _restart_openvpn_service(self):
        """Restart OpenVPN service"""
        try:
            subprocess.run(['systemctl', 'restart', 'openvpn@server'], check=True)
            logger.info("OpenVPN service restarted")
        except subprocess.CalledProcessError as e:
            logger.error("Failed to restart OpenVPN service", error=str(e))
            raise

    def backup_configuration(self) -> Dict[str, Any]:
        """Create backup of OpenVPN configuration"""
        try:
            timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
            backup_dir = f"/var/backups/openvpn_{timestamp}"

            # Create backup directory
            os.makedirs(backup_dir, exist_ok=True)

            # Copy configuration files
            shutil.copytree(self.config_dir, f"{backup_dir}/config", dirs_exist_ok=True)
            shutil.copytree(self.client_config_dir, f"{backup_dir}/clients", dirs_exist_ok=True)

            # Create compressed archive
            archive_path = f"{backup_dir}.tar.gz"
            subprocess.run(['tar', '-czf', archive_path, '-C', '/var/backups', f"openvpn_{timestamp}"], check=True)

            # Remove uncompressed backup
            shutil.rmtree(backup_dir)

            logger.info(f"OpenVPN configuration backed up to: {archive_path}")

            return {
                'success': True,
                'backup_file': archive_path,
                'timestamp': timestamp,
                'size_mb': round(os.path.getsize(archive_path) / (1024 * 1024), 2)
            }

        except Exception as e:
            logger.error("Failed to backup OpenVPN configuration", error=str(e))
            return {
                'success': False,
                'error': str(e)
            }

    def get_server_logs(self, lines: int = 100) -> List[str]:
        """Get OpenVPN server logs"""
        try:
            # Get logs from journalctl
            result = subprocess.run(
                ['journalctl', '-u', 'openvpn@server', '-n', str(lines), '--no-pager'],
                capture_output=True,
                text=True
            )

            if result.returncode == 0:
                return result.stdout.split('\n')
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