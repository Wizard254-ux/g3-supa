# services/system_service.py
import subprocess
import logging
import os
import tempfile
import json
from typing import Dict, List, Optional, Tuple
from pathlib import Path
import re

logger = logging.getLogger(__name__)


class SystemOperationError(Exception):
    """Custom exception for system operation failures"""
    pass


class SystemService:
    """
    Secure service for executing system operations using sudoers permissions
    This service provides a safe interface to system commands without direct sudo access
    """

    def __init__(self):
        self.scripts_dir = Path("/opt/f2net_isp/scripts")
        self.allowed_commands = {
            'systemctl': [
                'start', 'stop', 'restart', 'status', 'reload'
            ],
            'openvpn_services': [
                'openvpn@', 'freeradius'
            ]
        }

    def _validate_input(self, value: str, pattern: str) -> bool:
        """Validate input against allowed patterns"""
        return bool(re.match(pattern, value))

    def _run_command(self, command: List[str], capture_output: bool = True) -> Tuple[bool, str, str]:
        """
        Safely execute a system command
        Returns: (success, stdout, stderr)
        """
        try:
            logger.info(f"Executing command: {' '.join(command)}")

            result = subprocess.run(
                command,
                capture_output=capture_output,
                text=True,
                timeout=30,  # 30 second timeout
                check=False
            )

            success = result.returncode == 0
            stdout = result.stdout if result.stdout else ""
            stderr = result.stderr if result.stderr else ""

            if success:
                logger.info(f"Command succeeded: {' '.join(command)}")
            else:
                logger.error(f"Command failed with code {result.returncode}: {stderr}")

            return success, stdout, stderr

        except subprocess.TimeoutExpired:
            logger.error(f"Command timed out: {' '.join(command)}")
            return False, "", "Command timed out"
        except Exception as e:
            logger.error(f"Command execution failed: {e}")
            return False, "", str(e)


class OpenVPNService(SystemService):
    """Service for managing OpenVPN operations"""

    def deploy_config(self, config_name: str, config_content: str) -> Dict:
        """Deploy OpenVPN configuration"""
        # Validate config name
        if not self._validate_input(config_name, r'^f2net_[a-zA-Z0-9_-]+$'):
            raise SystemOperationError("Invalid config name format")

        try:
            # Write config to temporary file
            with tempfile.NamedTemporaryFile(
                    mode='w',
                    suffix='.conf',
                    prefix=f'{config_name}_',
                    dir='/tmp',
                    delete=False
            ) as tmp_file:
                tmp_file.write(config_content)
                tmp_path = tmp_file.name

            # Use management script to deploy
            success, stdout, stderr = self._run_command([
                '/usr/bin/sudo',
                str(self.scripts_dir / 'manage_openvpn.sh'),
                'deploy_config',
                config_name
            ])

            # Clean up temp file
            os.unlink(tmp_path)

            if not success:
                raise SystemOperationError(f"Failed to deploy config: {stderr}")

            return {
                'success': True,
                'message': f'Config {config_name} deployed successfully',
                'output': stdout
            }

        except Exception as e:
            logger.error(f"Config deployment failed: {e}")
            raise SystemOperationError(f"Config deployment failed: {e}")

    def remove_config(self, config_name: str) -> Dict:
        """Remove OpenVPN configuration"""
        if not self._validate_input(config_name, r'^f2net_[a-zA-Z0-9_-]+$'):
            raise SystemOperationError("Invalid config name format")

        success, stdout, stderr = self._run_command([
            '/usr/bin/sudo',
            str(self.scripts_dir / 'manage_openvpn.sh'),
            'remove_config',
            config_name
        ])

        if not success:
            raise SystemOperationError(f"Failed to remove config: {stderr}")

        return {
            'success': True,
            'message': f'Config {config_name} removed successfully',
            'output': stdout
        }

    def start_service(self, config_name: str) -> Dict:
        """Start OpenVPN service"""
        if not self._validate_input(config_name, r'^f2net_[a-zA-Z0-9_-]+$'):
            raise SystemOperationError("Invalid config name format")

        success, stdout, stderr = self._run_command([
            '/usr/bin/sudo', '/usr/bin/systemctl', 'start', f'openvpn@server'
        ])

        if not success:
            raise SystemOperationError(f"Failed to start service: {stderr}")

        return {
            'success': True,
            'message': f'OpenVPN service {config_name} started',
            'output': stdout
        }
    def restart_service(self, config_name: str) -> Dict:
        """Start OpenVPN service"""
        if not self._validate_input(config_name, r'^f2net_[a-zA-Z0-9_-]+$'):
            raise SystemOperationError("Invalid config name format")

        success, stdout, stderr = self._run_command([
            '/usr/bin/sudo', '/usr/bin/systemctl', 'restart', f'openvpn@server'
        ])

        if not success:
            raise SystemOperationError(f"Failed to start service: {stderr}")

        return {
            'success': True,
            'message': f'OpenVPN service {config_name} restarted',
            'output': stdout
        }

    def stop_service(self, config_name: str) -> Dict:
        """Stop OpenVPN service"""
        if not self._validate_input(config_name, r'^f2net_[a-zA-Z0-9_-]+$'):
            raise SystemOperationError("Invalid config name format")

        success, stdout, stderr = self._run_command([
            '/usr/bin/sudo', '/usr/bin/systemctl', 'stop', f'openvpn@server'
        ])

        if not success:
            raise SystemOperationError(f"Failed to stop service: {stderr}")

        return {
            'success': True,
            'message': f'OpenVPN service {config_name} stopped',
            'output': stdout
        }

    def get_service_status(self, config_name: str) -> Dict:
        """Get OpenVPN service status"""
        if not self._validate_input(config_name, r'^f2net_[a-zA-Z0-9_-]+$'):
            raise SystemOperationError("Invalid config name format")

        success, stdout, stderr = self._run_command([
            '/usr/bin/sudo', '/usr/bin/systemctl', 'status', f'openvpn@server'
        ])

        # Status command returns non-zero for inactive services, so we parse output
        is_active = 'Active: active (running)' in stdout

        return {
            'success': True,
            'active': is_active,
            'status': stdout,
            'config_name': config_name
        }


class CertificateService(SystemService):
    """Service for managing certificates"""

    def read_certificate(self, cert_name: str) -> str:
        """Read certificate content securely"""
        if not self._validate_input(cert_name, r'^f2net_[a-zA-Z0-9_-]+$'):
            raise SystemOperationError("Invalid certificate name format")

        cert_path = f"/etc/openvpn/server/easy-rsa/pki/issued/{cert_name}.crt"

        success, stdout, stderr = self._run_command([
            '/usr/bin/sudo', '/usr/bin/cat', cert_path
        ])

        if not success:
            raise SystemOperationError(f"Failed to read certificate {cert_name}: {stderr}")

        return stdout

    def generate_client_cert(self, cert_name: str) -> Dict:
        """Generate client certificate"""
        if not self._validate_input(cert_name, r'^f2net_[a-zA-Z0-9_-]+$'):
            raise SystemOperationError("Invalid certificate name format")
        success, stdout, stderr = self._run_command([
            '/usr/bin/sudo',
            str(self.scripts_dir / 'manage_certificates.sh'),
            'generate_client',
            cert_name
        ])
        # If failed due to existing request file, handle it
        if not success and "Request file already exists" in stderr:
            # Extract the file path from the error message
            req_file_path = self._extract_request_file_path(stderr)

            if req_file_path:
                print(f"Found existing request file: {req_file_path}")
                print("Removing existing request file and retrying...")

                # Remove the existing request file
                cleanup_success, _, cleanup_stderr = self._run_command([
                    '/usr/bin/sudo', '/usr/bin/rm', '-f', req_file_path
                ])

                if cleanup_success:
                    # Retry the certificate generation
                    success, stdout, stderr = self._run_command([
                        '/usr/bin/sudo',
                        str(self.scripts_dir / 'manage_certificates.sh'),
                        'generate_client',
                        cert_name
                    ])

                    if success:
                        return {
                            'success': True,
                            'message': f'Client certificate {cert_name} generated (existing request removed)',
                            'output': stdout
                        }
                else:
                    raise SystemOperationError(f"Failed to remove existing request file: {cleanup_stderr}")

        if not success:
            raise SystemOperationError(f"Failed to generate certificate: {stderr}")

        return {
            'success': True,
            'message': f'Client certificate {cert_name} generated',
            'output': stdout
        }

    def _extract_request_file_path(self, stderr: str):
        """Extract the request file path from Easy-RSA error message"""
        # Look for the pattern: "Matching file found at: /path/to/file.req"
        pattern = r'Matching file found at:\s*(.+\.req)'
        match = re.search(pattern, stderr)
        return match.group(1).strip() if match else None


    # Alternative: Reuse existing request instead of removing it
    def generate_client_cert_reuse_request(self, cert_name: str) -> Dict:
        """Generate client certificate, reusing existing request if available"""
        if not self._validate_input(cert_name, r'^f2net_[a-zA-Z0-9_-]+'):
            raise SystemOperationError("Invalid certificate name format")

        success, stdout, stderr = self._run_command([
            '/usr/bin/sudo',
            str(self.scripts_dir / 'manage_certificates.sh'),
            'generate_client',
            cert_name
        ])

        # If request file exists, try to sign it instead
        if not success and "Request file already exists" in stderr:
            print(f"Request file exists for {cert_name}, attempting to sign existing request...")

            # Use sign-req command instead of build-client-full
            success, stdout, stderr = self._run_command([
                '/usr/bin/sudo',
                str(self.scripts_dir / 'manage_certificates.sh'),
                "sign_client",
                cert_name
            ])

            if success:
                return {
                    'success': True,
                    'message': f'Client certificate {cert_name} generated from existing request',
                    'output': stdout
                }

        if not success:
            raise SystemOperationError(f"Failed to generate certificate: {stderr}")

        return {
            'success': True,
            'message': f'Client certificate {cert_name} generated',
            'output': stdout
        }

    def revoke_client_cert(self, cert_name: str) -> Dict:
        """Revoke client certificate"""
        if not self._validate_input(cert_name, r'^f2net_[a-zA-Z0-9_-]+$'):
            raise SystemOperationError("Invalid certificate name format")

        success, stdout, stderr = self._run_command([
            '/usr/bin/sudo',
            str(self.scripts_dir / 'manage_certificates.sh'),
            'revoke_client',
            cert_name
        ])

        if not success:
            raise SystemOperationError(f"Failed to revoke certificate: {stderr}")

        return {
            'success': True,
            'message': f'Client certificate {cert_name} revoked',
            'output': stdout
        }


class NetworkService(SystemService):
    """Service for network operations"""

    def add_iptables_rule(self, rule_params: List[str]) -> Dict:
        """Add iptables rule with validation"""
        # Validate rule parameters
        allowed_params = ['-A', '-I', '-D', '-s', '-d', '-p', '-j', '--dport', '--sport']

        for param in rule_params:
            if param.startswith('-') and param not in allowed_params:
                raise SystemOperationError(f"Parameter not allowed: {param}")

        command = ['/usr/bin/sudo', '/usr/sbin/iptables'] + rule_params
        success, stdout, stderr = self._run_command(command)

        if not success:
            raise SystemOperationError(f"Failed to add iptables rule: {stderr}")

        return {
            'success': True,
            'message': 'Iptables rule added successfully',
            'rule': ' '.join(rule_params)
        }

    def add_route(self, destination: str, gateway: str, interface: str = None) -> Dict:
        """Add network route"""
        # Validate IP addresses/CIDR
        if not self._validate_input(destination, r'^(\d{1,3}\.){3}\d{1,3}(/\d{1,2})?$'):
            raise SystemOperationError("Invalid destination format")

        if not self._validate_input(gateway, r'^(\d{1,3}\.){3}\d{1,3}$'):
            raise SystemOperationError("Invalid gateway format")

        command = ['/usr/bin/sudo', '/usr/sbin/ip', 'route', 'add', destination, 'via', gateway]
        if interface:
            if not self._validate_input(interface, r'^[a-zA-Z0-9]+$'):
                raise SystemOperationError("Invalid interface name")
            command.extend(['dev', interface])

        success, stdout, stderr = self._run_command(command)

        if not success:
            raise SystemOperationError(f"Failed to add route: {stderr}")

        return {
            'success': True,
            'message': f'Route added: {destination} via {gateway}',
            'destination': destination,
            'gateway': gateway
        }


class FreeRADIUSService(SystemService):
    """Service for FreeRADIUS operations"""

    def start_service(self) -> Dict:
        """Start FreeRADIUS service"""
        success, stdout, stderr = self._run_command([
            '/usr/bin/sudo', '/usr/bin/systemctl', 'start', 'freeradius'
        ])

        if not success:
            raise SystemOperationError(f"Failed to start FreeRADIUS: {stderr}")

        return {
            'success': True,
            'message': 'FreeRADIUS service started',
            'output': stdout
        }

    def stop_service(self) -> Dict:
        """Stop FreeRADIUS service"""
        success, stdout, stderr = self._run_command([
            '/usr/bin/sudo', '/usr/bin/systemctl', 'stop', 'freeradius'
        ])

        if not success:
            raise SystemOperationError(f"Failed to stop FreeRADIUS: {stderr}")

        return {
            'success': True,
            'message': 'FreeRADIUS service stopped',
            'output': stdout
        }

    def restart_service(self) -> Dict:
        """Restart FreeRADIUS service"""
        success, stdout, stderr = self._run_command([
            '/usr/bin/sudo', '/usr/bin/systemctl', 'restart', 'freeradius'
        ])

        if not success:
            raise SystemOperationError(f"Failed to restart FreeRADIUS: {stderr}")

        return {
            'success': True,
            'message': 'FreeRADIUS service restarted',
            'output': stdout
        }


# Factory class for getting service instances
class SystemServiceFactory:
    """Factory for creating system service instances"""

    @staticmethod
    def get_openvpn_service() -> OpenVPNService:
        return OpenVPNService()

    @staticmethod
    def get_certificate_service() -> CertificateService:
        return CertificateService()

    @staticmethod
    def get_network_service() -> NetworkService:
        return NetworkService()

    @staticmethod
    def get_radius_service() -> FreeRADIUSService:
        return FreeRADIUSService()
