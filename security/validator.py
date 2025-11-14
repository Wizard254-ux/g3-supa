import ipaddress
import re
from typing import Dict, Any


class SecurityValidator:
    """Security validator for system operation parameters"""

    @staticmethod
    def validate_config_name(name: str) -> bool:
        """Validate configuration name"""
        if not name or len(name) > 50:
            return False
        return bool(re.match(r'^f2net_[a-zA-Z0-9_-]+$', name))

    @staticmethod
    def validate_ip_address(ip: str) -> bool:
        """Validate IP address"""
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False

    @staticmethod
    def validate_cidr(cidr: str) -> bool:
        """Validate CIDR notation"""
        try:
            ipaddress.ip_network(cidr, strict=False)
            return True
        except ValueError:
            return False

    @staticmethod
    def validate_port(port: str) -> bool:
        """Validate port number"""
        try:
            port_num = int(port)
            return 1 <= port_num <= 65535
        except ValueError:
            return False

    @staticmethod
    def sanitize_config_content(content: str) -> str:
        """Sanitize OpenVPN config content"""
        # Remove potentially dangerous directives
        dangerous_directives = [
            'script-security',
            'up', 'down',
            'route-up', 'route-pre-down',
            'client-connect', 'client-disconnect',
            'learn-address',
            'auth-user-pass-verify',
            'tls-verify'
        ]

        lines = content.split('\n')
        safe_lines = []

        for line in lines:
            line = line.strip()
            if not line or line.startswith('#'):
                safe_lines.append(line)
                continue

            # Check for dangerous directives
            directive = line.split()[0] if line.split() else ''
            if directive.lower() not in [d.lower() for d in dangerous_directives]:
                safe_lines.append(line)

        return '\n'.join(safe_lines)

