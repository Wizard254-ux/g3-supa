# monitoring/health_checker.py
import psutil
import subprocess
from typing import Dict
from services.system_service import SystemServiceFactory


class HealthChecker:
    """System health monitoring"""

    @staticmethod
    def check_system_resources() -> Dict:
        """Check system resource usage"""
        return {
            'cpu_percent': psutil.cpu_percent(interval=1),
            'memory_percent': psutil.virtual_memory().percent,
            'disk_usage': psutil.disk_usage('/').percent,
            'load_average': psutil.getloadavg()
        }

    @staticmethod
    def check_services_status() -> Dict:
        """Check status of critical services"""
        services = ['postgresql', 'redis-server', 'nginx', 'openvpn', 'freeradius']
        status = {}

        for service in services:
            try:
                result = subprocess.run(
                    ['systemctl', 'is-active', service],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                status[service] = result.stdout.strip() == 'active'
            except:
                status[service] = False

        return status

    @staticmethod
    def check_vpn_connections() -> Dict:
        """Check VPN connection status"""
        try:
            # Check OpenVPN status files
            active_connections = 0
            # Implementation depends on your OpenVPN setup

            return {
                'active_connections': active_connections,
                'healthy': True
            }
        except Exception as e:
            return {
                'active_connections': 0,
                'healthy': False,
                'error': str(e)
            }