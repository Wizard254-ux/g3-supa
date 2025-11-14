# =============================================================================
# Health Check Script (scripts/health_check.py)
# =============================================================================

# !/usr/bin/env python3
"""
ISP Middleware Health Check Script
Comprehensive health monitoring for all system components
"""

import requests
import psycopg2
import redis
import subprocess
import sys
import json
import time
from datetime import datetime
from typing import Dict, List, Any


class HealthChecker:
    def __init__(self):
        self.results = {}
        self.overall_healthy = True

    def check_flask_app(self) -> Dict[str, Any]:
        """Check Flask application health"""
        try:
            response = requests.get('http://localhost:5000/health', timeout=10)
            if response.status_code == 200:
                data = response.json()
                return {
                    'status': 'healthy',
                    'response_time': response.elapsed.total_seconds(),
                    'details': data
                }
            else:
                return {
                    'status': 'unhealthy',
                    'error': f'HTTP {response.status_code}'
                }
        except Exception as e:
            return {
                'status': 'unhealthy',
                'error': str(e)
            }

    def check_database(self) -> Dict[str, Any]:
        """Check PostgreSQL database"""
        try:
            conn = psycopg2.connect(
                host='localhost',
                database='isp_middleware',
                user='isp_user',
                password='isp_password'
            )
            cursor = conn.cursor()
            cursor.execute('SELECT 1;')
            result = cursor.fetchone()
            conn.close()

            return {
                'status': 'healthy',
                'details': 'Database connection successful'
            }
        except Exception as e:
            return {
                'status': 'unhealthy',
                'error': str(e)
            }

    def check_redis(self) -> Dict[str, Any]:
        """Check Redis connection"""
        try:
            r = redis.Redis(host='localhost', port=6379, db=0)
            r.ping()
            info = r.info()

            return {
                'status': 'healthy',
                'details': {
                    'connected_clients': info.get('connected_clients', 0),
                    'used_memory_human': info.get('used_memory_human', '0B')
                }
            }
        except Exception as e:
            return {
                'status': 'unhealthy',
                'error': str(e)
            }

    def check_services(self) -> Dict[str, Any]:
        """Check systemd services"""
        services = [
            'isp-middleware',
            'isp-middleware-celery',
            'nginx',
            'postgresql',
            'redis'
        ]

        service_status = {}
        for service in services:
            try:
                result = subprocess.run(
                    ['systemctl', 'is-active', service],
                    capture_output=True,
                    text=True
                )
                service_status[service] = {
                    'status': 'healthy' if result.returncode == 0 else 'unhealthy',
                    'state': result.stdout.strip()
                }
            except Exception as e:
                service_status[service] = {
                    'status': 'unhealthy',
                    'error': str(e)
                }

        return service_status

    def check_disk_space(self) -> Dict[str, Any]:
        """Check disk space"""
        try:
            result = subprocess.run(['df', '-h'], capture_output=True, text=True)
            lines = result.stdout.strip().split('\n')[1:]  # Skip header

            disk_info = []
            for line in lines:
                parts = line.split()
                if len(parts) >= 6:
                    usage_percent = int(parts[4].rstrip('%'))
                    disk_info.append({
                        'filesystem': parts[0],
                        'size': parts[1],
                        'used': parts[2],
                        'available': parts[3],
                        'usage_percent': usage_percent,
                        'mount_point': parts[5],
                        'status': 'warning' if usage_percent > 80 else 'healthy'
                    })

            return {
                'status': 'healthy',
                'disks': disk_info
            }
        except Exception as e:
            return {
                'status': 'unhealthy',
                'error': str(e)
            }

    def check_network(self) -> Dict[str, Any]:
        """Check network connectivity"""
        try:
            # Test internet connectivity
            response = requests.get('https://8.8.8.8', timeout=5)
            internet_ok = True
        except:
            internet_ok = False

        # Test DNS resolution
        try:
            response = requests.get('https://google.com', timeout=5)
            dns_ok = True
        except:
            dns_ok = False

        return {
            'status': 'healthy' if internet_ok and dns_ok else 'warning',
            'internet_connectivity': internet_ok,
            'dns_resolution': dns_ok
        }

    def run_all_checks(self) -> Dict[str, Any]:
        """Run all health checks"""
        print("Running ISP Middleware health checks...")

        checks = {
            'flask_app': self.check_flask_app,
            'database': self.check_database,
            'redis': self.check_redis,
            'services': self.check_services,
            'disk_space': self.check_disk_space,
            'network': self.check_network
        }

        results = {}
        for check_name, check_func in checks.items():
            print(f"Checking {check_name}...")
            try:
                results[check_name] = check_func()

                # Determine if this check passed
                if isinstance(results[check_name], dict):
                    if results[check_name].get('status') not in ['healthy', 'warning']:
                        self.overall_healthy = False
                else:
                    # For services check, check individual services
                    for service, status in results[check_name].items():
                        if status.get('status') != 'healthy':
                            self.overall_healthy = False

            except Exception as e:
                results[check_name] = {
                    'status': 'error',
                    'error': str(e)
                }
                self.overall_healthy = False

        # Overall summary
        results['summary'] = {
            'overall_status': 'healthy' if self.overall_healthy else 'unhealthy',
            'timestamp': datetime.utcnow().isoformat(),
            'checks_passed': sum(1 for r in results.values() if isinstance(r, dict) and r.get('status') == 'healthy'),
            'total_checks': len(checks)
        }

        return results


def main():
    checker = HealthChecker()
    results = checker.run_all_checks()

    # Print results
    print(json.dumps(results, indent=2))

    # Exit with appropriate code
    sys.exit(0 if checker.overall_healthy else 1)


if __name__ == '__main__':
    main()