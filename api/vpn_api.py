"""
VPN API Blueprint for ISP Middleware
Provides endpoints for OpenVPN management and client operations
"""
import traceback

from flask import Blueprint, request, jsonify, current_app, g, send_file
import structlog
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
import tempfile
import os

from openvpn_manager import OpenVPNManager
from utils.decorators import (
    api_endpoint, require_api_key, log_api_call,
    validate_json, handle_exceptions, monitor_performance
)

logger = structlog.get_logger()

# Create blueprint
vpn_bp = Blueprint('vpn', __name__)


@vpn_bp.route('/status', methods=['GET'])
@api_endpoint(require_auth=True, require_json=False, cache_timeout=30)
def get_server_status():
    """
    Get OpenVPN server status
    """
    try:
        vpn_manager = OpenVPNManager(current_app)

        # Get server status
        status = vpn_manager.check_server_status()

        return jsonify({
            'success': True,
            'server_status': status,
            'timestamp': datetime.utcnow().isoformat()
        }), 200

    except Exception as e:
        logger.error("Error getting VPN server status", error=str(e))
        return jsonify({
            'success': False,
            'error': 'Internal server error'
        }), 500


@vpn_bp.route('/clients', methods=['GET'])
@api_endpoint(require_auth=True, require_json=False, cache_timeout=60)
def get_clients():
    """
    Get list of all VPN clients
    """
    try:
        vpn_manager = OpenVPNManager(current_app)

        # Get client list
        clients = vpn_manager.get_client_list()

        # Separate connected and disconnected clients
        connected_clients = [c for c in clients if c['is_connected']]
        disconnected_clients = [c for c in clients if not c['is_connected']]

        # Calculate statistics
        stats = {
            'total_clients': len(clients),
            'connected_clients': len(connected_clients),
            'disconnected_clients': len(disconnected_clients),
            'valid_certificates': len([c for c in clients if c['is_valid']]),
            'expired_certificates': len([c for c in clients if not c['is_valid']])
        }

        return jsonify({
            'success': True,
            'clients': clients,
            'connected_clients': connected_clients,
            'statistics': stats,
            'timestamp': datetime.utcnow().isoformat()
        }), 200

    except Exception as e:
        logger.error("Error getting VPN clients", error=str(e))
        return jsonify({
            'success': False,
            'error': 'Internal server error'
        })


@vpn_bp.route('/clients/connected', methods=['GET'])
@api_endpoint(require_auth=True, require_json=False, cache_timeout=10)
def get_connected_clients():
    """
    Get list of currently connected VPN clients
    """
    try:
        vpn_manager = OpenVPNManager(current_app)

        # Get server status (includes connected clients)
        status = vpn_manager.check_server_status()

        connected_clients = status.get('client_list', [])

        # Calculate bandwidth totals
        total_bytes_received = sum(c.get('bytes_received', 0) for c in connected_clients)
        total_bytes_sent = sum(c.get('bytes_sent', 0) for c in connected_clients)

        return jsonify({
            'success': True,
            'connected_clients': connected_clients,
            'total_connected': len(connected_clients),
            'bandwidth_summary': {
                'total_bytes_received': total_bytes_received,
                'total_bytes_sent': total_bytes_sent,
                'total_bytes': total_bytes_received + total_bytes_sent,
                'total_mb_received': round(total_bytes_received / (1024 * 1024), 2),
                'total_mb_sent': round(total_bytes_sent / (1024 * 1024), 2),
                'total_mb': round((total_bytes_received + total_bytes_sent) / (1024 * 1024), 2)
            },
            'timestamp': datetime.utcnow().isoformat()
        }), 200

    except Exception as e:
        logger.error("Error getting connected VPN clients", error=str(e))
        return jsonify({
            'success': False,
            'error': 'Internal server error'
        }), 500


@vpn_bp.route('/clients/create', methods=['POST'])
@api_endpoint(
    require_auth=True,
    require_json=True,
    required_fields=['client_name'],
    rate_limit=10  # Limit certificate generation
)
def create_client():
    """
    Create new VPN client certificate
    """
    try:
        data = g.validated_data
        client_name = data['client_name'].strip()
        email = data.get('email', '').strip()

        # Validate client name
        if not client_name:
            return jsonify({
                'success': False,
                'error': 'Client name cannot be empty'
            }), 400
        print("dd", client_name)
        if len(client_name) > 64:
            return jsonify({
                'success': False,
                'error': 'Client name must be 64 characters or less'
            }), 400

        vpn_manager = OpenVPNManager(current_app)
        # Generate client certificate
        result = vpn_manager.generate_client_certificate(client_name, email)

        if result['success']:
            logger.info(f"Created VPN client certificate: {client_name}")

            # Don't include the full config content in response for security
            response_data = {
                'success': True,
                'client_name': client_name,
                'certificate_created': True,
                'config_file_available': True,
                'created_at': result.get('created_at'),
                'message': f'VPN client "{client_name}" created successfully'
            }

            return jsonify(response_data), 201
        else:
            logger.error(f"Failed to create VPN client certificate: {client_name}", error=result.get('error'))
            return jsonify({
                'success': False,
                'error': result.get('error', 'Failed to create client certificate')
            }), 500

    except Exception as e:
        # traceback.print_exc()
        logger.error("Error creating VPN client", error=e or "Unknown error")
        return jsonify({
            'success': False,
            'error': 'Internal server error 56'
        })


@vpn_bp.route('/clients/<client_name>/config', methods=['GET'])
@api_endpoint(require_auth=True, require_json=False)
def download_client_config(client_name):
    """
    Download client configuration file
    """
    try:
        vpn_manager = OpenVPNManager(current_app)

        # Check if client exists
        clients = vpn_manager.get_client_list()
        client = next((c for c in clients if c['name'] == client_name), None)

        if not client:
            return jsonify({
                'success': False,
                'error': f'Client "{client_name}" not found'
            }), 404

        config_file = client.get('config_file')

        if not config_file or not os.path.exists(config_file):
            return jsonify({
                'success': False,
                'error': f'Configuration file not found for client "{client_name}"'
            }), 404

        logger.info(f"Downloaded VPN config for client: {client_name}")

        # Send file as download
        return send_file(
            config_file,
            as_attachment=True,
            download_name=f"{client_name}.ovpn",
            mimetype='application/x-openvpn-profile'
        )

    except Exception as e:
        logger.error(f"Error downloading config for client {client_name}", error=str(e))
        return jsonify({
            'success': False,
            'error': 'Internal server error'
        }), 500


@vpn_bp.route('/clients/<client_name>/revoke', methods=['POST'])
@api_endpoint(require_auth=True, require_json=False, rate_limit=20)
def revoke_client(client_name):
    """
    Revoke client certificate
    """
    try:
        vpn_manager = OpenVPNManager(current_app)

        # Check if client exists
        clients = vpn_manager.get_client_list()
        client = next((c for c in clients if c['name'] == client_name), None)

        if not client:
            return jsonify({
                'success': False,
                'error': f'Client "{client_name}" not found'
            }), 404

        # Revoke certificate
        result = vpn_manager.revoke_client_certificate(client_name)

        if result['success']:
            logger.info(f"Revoked VPN client certificate: {client_name}")

            return jsonify({
                'success': True,
                'client_name': client_name,
                'revoked_at': result['revoked_at'],
                'message': f'Client "{client_name}" certificate revoked successfully'
            }), 200
        else:
            logger.error(f"Failed to revoke VPN client certificate: {client_name}", error=result.get('error'))

            return jsonify({
                'success': False,
                'error': result.get('error', 'Failed to revoke client certificate')
            }), 500

    except Exception as e:
        logger.error(f"Error revoking client {client_name}", error=str(e))
        return jsonify({
            'success': False,
            'error': 'Internal server error'
        }), 500


@vpn_bp.route('/clients/<client_name>/disconnect', methods=['POST'])
@api_endpoint(require_auth=True, require_json=False, rate_limit=30)
def disconnect_client(client_name):
    """
    Disconnect specific VPN client
    """
    try:
        vpn_manager = OpenVPNManager(current_app)

        # Check if client is connected
        status = vpn_manager.check_server_status()
        connected_clients = status.get('client_list', [])

        client_connected = any(c['common_name'] == client_name for c in connected_clients)

        if not client_connected:
            return jsonify({
                'success': False,
                'error': f'Client "{client_name}" is not currently connected'
            }), 404

        # Disconnect client
        result = vpn_manager.disconnect_client(client_name)

        if result['success']:
            logger.info(f"Disconnected VPN client: {client_name}")

            return jsonify({
                'success': True,
                'client_name': client_name,
                'message': result['message'],
                'disconnected_at': datetime.utcnow().isoformat()
            }), 200
        else:
            logger.error(f"Failed to disconnect VPN client: {client_name}", error=result.get('error'))

            return jsonify({
                'success': False,
                'error': result.get('error', 'Failed to disconnect client')
            }), 500

    except Exception as e:
        logger.error(f"Error disconnecting client {client_name}", error=str(e))
        return jsonify({
            'success': False,
            'error': 'Internal server error'
        }), 500


@vpn_bp.route('/server/logs', methods=['GET'])
@api_endpoint(require_auth=True, require_json=False, cache_timeout=10)
def get_server_logs():
    """
    Get OpenVPN server logs
    """
    try:
        lines = min(int(request.args.get('lines', 100)), 1000)  # Max 1000 lines

        vpn_manager = OpenVPNManager(current_app)

        # Get server logs
        logs = vpn_manager.get_server_logs(lines)

        return jsonify({
            'success': True,
            'logs': logs,
            'total_lines': len(logs),
            'requested_lines': lines,
            'timestamp': datetime.utcnow().isoformat()
        }), 200

    except Exception as e:
        logger.error("Error getting VPN server logs", error=str(e))
        return jsonify({
            'success': False,
            'error': 'Internal server error'
        }), 500


@vpn_bp.route('/server/backup', methods=['POST'])
@api_endpoint(require_auth=True, require_json=False, rate_limit=2)
def backup_configuration():
    """
    Create backup of VPN configuration
    """
    try:
        vpn_manager = OpenVPNManager(current_app)

        # Create backup
        result = vpn_manager.backup_configuration()

        if result['success']:
            logger.info("Created VPN configuration backup")

            return jsonify({
                'success': True,
                'backup_file': result['backup_file'],
                'timestamp': result['timestamp'],
                'size_mb': result['size_mb'],
                'message': 'VPN configuration backup created successfully'
            }), 200
        else:
            logger.error("Failed to create VPN configuration backup", error=result.get('error'))

            return jsonify({
                'success': False,
                'error': result.get('error', 'Failed to create backup')
            }), 500

    except Exception as e:
        logger.error("Error creating VPN backup", error=str(e))
        return jsonify({
            'success': False,
            'error': 'Internal server error'
        }), 500


@vpn_bp.route('/server/config', methods=['GET'])
@api_endpoint(require_auth=True, require_json=False, rate_limit=2)
def get_configuration():
    """
    Create backup of VPN configuration
    """
    try:
        vpn_manager = OpenVPNManager(current_app)

        # Create backup
        result = vpn_manager.parse_openvpn_config()

        if result['success']:
            return jsonify({
                'success': True,
                'config': result['config'],
            }), 200
        else:
            logger.error("Failed to get VPN configuration", error=result.get('error'))

            return jsonify({
                'success': False,
                'error': result.get('error', 'Failed to get config')
            }), 500

    except Exception as e:
        logger.error("Error creating VPN backup", error=str(e))
        return jsonify({
            'success': False,
            'error': 'Internal server error'
        }), 500


@vpn_bp.route('/server/ip', methods=['GET'])
@api_endpoint(require_auth=True, require_json=False, rate_limit=20)
def remore_ip():
    """
    Create backup of VPN configuration
    """
    try:
        vpn_manager = OpenVPNManager(current_app)

        # Create backup
        result = vpn_manager.parse_client_template()

        if result['success']:
            return jsonify({
                'success': True,
                'ip': result['config'].get("remote").split(None, 1)[0],
            }), 200
        else:
            logger.error("Failed to get VPN configuration", error=result.get('error'))

            return jsonify({
                'success': False,
                'error': result.get('error', 'Failed to get config')
            }), 500

    except Exception as e:
        logger.error("Error creating VPN backup", error=str(e))
        return jsonify({
            'success': False,
            'error': 'Internal server error'
        }), 500


@vpn_bp.route('/client/template', methods=['GET'])
@api_endpoint(require_auth=True, require_json=False, rate_limit=2)
def get_client_template():
    """
    Create backup of VPN configuration
    """
    try:
        vpn_manager = OpenVPNManager(current_app)

        # Create backup
        result = vpn_manager.parse_client_template()

        if result['success']:
            return jsonify({
                'success': True,
                'config': result['config'],
            }), 200
        else:
            logger.error("Failed to get client template", error=result.get('error'))

            return jsonify({
                'success': False,
                'error': result.get('error', 'Failed to get config')
            }), 500

    except Exception as e:
        logger.error("Error creating VPN backup", error=str(e))
        return jsonify({
            'success': False,
            'error': 'Internal server error'
        }), 500


@vpn_bp.route('/statistics/usage', methods=['GET'])
@api_endpoint(require_auth=True, require_json=False, cache_timeout=300)
def get_usage_statistics():
    """
    Get VPN usage statistics
    """
    try:
        days = min(int(request.args.get('days', 7)), 90)  # Max 90 days

        vpn_manager = OpenVPNManager(current_app)

        # Get current status
        status = vpn_manager.check_server_status()

        # Get all clients
        clients = vpn_manager.get_client_list()

        # Calculate statistics
        total_clients = len(clients)
        valid_certificates = len([c for c in clients if c.get('is_valid', False)])
        expired_certificates = total_clients - valid_certificates
        currently_connected = status.get('connected_clients', 0)

        # Calculate bandwidth for connected clients
        connected_clients_data = status.get('client_list', [])
        total_bandwidth = {
            'bytes_received': sum(c.get('bytes_received', 0) for c in connected_clients_data),
            'bytes_sent': sum(c.get('bytes_sent', 0) for c in connected_clients_data)
        }

        statistics = {
            'server_status': {
                'service_running': status.get('service_running', False),
                'port_listening': status.get('port_listening', False)
            },
            'client_statistics': {
                'total_clients': total_clients,
                'valid_certificates': valid_certificates,
                'expired_certificates': expired_certificates,
                'currently_connected': currently_connected,
                'connection_rate': round((currently_connected / max(total_clients, 1)) * 100, 2)
            },
            'bandwidth_statistics': {
                'total_bytes_received': total_bandwidth['bytes_received'],
                'total_bytes_sent': total_bandwidth['bytes_sent'],
                'total_mb_received': round(total_bandwidth['bytes_received'] / (1024 * 1024), 2),
                'total_mb_sent': round(total_bandwidth['bytes_sent'] / (1024 * 1024), 2),
                'total_bandwidth_mb': round(
                    (total_bandwidth['bytes_received'] + total_bandwidth['bytes_sent']) / (1024 * 1024), 2)
            },
            'period_days': days,
            'timestamp': datetime.utcnow().isoformat()
        }

        return jsonify({
            'success': True,
            'statistics': statistics
        }), 200

    except Exception as e:
        logger.error("Error getting VPN usage statistics", error=str(e))
        return jsonify({
            'success': False,
            'error': 'Internal server error'
        }), 500


@vpn_bp.route('/clients/<client_name>/details', methods=['GET'])
@api_endpoint(require_auth=True, require_json=False, cache_timeout=60)
def get_client_details(client_name):
    """
    Get detailed information about a specific client
    """
    try:
        vpn_manager = OpenVPNManager(current_app)

        # Get client list
        clients = vpn_manager.get_client_list()
        client = next((c for c in clients if c['name'] == client_name), None)

        if not client:
            return jsonify({
                'success': False,
                'error': f'Client "{client_name}" not found'
            }), 404

        # Get connection details if client is connected
        connection_details = None
        status = vpn_manager.check_server_status()
        connected_clients = status.get('client_list', [])

        for connected_client in connected_clients:
            if connected_client['common_name'] == client_name:
                connection_details = connected_client
                break

        # Combine client information with connection details
        client_details = {
            'client_info': client,
            'connection_details': connection_details,
            'is_connected': client['is_connected'],
            'has_valid_certificate': client.get('is_valid', False),
            'config_file_exists': client.get('config_file') is not None
        }

        return jsonify({
            'success': True,
            'client_details': client_details,
            'timestamp': datetime.utcnow().isoformat()
        }), 200

    except Exception as e:
        logger.error(f"Error getting client details for {client_name}", error=str(e))
        return jsonify({
            'success': False,
            'error': 'Internal server error'
        }), 500


@vpn_bp.route('/health', methods=['GET'])
@api_endpoint(require_auth=False, require_json=False, cache_timeout=30)
def vpn_health():
    """
    VPN service health check
    """
    try:
        vpn_manager = OpenVPNManager(current_app)

        # Check server status
        status = vpn_manager.check_server_status()

        # Determine overall health
        service_running = status.get('service_running', False)
        port_listening = status.get('port_listening', False)

        if service_running and port_listening:
            health_status = 'healthy'
        elif service_running or port_listening:
            health_status = 'degraded'
        else:
            health_status = 'unhealthy'

        return jsonify({
            'status': health_status,
            'service': 'openvpn',
            'timestamp': datetime.utcnow().isoformat(),
            'details': {
                'service_running': service_running,
                'port_listening': port_listening,
                'connected_clients': status.get('connected_clients', 0)
            }
        }), 200

    except Exception as e:
        logger.error("VPN health check failed", error=str(e))
        return jsonify({
            'status': 'unhealthy',
            'service': 'openvpn',
            'timestamp': datetime.utcnow().isoformat(),
            'error': str(e)
        }), 500


# Error handlers for this blueprint
@vpn_bp.errorhandler(404)
def not_found_handler(e):
    return jsonify({
        'success': False,
        'error': 'Not found',
        'message': 'The requested VPN resource was not found'
    }), 404


@vpn_bp.errorhandler(429)
def ratelimit_handler(e):
    return jsonify({
        'success': False,
        'error': 'Rate limit exceeded',
        'message': 'Too many VPN API requests',
        'retry_after': str(e.retry_after)
    }), 429


@vpn_bp.errorhandler(500)
def internal_error_handler(e):
    logger.error("Internal server error in VPN API", error=str(e))
    return jsonify({
        'success': False,
        'error': 'Internal server error',
        'message': 'VPN service error'
    }), 500
