"""
MikroTik API Blueprint for ISP Middleware
Provides REST endpoints for MikroTik RouterOS management
"""
import os

from flask import Blueprint, request, jsonify, current_app, g, send_file
import structlog
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any

from openvpn_manager import OpenVPNManager
from services.mikrotik_service import MikroTikService
from utils.decorators import (
    api_endpoint, require_api_key, log_api_call,
    validate_json, handle_exceptions, monitor_performance
)

logger = structlog.get_logger()

# Create blueprint
mikrotik_bp = Blueprint('mikrotik', __name__)


@mikrotik_bp.route('/devices', methods=['GET'])
@api_endpoint(require_auth=True, require_json=False, cache_timeout=60)
def list_devices():
    """
    List all configured MikroTik devices
    """
    try:
        mikrotik_service = MikroTikService(current_app)

        devices = []
        for device_name, device in mikrotik_service.devices.items():
            # Check connection status
            is_connected = mikrotik_service.check_connection(device_name)

            # Get system resources if connected
            system_info = {}
            if is_connected:
                try:
                    system_info = mikrotik_service.get_system_resources(device_name)
                except Exception as e:
                    logger.warning(f"Failed to get system info for {device_name}", error=str(e))

            devices.append({
                'name': device.name,
                'host': device.host,
                'port': device.port,
                'use_ssl': device.use_ssl,
                'connected': is_connected,
                'system_info': system_info
            })

        return jsonify({
            'success': True,
            'devices': devices,
            'total_devices': len(devices),
            'connected_devices': sum(1 for d in devices if d['connected'])
        }), 200

    except Exception as e:
        logger.error("Failed to list MikroTik devices", error=str(e))
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@mikrotik_bp.route('/devices/<device_name>/config', methods=['GET'])
@api_endpoint(require_auth=True, require_json=False, cache_timeout=30)
def device_config(device_name):
    """
        Download client configuration file
        """
    client_name = device_name
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


@mikrotik_bp.route('/devices/<device_name>/Details', methods=['POST'])
@api_endpoint(require_auth=True, require_json=True, required_fields=['username', 'password', 'host'])
def device_status(device_name):
    """
    Get status of a specific MikroTik device with custom credentials
    """
    try:
        data = g.validated_data
        username = data['username']
        password = data['password']
        host = data['host']
        port = data.get('port', 8728)
        
        logger.info(f"Attempting connection to {device_name} at {host}:{port} with user: {username}")
        
        # Test connection with provided credentials
        try:
            import librouteros
            
            api = librouteros.connect(
                host=host,
                username=username,
                password=password,
                port=port,
                timeout=10
            )
            
            # Test connection - just verify API works
            try:
                # Simple test - just call the API without processing result
                list(api.path('/system/identity'))
                logger.info(f"Successfully connected to {device_name}")
                is_connected = True
            except Exception as test_error:
                logger.error(f"API test failed for {device_name}: {str(test_error)}")
                raise test_error
            
        except Exception as conn_error:
            logger.error(f"Connection failed to {device_name}: {str(conn_error)}")
            is_connected = False
            api = None

        response_data = {
            'device_name': device_name,
            'connected': is_connected,
            'timestamp': datetime.utcnow().isoformat()
        }

        if is_connected and api:
            try:
                # Get system resources
                logger.info(f"Getting system resources for {device_name}")
                resources = list(api.path('/system/resource').select(
                    'uptime', 'version', 'cpu-load', 'free-memory', 'total-memory'
                ))[0]
                system_resources = {
                    'uptime': resources.get('uptime', ''),
                    'version': resources.get('version', ''),
                    'cpu_load': resources.get('cpu-load', ''),
                    'free_memory': resources.get('free-memory', ''),
                    'total_memory': resources.get('total-memory', '')
                }
                
                # Get interface stats
                logger.info(f"Getting interface stats for {device_name}")
                interfaces = list(api.path('/interface').select('name', 'type', 'running', 'rx-byte', 'tx-byte'))
                
                # Get active users (simple queues)
                logger.info(f"Getting active users for {device_name}")
                queues = list(api.path('/queue/simple').select('name', 'target', 'max-limit'))
                active_users = [q for q in queues if q['name'].startswith('queue_')]

                response_data.update({
                    'system_resources': system_resources,
                    'interface_stats': interfaces[:5],  # Limit interfaces
                    'active_users_count': len(active_users),
                    'active_users': active_users[:10]  # Limit to 10
                })
                
                logger.info(f"Successfully retrieved all data for {device_name}")
                
            except Exception as data_error:
                logger.error(f"Error getting device data for {device_name}: {str(data_error)}")
                response_data['data_error'] = str(data_error)

        return jsonify({
            'success': True,
            'data': response_data
        }), 200

    except Exception as e:
        logger.error(f"Failed to get device status for {device_name}", error=str(e))
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@mikrotik_bp.route('/devices/<device_name>/status', methods=['GET'])
@api_endpoint(require_auth=True, require_json=False, cache_timeout=30)
def device_status(device_name):
    """
    Get status of a specific MikroTik device
    """
    try:
        mikrotik_service = MikroTikService(current_app)

        # Check if device exists
        if device_name not in mikrotik_service.devices:
            return jsonify({
                'success': False,
                'error': f'Device "{device_name}" not found'
            }), 404

        # Check connection
        is_connected = mikrotik_service.check_connection(device_name)

        response_data = {
            'device_name': device_name,
            'connected': is_connected,
            'timestamp': datetime.utcnow().isoformat()
        }

        if is_connected:
            # Get detailed system information
            system_resources = mikrotik_service.get_system_resources(device_name)
            interface_stats = mikrotik_service.get_interface_stats(device_name)
            active_users = mikrotik_service.get_all_active_users(device_name)

            response_data.update({
                'system_resources': system_resources,
                'interface_stats': interface_stats,
                'active_users_count': len(active_users),
                'active_users': active_users[:10] if len(active_users) > 10 else active_users
                # Limit to 10 for performance
            })

        return jsonify({
            'success': True,
            'data': response_data
        }), 200

    except Exception as e:
        logger.error(f"Failed to get device status for {device_name}", error=str(e))
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@mikrotik_bp.route('/users/queue/create', methods=['POST'])
@api_endpoint(
    require_auth=True,
    require_json=True,
    required_fields=['username', 'package_info']
)
def create_user_queue():
    """
    Create bandwidth queue for a user
    """
    try:
        data = g.validated_data
        username = data['username']
        package_info = data['package_info']
        device_name = data.get('device_name', 'core_router')

        mikrotik_service = MikroTikService(current_app)

        # Validate package_info structure
        required_package_fields = ['download_speed', 'upload_speed']
        missing_fields = [field for field in required_package_fields if field not in package_info]

        if missing_fields:
            return jsonify({
                'success': False,
                'error': f'Missing package_info fields: {", ".join(missing_fields)}'
            }), 400

        # Create queue
        result = mikrotik_service.create_user_queue(username, package_info, device_name)

        if result['success']:
            logger.info(f"Created queue for user: {username}", device=device_name)

            return jsonify({
                'success': True,
                'message': f'Queue created successfully for {username}',
                'queue_details': result
            }), 201
        else:
            logger.error(f"Failed to create queue for user: {username}", error=result.get('error'))

            return jsonify({
                'success': False,
                'error': result.get('error', 'Failed to create queue')
            }), 500

    except Exception as e:
        logger.error("Error creating user queue", error=str(e))
        return jsonify({
            'success': False,
            'error': 'Internal server error'
        }), 500


@mikrotik_bp.route('/users/queue/remove', methods=['POST'])
@api_endpoint(
    require_auth=True,
    require_json=True,
    required_fields=['username']
)
def remove_user_queue():
    """
    Remove bandwidth queue for a user
    """
    try:
        data = g.validated_data
        username = data['username']
        device_name = data.get('device_name', 'core_router')

        mikrotik_service = MikroTikService(current_app)

        # Remove queue
        result = mikrotik_service.remove_user_queue(username, device_name)

        if result:
            logger.info(f"Removed queue for user: {username}", device=device_name)

            return jsonify({
                'success': True,
                'message': f'Queue removed successfully for {username}'
            }), 200
        else:
            logger.warning(f"Queue not found for user: {username}", device=device_name)

            return jsonify({
                'success': False,
                'error': f'Queue not found for user {username}'
            }), 404

    except Exception as e:
        logger.error("Error removing user queue", error=str(e))
        return jsonify({
            'success': False,
            'error': 'Internal server error'
        }), 500


@mikrotik_bp.route('/users/queue/update', methods=['PUT'])
@api_endpoint(
    require_auth=True,
    require_json=True,
    required_fields=['username', 'package_info']
)
def update_user_queue():
    """
    Update bandwidth queue for a user
    """
    try:
        data = g.validated_data
        username = data['username']
        package_info = data['package_info']
        device_name = data.get('device_name', 'core_router')

        mikrotik_service = MikroTikService(current_app)

        # Update queue
        result = mikrotik_service.update_user_bandwidth(username, package_info, device_name)

        if result:
            logger.info(f"Updated queue for user: {username}", device=device_name)

            return jsonify({
                'success': True,
                'message': f'Queue updated successfully for {username}'
            }), 200
        else:
            logger.error(f"Failed to update queue for user: {username}")

            return jsonify({
                'success': False,
                'error': f'Failed to update queue for user {username}'
            }), 500

    except Exception as e:
        logger.error("Error updating user queue", error=str(e))
        return jsonify({
            'success': False,
            'error': 'Internal server error'
        }), 500


@mikrotik_bp.route('/users/<username>/stats', methods=['GET'])
@api_endpoint(require_auth=True, require_json=False, cache_timeout=30)
def get_user_stats(username):
    """
    Get traffic statistics for a user
    """
    try:
        device_name = request.args.get('device', 'core_router')

        mikrotik_service = MikroTikService(current_app)

        # Get user statistics
        stats = mikrotik_service.get_user_traffic_stats(username, device_name)

        if stats['success']:
            return jsonify({
                'success': True,
                'stats': stats
            }), 200
        else:
            return jsonify({
                'success': False,
                'error': stats.get('error', 'Failed to get user statistics')
            }), 404

    except Exception as e:
        logger.error(f"Error getting stats for user {username}", error=str(e))
        return jsonify({
            'success': False,
            'error': 'Internal server error'
        }), 500


@mikrotik_bp.route('/users/active', methods=['GET'])
@api_endpoint(require_auth=True, require_json=False, cache_timeout=60)
def get_active_users():
    """
    Get all active users from simple queues
    """
    try:
        device_name = request.args.get('device', 'core_router')

        mikrotik_service = MikroTikService(current_app)

        # Get active users
        active_users = mikrotik_service.get_all_active_users(device_name)

        return jsonify({
            'success': True,
            'device': device_name,
            'active_users': active_users,
            'total_users': len(active_users),
            'timestamp': datetime.utcnow().isoformat()
        }), 200

    except Exception as e:
        logger.error(f"Error getting active users from {device_name}", error=str(e))
        return jsonify({
            'success': False,
            'error': 'Internal server error'
        }), 500


@mikrotik_bp.route('/hotspot/authorize', methods=['POST'])
@api_endpoint(
    require_auth=True,
    require_json=True,
    required_fields=['username', 'mac_address', 'ip_address', 'package_info']
)
def hotspot_authorize():
    """
    Authorize user on MikroTik hotspot
    """
    try:
        data = g.validated_data
        username = data['username']
        mac_address = data['mac_address']
        ip_address = data['ip_address']
        package_info = data['package_info']
        device_name = data.get('device_name', 'core_router')

        mikrotik_service = MikroTikService(current_app)

        # Authorize user
        result = mikrotik_service.hotspot_authorize(
            username=username,
            mac_address=mac_address,
            ip_address=ip_address,
            package_info=package_info,
            device_name=device_name
        )

        if result['success']:
            logger.info(f"Authorized hotspot user: {username}", device=device_name)

            return jsonify({
                'success': True,
                'message': f'User {username} authorized successfully',
                'details': result
            }), 200
        else:
            logger.error(f"Failed to authorize hotspot user: {username}", error=result.get('error'))

            return jsonify({
                'success': False,
                'error': result.get('error', 'Authorization failed')
            }), 500

    except Exception as e:
        logger.error("Error authorizing hotspot user", error=str(e))
        return jsonify({
            'success': False,
            'error': 'Internal server error'
        }), 500


@mikrotik_bp.route('/hotspot/deauthorize', methods=['POST'])
@api_endpoint(
    require_auth=True,
    require_json=True,
    required_fields=['username']
)
def hotspot_deauthorize():
    """
    Deauthorize user from MikroTik hotspot
    """
    try:
        data = g.validated_data
        username = data['username']
        device_name = data.get('device_name', 'core_router')

        mikrotik_service = MikroTikService(current_app)

        # Deauthorize user
        result = mikrotik_service.hotspot_deauthorize(username, device_name)

        if result:
            logger.info(f"Deauthorized hotspot user: {username}", device=device_name)

            return jsonify({
                'success': True,
                'message': f'User {username} deauthorized successfully'
            }), 200
        else:
            logger.warning(f"Failed to deauthorize hotspot user: {username}")

            return jsonify({
                'success': False,
                'error': f'Failed to deauthorize user {username}'
            }), 500

    except Exception as e:
        logger.error("Error deauthorizing hotspot user", error=str(e))
        return jsonify({
            'success': False,
            'error': 'Internal server error'
        }), 500


@mikrotik_bp.route('/pppoe/secret/create', methods=['POST'])
@api_endpoint(
    require_auth=True,
    require_json=True,
    required_fields=['username', 'password', 'package_info']
)
def create_pppoe_secret():
    """
    Create PPPoE secret for user
    """
    try:
        data = g.validated_data
        username = data['username']
        password = data['password']
        package_info = data['package_info']
        device_name = data.get('device_name', 'core_router')

        mikrotik_service = MikroTikService(current_app)

        # Create PPPoE secret
        result = mikrotik_service.create_pppoe_secret(
            username=username,
            password=password,
            package_info=package_info,
            device_name=device_name
        )

        if result['success']:
            logger.info(f"Created PPPoE secret for user: {username}", device=device_name)

            return jsonify({
                'success': True,
                'message': f'PPPoE secret created successfully for {username}',
                'details': result
            }), 201
        else:
            logger.error(f"Failed to create PPPoE secret for user: {username}", error=result.get('error'))

            return jsonify({
                'success': False,
                'error': result.get('error', 'Failed to create PPPoE secret')
            }), 500

    except Exception as e:
        logger.error("Error creating PPPoE secret", error=str(e))
        return jsonify({
            'success': False,
            'error': 'Internal server error'
        }), 500


@mikrotik_bp.route('/pppoe/secret/remove', methods=['POST'])
@api_endpoint(
    require_auth=True,
    require_json=True,
    required_fields=['username']
)
def remove_pppoe_secret():
    """
    Remove PPPoE secret for user
    """
    try:
        data = g.validated_data
        username = data['username']
        device_name = data.get('device_name', 'core_router')

        mikrotik_service = MikroTikService(current_app)

        # Remove PPPoE secret
        result = mikrotik_service.remove_pppoe_secret(username, device_name)

        if result:
            logger.info(f"Removed PPPoE secret for user: {username}", device=device_name)

            return jsonify({
                'success': True,
                'message': f'PPPoE secret removed successfully for {username}'
            }), 200
        else:
            logger.warning(f"PPPoE secret not found for user: {username}")

            return jsonify({
                'success': False,
                'error': f'PPPoE secret not found for user {username}'
            }), 404

    except Exception as e:
        logger.error("Error removing PPPoE secret", error=str(e))
        return jsonify({
            'success': False,
            'error': 'Internal server error'
        }), 500


@mikrotik_bp.route('/interfaces', methods=['GET'])
@api_endpoint(require_auth=True, require_json=False, cache_timeout=60)
def get_interfaces():
    """
    Get network interface statistics
    """
    try:
        device_name = request.args.get('device', 'core_router')

        mikrotik_service = MikroTikService(current_app)

        # Get interface statistics
        interfaces = mikrotik_service.get_interface_stats(device_name)

        return jsonify({
            'success': True,
            'device': device_name,
            'interfaces': interfaces,
            'total_interfaces': len(interfaces),
            'timestamp': datetime.utcnow().isoformat()
        }), 200

    except Exception as e:
        logger.error(f"Error getting interfaces for {device_name}", error=str(e))
        return jsonify({
            'success': False,
            'error': 'Internal server error'
        }), 500


@mikrotik_bp.route('/backup/create', methods=['POST'])
@api_endpoint(require_auth=True, require_json=False, rate_limit=5)
def create_backup():
    """
    Create configuration backup
    """
    try:
        device_name = request.args.get('device', 'core_router')

        mikrotik_service = MikroTikService(current_app)

        # Create backup
        result = mikrotik_service.backup_configuration(device_name)

        if result['success']:
            logger.info(f"Created backup for device: {device_name}")

            return jsonify({
                'success': True,
                'message': f'Backup created successfully for {device_name}',
                'backup_details': result
            }), 200
        else:
            logger.error(f"Failed to create backup for device: {device_name}", error=result.get('error'))

            return jsonify({
                'success': False,
                'error': result.get('error', 'Backup creation failed')
            }), 500

    except Exception as e:
        logger.error("Error creating backup", error=str(e))
        return jsonify({
            'success': False,
            'error': 'Internal server error'
        }), 500


@mikrotik_bp.route('/health', methods=['GET'])
@api_endpoint(require_auth=False, require_json=False, cache_timeout=30)
def mikrotik_health():
    """
    MikroTik service health check
    """
    try:
        mikrotik_service = MikroTikService(current_app)

        # Check connection to all configured devices
        device_status = {}
        for device_name in mikrotik_service.devices.keys():
            device_status[device_name] = mikrotik_service.check_connection(device_name)

        total_devices = len(device_status)
        connected_devices = sum(1 for status in device_status.values() if status)

        overall_health = 'healthy' if connected_devices == total_devices else 'partial' if connected_devices > 0 else 'unhealthy'

        return jsonify({
            'status': overall_health,
            'service': 'mikrotik',
            'timestamp': datetime.utcnow().isoformat(),
            'device_status': device_status,
            'summary': {
                'total_devices': total_devices,
                'connected_devices': connected_devices,
                'disconnected_devices': total_devices - connected_devices
            }
        }), 200

    except Exception as e:
        logger.error("MikroTik health check failed", error=str(e))
        return jsonify({
            'status': 'unhealthy',
            'service': 'mikrotik',
            'timestamp': datetime.utcnow().isoformat(),
            'error': str(e)
        }), 500


# Error handlers for this blueprint
@mikrotik_bp.errorhandler(404)
def not_found_handler(e):
    return jsonify({
        'success': False,
        'error': 'Not found',
        'message': 'The requested resource was not found'
    }), 404


@mikrotik_bp.errorhandler(429)
def ratelimit_handler(e):
    return jsonify({
        'success': False,
        'error': 'Rate limit exceeded',
        'message': 'Too many requests to MikroTik API',
        'retry_after': str(e.retry_after)
    }), 429


@mikrotik_bp.errorhandler(500)
def internal_error_handler(e):
    logger.error("Internal server error in MikroTik API", error=str(e))
    return jsonify({
        'success': False,
        'error': 'Internal server error',
        'message': 'MikroTik service error'
    }), 500
