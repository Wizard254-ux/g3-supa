"""
Authentication API Blueprint for ISP Middleware
Handles RADIUS authentication, session management, and user validation
"""

from flask import Blueprint, request, jsonify, current_app
from flask_jwt_extended import jwt_required, create_access_token, get_jwt_identity
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import structlog
from datetime import datetime, timedelta
from typing import Dict, Any
import ipaddress

from auth.radius_auth import RadiusAuth
from services.mikrotik_service import MikroTikService
from services.radius_service import RadiusService
from utils.decorators import require_api_key, log_api_call

logger = structlog.get_logger()

# Create blueprint
auth_bp = Blueprint('auth', __name__)

# Initialize rate limiter
limiter = Limiter(key_func=get_remote_address)


@auth_bp.route('/radius/authenticate', methods=['POST'])
@limiter.limit("100 per minute")
@log_api_call
def radius_authenticate():
    """
    RADIUS authentication endpoint
    Used by FreeRADIUS server for user authentication
    """
    try:
        data = request.get_json()

        # Validate required fields
        required_fields = ['username', 'password']
        missing_fields = [field for field in required_fields if not data.get(field)]

        if missing_fields:
            return jsonify({
                'access': 'reject',
                'reason': f'Missing required fields: {", ".join(missing_fields)}'
            }), 400

        username = data['username']
        password = data['password']
        nas_ip = data.get('nas_ip_address')
        nas_port = data.get('nas_port')
        calling_station_id = data.get('calling_station_id')  # MAC address

        logger.info(
            "RADIUS authentication request",
            username=username,
            nas_ip=nas_ip,
            nas_port=nas_port,
            calling_station_id=calling_station_id
        )

        # Initialize services
        radius_auth = RadiusAuth(current_app)
        mikrotik_service = MikroTikService(current_app)

        # Check concurrent sessions
        session_check = radius_auth.check_concurrent_sessions(username)
        if not session_check['can_login']:
            logger.warning(
                "Max concurrent sessions exceeded",
                username=username,
                active_sessions=session_check['active_sessions'],
                max_sessions=session_check['max_sessions']
            )
            return jsonify({
                'access': 'reject',
                'reason': 'Maximum concurrent sessions exceeded'
            }), 200

        # Authenticate user
        auth_result = radius_auth.authenticate_user(
            username=username,
            password=password,
            nas_ip=nas_ip,
            nas_port=nas_port,
            mac_address=calling_station_id
        )

        if auth_result['success']:
            package_info = auth_result['package_info']

            # Calculate RADIUS attributes
            download_speed = package_info.get('download_speed', 1)
            upload_speed = package_info.get('upload_speed', 1)
            session_timeout = package_info.get('session_timeout', 3600)
            idle_timeout = package_info.get('idle_timeout', 600)

            # Prepare RADIUS response
            response_data = {
                'access': 'accept',
                'attributes': {
                    'Mikrotik-Rate-Limit': f"{download_speed}M/{upload_speed}M",
                    'Session-Timeout': session_timeout,
                    'Idle-Timeout': idle_timeout,
                    'Acct-Interim-Interval': 300,  # 5 minutes
                    'Framed-IP-Address': '0.0.0.0',  # Dynamic IP
                    'Service-Type': 'Framed-User'
                }
            }

            # Add additional attributes based on package type
            package_type = package_info.get('package_type', 'hotspot')
            if package_type == 'pppoe':
                response_data['attributes']['Framed-Protocol'] = 'PPP'
                response_data['attributes']['Framed-Compression'] = 'Van-Jacobsen-TCP-IP'

            # Add burst settings if available
            if package_info.get('burst_speed'):
                burst_download = package_info['burst_speed']
                burst_upload = package_info['burst_speed']
                response_data['attributes'][
                    'Mikrotik-Rate-Limit'] = f"{download_speed}M/{upload_speed}M {burst_download}M/{burst_upload}M"

            logger.info(
                "RADIUS authentication successful",
                username=username,
                package=package_info.get('package_name'),
                download_speed=download_speed,
                upload_speed=upload_speed
            )

            return jsonify(response_data), 200

        else:
            reason = auth_result.get('reason', 'Authentication failed')
            logger.warning(
                "RADIUS authentication failed",
                username=username,
                reason=reason
            )

            return jsonify({
                'access': 'reject',
                'reason': reason
            }), 200

    except Exception as e:
        logger.error("RADIUS authentication error", error=str(e))
        return jsonify({
            'access': 'reject',
            'reason': 'Internal server error'
        }), 500


@auth_bp.route('/radius/accounting', methods=['POST'])
@limiter.limit("200 per minute")
@log_api_call
def radius_accounting():
    """
    RADIUS accounting endpoint
    Handles session start, stop, and interim updates
    """
    try:
        data = request.get_json()

        # Validate required fields
        required_fields = ['acct_status_type', 'username', 'acct_session_id']
        missing_fields = [field for field in required_fields if not data.get(field)]

        if missing_fields:
            return jsonify({
                'status': 'error',
                'message': f'Missing required fields: {", ".join(missing_fields)}'
            }), 400

        acct_status_type = data['acct_status_type']
        username = data['username']
        session_id = data['acct_session_id']
        nas_ip = data.get('nas_ip_address')

        logger.info(
            "RADIUS accounting request",
            username=username,
            session_id=session_id,
            status_type=acct_status_type,
            nas_ip=nas_ip
        )

        # Initialize services
        radius_service = RadiusService(current_app)
        mikrotik_service = MikroTikService(current_app)

        # Process accounting request based on status type
        if acct_status_type == 'Start':
            # Session start
            result = radius_service.handle_session_start({
                'username': username,
                'session_id': session_id,
                'nas_ip': nas_ip,
                'nas_port': data.get('nas_port'),
                'framed_ip': data.get('framed_ip_address'),
                'calling_station_id': data.get('calling_station_id'),
                'called_station_id': data.get('called_station_id'),
                'start_time': datetime.utcnow()
            })

            logger.info(f"Session started for user: {username}")

        elif acct_status_type == 'Stop':
            # Session stop
            stop_data = {
                'username': username,
                'session_id': session_id,
                'nas_ip': nas_ip,
                'stop_time': datetime.utcnow(),
                'session_time': data.get('acct_session_time', 0),
                'input_octets': data.get('acct_input_octets', 0),
                'output_octets': data.get('acct_output_octets', 0),
                'input_packets': data.get('acct_input_packets', 0),
                'output_packets': data.get('acct_output_packets', 0),
                'terminate_cause': data.get('acct_terminate_cause', 'Unknown')
            }

            result = radius_service.handle_session_stop(stop_data)

            # Clean up MikroTik queue
            mikrotik_service.remove_user_queue(username)

            logger.info(
                "Session stopped for user",
                username=username,
                session_time=stop_data['session_time'],
                input_mb=round(stop_data['input_octets'] / (1024 * 1024), 2),
                output_mb=round(stop_data['output_octets'] / (1024 * 1024), 2)
            )

        elif acct_status_type == 'Interim-Update':
            # Session interim update
            update_data = {
                'username': username,
                'session_id': session_id,
                'nas_ip': nas_ip,
                'update_time': datetime.utcnow(),
                'session_time': data.get('acct_session_time', 0),
                'input_octets': data.get('acct_input_octets', 0),
                'output_octets': data.get('acct_output_octets', 0),
                'input_packets': data.get('acct_input_packets', 0),
                'output_packets': data.get('acct_output_packets', 0)
            }

            result = radius_service.handle_session_update(update_data)

            logger.debug(
                "Session updated for user",
                username=username,
                session_time=update_data['session_time']
            )

        else:
            logger.warning(f"Unknown accounting status type: {acct_status_type}")
            return jsonify({
                'status': 'error',
                'message': f'Unknown status type: {acct_status_type}'
            }), 400

        return jsonify({'status': 'ok'}), 200

    except Exception as e:
        logger.error("RADIUS accounting error", error=str(e))
        return jsonify({
            'status': 'error',
            'message': 'Internal server error'
        }), 500


@auth_bp.route('/hotspot/login', methods=['POST'])
@limiter.limit("50 per minute")
@log_api_call
def hotspot_login():
    """
    Hotspot captive portal login endpoint
    """
    try:
        data = request.get_json()

        # Validate required fields
        required_fields = ['username', 'password']
        missing_fields = [field for field in required_fields if not data.get(field)]

        if missing_fields:
            return jsonify({
                'success': False,
                'message': f'Missing required fields: {", ".join(missing_fields)}'
            }), 400

        username = data['username']
        password = data['password']
        mac_address = data.get('mac')
        ip_address = data.get('ip')
        link_orig = data.get('link_orig', 'http://google.com')

        logger.info(
            "Hotspot login request",
            username=username,
            mac_address=mac_address,
            ip_address=ip_address
        )

        # Initialize services
        radius_auth = RadiusAuth(current_app)
        mikrotik_service = MikroTikService(current_app)

        # Authenticate user
        auth_result = radius_auth.authenticate_user(
            username=username,
            password=password,
            mac_address=mac_address
        )

        if auth_result['success']:
            package_info = auth_result['package_info']

            # Authorize user on MikroTik hotspot
            hotspot_result = mikrotik_service.hotspot_authorize(
                username=username,
                mac_address=mac_address,
                ip_address=ip_address,
                package_info=package_info
            )

            if hotspot_result['success']:
                logger.info(f"Hotspot login successful for user: {username}")

                return jsonify({
                    'success': True,
                    'message': 'Login successful',
                    'redirect_url': link_orig,
                    'package': {
                        'name': package_info.get('package_name'),
                        'download_speed': package_info.get('download_speed'),
                        'upload_speed': package_info.get('upload_speed'),
                        'data_limit': package_info.get('data_limit'),
                        'time_limit': package_info.get('time_limit')
                    }
                }), 200
            else:
                logger.error(f"Failed to authorize hotspot user: {username}")
                return jsonify({
                    'success': False,
                    'message': 'Failed to authorize on network'
                }), 500
        else:
            reason = auth_result.get('reason', 'Invalid credentials')
            logger.warning(f"Hotspot login failed for user: {username}", reason=reason)

            return jsonify({
                'success': False,
                'message': reason
            }), 401

    except Exception as e:
        logger.error("Hotspot login error", error=str(e))
        return jsonify({
            'success': False,
            'message': 'Login failed due to server error'
        }), 500


@auth_bp.route('/hotspot/logout', methods=['POST'])
@limiter.limit("50 per minute")
@log_api_call
def hotspot_logout():
    """
    Hotspot logout endpoint
    """
    try:
        data = request.get_json()
        username = data.get('username')

        if not username:
            return jsonify({
                'success': False,
                'message': 'Username required'
            }), 400

        logger.info(f"Hotspot logout request for user: {username}")

        # Initialize services
        mikrotik_service = MikroTikService(current_app)
        radius_auth = RadiusAuth(current_app)

        # Deauthorize user from hotspot
        deauth_result = mikrotik_service.hotspot_deauthorize(username)

        # Terminate any active sessions
        # Note: In a real implementation, you'd need to track session IDs
        # For now, we'll just clean up the hotspot authorization

        if deauth_result:
            logger.info(f"Hotspot logout successful for user: {username}")
            return jsonify({
                'success': True,
                'message': 'Logout successful'
            }), 200
        else:
            logger.warning(f"Failed to logout hotspot user: {username}")
            return jsonify({
                'success': False,
                'message': 'Logout failed'
            }), 500

    except Exception as e:
        logger.error("Hotspot logout error", error=str(e))
        return jsonify({
            'success': False,
            'message': 'Logout failed due to server error'
        }), 500


@auth_bp.route('/session/validate', methods=['POST'])
@require_api_key
@log_api_call
def validate_session():
    """
    Validate user session
    """
    try:
        data = request.get_json()
        username = data.get('username')
        session_id = data.get('session_id')

        if not username or not session_id:
            return jsonify({
                'valid': False,
                'reason': 'Username and session_id required'
            }), 400

        # Initialize service
        radius_auth = RadiusAuth(current_app)

        # Validate session
        validation_result = radius_auth.validate_session(username, session_id)

        return jsonify(validation_result), 200

    except Exception as e:
        logger.error("Session validation error", error=str(e))
        return jsonify({
            'valid': False,
            'reason': 'Session validation error'
        }), 500


@auth_bp.route('/session/terminate', methods=['POST'])
@require_api_key
@log_api_call
def terminate_session():
    """
    Terminate user session
    """
    try:
        data = request.get_json()
        username = data.get('username')
        session_id = data.get('session_id')
        reason = data.get('reason', 'Manual termination')

        if not username or not session_id:
            return jsonify({
                'success': False,
                'message': 'Username and session_id required'
            }), 400

        logger.info(f"Terminating session for user: {username}", session_id=session_id, reason=reason)

        # Initialize services
        radius_auth = RadiusAuth(current_app)
        mikrotik_service = MikroTikService(current_app)

        # Terminate session
        termination_result = radius_auth.terminate_session(username, session_id)

        # Clean up MikroTik resources
        mikrotik_service.remove_user_queue(username)
        mikrotik_service.hotspot_deauthorize(username)

        if termination_result:
            logger.info(f"Session terminated successfully for user: {username}")
            return jsonify({
                'success': True,
                'message': 'Session terminated successfully'
            }), 200
        else:
            logger.warning(f"Failed to terminate session for user: {username}")
            return jsonify({
                'success': False,
                'message': 'Failed to terminate session'
            }), 500

    except Exception as e:
        logger.error("Session termination error", error=str(e))
        return jsonify({
            'success': False,
            'message': 'Session termination error'
        }), 500


@auth_bp.route('/stats', methods=['GET'])
@require_api_key
@log_api_call
def auth_stats():
    """
    Get authentication statistics
    """
    try:
        # Initialize service
        radius_auth = RadiusAuth(current_app)

        # Get authentication statistics
        stats = radius_auth.get_auth_stats()

        return jsonify(stats), 200

    except Exception as e:
        logger.error("Error getting auth stats", error=str(e))
        return jsonify({
            'error': 'Failed to get authentication statistics'
        }), 500


@auth_bp.route('/health', methods=['GET'])
def auth_health():
    """
    Authentication service health check
    """
    try:
        # Initialize services
        radius_auth = RadiusAuth(current_app)

        # Check Redis connection
        stats = radius_auth.get_auth_stats()

        return jsonify({
            'status': 'healthy',
            'service': 'authentication',
            'timestamp': datetime.utcnow().isoformat(),
            'stats': stats
        }), 200

    except Exception as e:
        logger.error("Auth health check failed", error=str(e))
        return jsonify({
            'status': 'unhealthy',
            'service': 'authentication',
            'timestamp': datetime.utcnow().isoformat(),
            'error': str(e)
        }), 500


# Error handlers for this blueprint
@auth_bp.errorhandler(429)
def ratelimit_handler(e):
    return jsonify({
        'error': 'Rate limit exceeded',
        'message': 'Too many authentication requests',
        'retry_after': str(e.retry_after)
    }), 429


@auth_bp.errorhandler(400)
def bad_request_handler(e):
    return jsonify({
        'error': 'Bad request',
        'message': str(e)
    }), 400


@auth_bp.errorhandler(500)
def internal_error_handler(e):
    logger.error("Internal server error in auth API", error=str(e))
    return jsonify({
        'error': 'Internal server error',
        'message': 'Authentication service error'
    }), 500