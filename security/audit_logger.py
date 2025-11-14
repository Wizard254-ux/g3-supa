# security/audit_logger.py
import logging
import json
from datetime import datetime
from functools import wraps
from flask import request, g
from flask_jwt_extended import get_jwt_identity

def make_serializable(obj):
    try:
        json.dumps(obj)
        return obj
    except TypeError:
        return str(obj)
class AuditLogger:
    """Audit logger for system operations"""

    def __init__(self, log_file='/var/log/f2net_isp/audit.log'):
        self.logger = logging.getLogger('audit')
        self.logger.setLevel(logging.INFO)

        # Create file handler
        handler = logging.FileHandler(log_file)
        formatter = logging.Formatter(
            '%(asctime)s - AUDIT - %(message)s'
        )
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)

    def log_system_operation(self, operation, parameters, result, user_id=None):
        """Log system operation with full context"""

        serializable_args = [make_serializable(arg) for arg in parameters.get('args', [])]
        serializable_kwargs = {k: make_serializable(v) for k, v in parameters.get('kwargs', {}).items()}

        parameters_cleaned = {
            'args': serializable_args,
            'kwargs': serializable_kwargs
        }
        audit_entry = {
            'timestamp': datetime.utcnow().isoformat(),
            'user_id': user_id or 'system',
            'ip_address': request.remote_addr if request else 'system',
            'operation': operation,
            'parameters': parameters_cleaned,
            'result': result,
            'success': result.get('success', False)
        }

        self.logger.info(json.dumps(audit_entry))


# Decorator for auditing system operations
def audit_system_operation(operation_name):
    """Decorator to audit system operations"""

    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            user_id = None
            try:
                user_id = get_jwt_identity().get('user_id')
            except:
                pass

            # Log operation attempt
            audit_logger = AuditLogger()
            #
            try:
                result = func(*args, **kwargs)

                # Log successful operation
                audit_logger.log_system_operation(
                    operation=operation_name,
                    parameters={'args': args, 'kwargs': kwargs},
                    result={'success': True, 'data': result},
                    user_id=user_id
                )

                return result

            except Exception as e:
                print("ohh no",e)
                # Log failed operation
                audit_logger.log_system_operation(
                    operation=operation_name,
                    parameters={'args': args, 'kwargs': kwargs},
                    result={'success': False, 'error': str(e)},
                    user_id=user_id
                )
                raise

        return wrapper

    return decorator





#
# # Enhanced Flask routes with security features
# from security.audit_logger import audit_system_operation
# from security.rate_limiter import rate_limit
# from security.validator import SecurityValidator
#
#
# @system_bp.route('/openvpn/deploy-secure', methods=['POST'])
# @jwt_required()
# @require_admin()
# @rate_limit('system_operations')
# @audit_system_operation('openvpn_deploy')
# def deploy_openvpn_config_secure():
#     """Securely deploy OpenVPN configuration with validation"""
#     try:
#         data = request.get_json()
#         config_name = data.get('config_name')
#         config_content = data.get('config_content')
#
#         # Validate inputs
#         if not SecurityValidator.validate_config_name(config_name):
#             return jsonify({'error': 'Invalid config name format'}), 400
#
#         # Sanitize config content
#         safe_content = SecurityValidator.sanitize_config_content(config_content)
#
#         # Deploy configuration
#         openvpn_service = SystemServiceFactory.get_openvpn_service()
#         result = openvpn_service.deploy_config(config_name, safe_content)
#
#         return jsonify(result), 200
#
#     except Exception as e:
#         logger.error(f"Secure deployment failed: {e}")
#         return jsonify({'error': 'Deployment failed'}), 500
#
#
# @system_bp.route('/health', methods=['GET'])
# def system_health():
#     """Get system health status"""
#     try:
#         health_checker = HealthChecker()
#
#         health_data = {
#             'timestamp': datetime.utcnow().isoformat(),
#             'resources': health_checker.check_system_resources(),
#             'services': health_checker.check_services_status(),
#             'vpn': health_checker.check_vpn_connections()
#         }
#
#         # Determine overall health
#         critical_services = ['postgresql', 'redis-server', 'nginx']
#         services_healthy = all(
#             health_data['services'].get(service, False)
#             for service in critical_services
#         )
#
#         health_data['overall_status'] = 'healthy' if services_healthy else 'degraded'
#
#         return jsonify(health_data), 200
#
#     except Exception as e:
#         logger.error(f"Health check failed: {e}")
#         return jsonify({
#             'overall_status': 'unhealthy',
#             'error': 'Health check failed'
#         }), 500


# Configuration for production security
SECURITY_CONFIG = {
    'MAX_CONFIG_SIZE': 50 * 1024,  # 50KB max config file
    'ALLOWED_CONFIG_EXTENSIONS': ['.conf', '.ovpn'],
    'MAX_CERT_NAME_LENGTH': 50,
    'COMMAND_TIMEOUT': 30,
    'MAX_OPERATIONS_PER_USER_PER_HOUR': 100,
    'AUDIT_LOG_RETENTION_DAYS': 90,
    'ENABLE_OPERATION_NOTIFICATIONS': True
}