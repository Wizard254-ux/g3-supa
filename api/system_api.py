# routes/system_api.py
from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from services.system_service import (
    SystemServiceFactory,
    SystemOperationError
)
import logging

logger = logging.getLogger(__name__)
system_bp = Blueprint('system', __name__, url_prefix='/api/system')


def require_admin():
    """Decorator to require admin privileges"""

    def decorator(f):
        def decorated_function(*args, **kwargs):
            current_user = get_jwt_identity()
            # Add your admin check logic here
            if not current_user.get('is_admin'):
                return jsonify({'error': 'Admin privileges required'}), 403
            return f(*args, **kwargs)

        return decorated_function

    return decorator


@system_bp.route('/openvpn/deploy', methods=['POST'])
@jwt_required()
@require_admin()
def deploy_openvpn_config():
    """Deploy OpenVPN configuration"""
    try:
        data = request.get_json()
        config_name = data.get('config_name')
        config_content = data.get('config_content')

        if not config_name or not config_content:
            return jsonify({
                'error': 'config_name and config_content are required'
            }), 400

        # Get OpenVPN service
        openvpn_service = SystemServiceFactory.get_openvpn_service()

        # Deploy configuration
        result = openvpn_service.deploy_config(config_name, config_content)

        # Log the operation
        logger.info(f"OpenVPN config deployed: {config_name} by {get_jwt_identity()}")

        return jsonify(result), 200

    except SystemOperationError as e:
        logger.error(f"System operation failed: {e}")
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        return jsonify({'error': 'Internal server error'}), 500


@system_bp.route('/openvpn/start/<config_name>', methods=['POST'])
@jwt_required()
@require_admin()
def start_openvpn_service(config_name):
    """Start OpenVPN service"""
    try:
        openvpn_service = SystemServiceFactory.get_openvpn_service()
        result = openvpn_service.start_service(config_name)

        logger.info(f"OpenVPN service started: {config_name} by {get_jwt_identity()}")
        return jsonify(result), 200

    except SystemOperationError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        return jsonify({'error': 'Internal server error'}), 500


@system_bp.route('/openvpn/stop/<config_name>', methods=['POST'])
@jwt_required()
@require_admin()
def stop_openvpn_service(config_name):
    """Stop OpenVPN service"""
    try:
        openvpn_service = SystemServiceFactory.get_openvpn_service()
        result = openvpn_service.stop_service(config_name)

        logger.info(f"OpenVPN service stopped: {config_name} by {get_jwt_identity()}")
        return jsonify(result), 200

    except SystemOperationError as e:
        return jsonify({'error': str(e)}), 400


@system_bp.route('/openvpn/status/<config_name>', methods=['GET'])
@jwt_required()
def get_openvpn_status(config_name):
    """Get OpenVPN service status"""
    try:
        openvpn_service = SystemServiceFactory.get_openvpn_service()
        result = openvpn_service.get_service_status(config_name)
        return jsonify(result), 200

    except SystemOperationError as e:
        return jsonify({'error': str(e)}), 400


@system_bp.route('/certificates/generate', methods=['POST'])
@jwt_required()
@require_admin()
def generate_certificate():
    """Generate client certificate"""
    try:
        data = request.get_json()
        cert_name = data.get('cert_name')

        if not cert_name:
            return jsonify({'error': 'cert_name is required'}), 400

        cert_service = SystemServiceFactory.get_certificate_service()
        result = cert_service.generate_client_cert(cert_name)

        logger.info(f"Certificate generated: {cert_name} by {get_jwt_identity()}")
        return jsonify(result), 200

    except SystemOperationError as e:
        return jsonify({'error': str(e)}), 400


@system_bp.route('/certificates/revoke', methods=['POST'])
@jwt_required()
@require_admin()
def revoke_certificate():
    """Revoke client certificate"""
    try:
        data = request.get_json()
        cert_name = data.get('cert_name')

        if not cert_name:
            return jsonify({'error': 'cert_name is required'}), 400

        cert_service = SystemServiceFactory.get_certificate_service()
        result = cert_service.revoke_client_cert(cert_name)

        logger.info(f"Certificate revoked: {cert_name} by {get_jwt_identity()}")
        return jsonify(result), 200

    except SystemOperationError as e:
        return jsonify({'error': str(e)}), 400


@system_bp.route('/network/iptables', methods=['POST'])
@jwt_required()
@require_admin()
def add_iptables_rule():
    """Add iptables rule"""
    try:
        data = request.get_json()
        rule_params = data.get('rule_params', [])

        if not rule_params:
            return jsonify({'error': 'rule_params are required'}), 400

        network_service = SystemServiceFactory.get_network_service()
        result = network_service.add_iptables_rule(rule_params)

        logger.info(f"Iptables rule added by {get_jwt_identity()}: {rule_params}")
        return jsonify(result), 200

    except SystemOperationError as e:
        return jsonify({'error': str(e)}), 400


@system_bp.route('/network/route', methods=['POST'])
@jwt_required()
@require_admin()
def add_network_route():
    """Add network route"""
    try:
        data = request.get_json()
        destination = data.get('destination')
        gateway = data.get('gateway')
        interface = data.get('interface')

        if not destination or not gateway:
            return jsonify({'error': 'destination and gateway are required'}), 400

        network_service = SystemServiceFactory.get_network_service()
        result = network_service.add_route(destination, gateway, interface)

        logger.info(f"Route added by {get_jwt_identity()}: {destination} via {gateway}")
        return jsonify(result), 200

    except SystemOperationError as e:
        return jsonify({'error': str(e)}), 400


@system_bp.route('/radius/start', methods=['POST'])
@jwt_required()
@require_admin()
def start_radius_service():
    """Start FreeRADIUS service"""
    try:
        radius_service = SystemServiceFactory.get_radius_service()
        result = radius_service.start_service()

        logger.info(f"FreeRADIUS started by {get_jwt_identity()}")
        return jsonify(result), 200

    except SystemOperationError as e:
        return jsonify({'error': str(e)}), 400


@system_bp.route('/radius/stop', methods=['POST'])
@jwt_required()
@require_admin()
def stop_radius_service():
    """Stop FreeRADIUS service"""
    try:
        radius_service = SystemServiceFactory.get_radius_service()
        result = radius_service.stop_service()

        logger.info(f"FreeRADIUS stopped by {get_jwt_identity()}")
        return jsonify(result), 200

    except SystemOperationError as e:
        return jsonify({'error': str(e)}), 400


@system_bp.route('/radius/restart', methods=['POST'])
@jwt_required()
@require_admin()
def restart_radius_service():
    """Restart FreeRADIUS service"""
    try:
        radius_service = SystemServiceFactory.get_radius_service()
        result = radius_service.restart_service()

        logger.info(f"FreeRADIUS restarted by {get_jwt_identity()}")
        return jsonify(result), 200

    except SystemOperationError as e:
        return jsonify({'error': str(e)}), 400


# Example of using system services in background tasks (Celery)
# tasks/system_tasks.py
from celery import Celery
from services.system_service import SystemServiceFactory, SystemOperationError
import logging

logger = logging.getLogger(__name__)


def configure_celery(app):
    """Configure Celery with Flask app"""
    celery = Celery(app.import_name)
    celery.conf.update(app.config)
    return celery


@celery.task
def deploy_vpn_config_async(config_name, config_content):
    """Asynchronously deploy VPN configuration"""
    try:
        openvpn_service = SystemServiceFactory.get_openvpn_service()
        result = openvpn_service.deploy_config(config_name, config_content)

        # Start the service after deployment
        openvpn_service.start_service(config_name)

        logger.info(f"VPN config deployed and started: {config_name}")
        return result

    except SystemOperationError as e:
        logger.error(f"Failed to deploy VPN config: {e}")
        raise


@celery.task
def cleanup_expired_certificates():
    """Background task to clean up expired certificates"""
    try:
        # Your certificate cleanup logic here
        cert_service = SystemServiceFactory.get_certificate_service()

        # Example: revoke expired certificates
        # This would need your own logic to check certificate expiry

        logger.info("Certificate cleanup completed")

    except Exception as e:
        logger.error(f"Certificate cleanup failed: {e}")
        raise


# Example usage in a Flask route with async processing
@system_bp.route('/openvpn/deploy-async', methods=['POST'])
@jwt_required()
@require_admin()
def deploy_openvpn_config_async():
    """Deploy OpenVPN configuration asynchronously"""
    try:
        data = request.get_json()
        config_name = data.get('config_name')
        config_content = data.get('config_content')

        if not config_name or not config_content:
            return jsonify({
                'error': 'config_name and config_content are required'
            }), 400

        # Queue the task
        task = deploy_vpn_config_async.delay(config_name, config_content)

        return jsonify({
            'success': True,
            'message': 'VPN configuration deployment queued',
            'task_id': task.id
        }), 202

    except Exception as e:
        logger.error(f"Failed to queue VPN deployment: {e}")
        return jsonify({'error': 'Failed to queue deployment'}), 500


# app.py integration
from flask import Flask
from routes.system_api import system_bp


def create_app():
    app = Flask(__name__)

    # Register the system blueprint
    app.register_blueprint(system_bp)

    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s %(levelname)s %(name)s %(message)s'
    )

    return app


# Usage examples for testing
def example_usage():
    """Example of how to use the system services"""

    # Initialize services
    openvpn_service = SystemServiceFactory.get_openvpn_service()
    cert_service = SystemServiceFactory.get_certificate_service()
    network_service = SystemServiceFactory.get_network_service()

    try:
        # Deploy OpenVPN config
        config_content = """
        client
        dev tun
        proto udp
        remote your-server.com 1194
        ca ca.crt
        cert client.crt
        key client.key
        """

        result = openvpn_service.deploy_config("f2net_client1", config_content)
        print(f"Deploy result: {result}")

        # Start the service
        result = openvpn_service.start_service("f2net_client1")
        print(f"Start result: {result}")

        # Generate certificate
        result = cert_service.generate_client_cert("f2net_client1")
        print(f"Certificate result: {result}")

        # Add iptables rule
        result = network_service.add_iptables_rule([
            '-A', 'FORWARD',
            '-s', '10.8.0.0/24',
            '-j', 'ACCEPT'
        ])
        print(f"Iptables result: {result}")

    except SystemOperationError as e:
        print(f"System operation failed: {e}")