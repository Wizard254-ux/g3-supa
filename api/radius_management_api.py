"""
RADIUS Management API Blueprint
Handles package and customer management for multi-tenant RADIUS
"""

from flask import Blueprint, request, jsonify, current_app
import structlog
from typing import Dict, Any

from services.radius_management_service import RadiusManagementService
from utils.decorators import api_endpoint

logger = structlog.get_logger()

# Create blueprint
radius_mgmt_bp = Blueprint('radius_management', __name__)


# ==================== PACKAGE ENDPOINTS ====================

@radius_mgmt_bp.route('/packages', methods=['POST'])
@api_endpoint(
    require_auth=True,
    require_json=True,
    required_fields=['username', 'package_name', 'download_speed', 'upload_speed', 'price']
)
def create_package():
    """
    Create a new bandwidth package

    Request:
    {
        "username": "abutis",
        "package_name": "bronze",
        "download_speed": "5M",
        "upload_speed": "5M",
        "price": 500.00,
        "description": "Bronze package - 5 Mbps"
    }

    Response:
    {
        "success": true,
        "package": {
            "id": 1,
            "username": "abutis",
            "package_name": "bronze",
            "download_speed": "5M",
            "upload_speed": "5M",
            "price": 500.00,
            "description": "Bronze package - 5 Mbps"
        }
    }
    """
    try:
        data = request.get_json()

        username = data['username']
        package_name = data['package_name']
        download_speed = data['download_speed']
        upload_speed = data['upload_speed']
        price = float(data['price'])
        description = data.get('description')

        logger.info("Create package request", username=username, package_name=package_name)

        service = RadiusManagementService(current_app)
        result = service.create_package(
            username=username,
            package_name=package_name,
            download_speed=download_speed,
            upload_speed=upload_speed,
            price=price,
            description=description
        )

        status_code = 200 if result['success'] else 400
        return jsonify(result), status_code

    except ValueError as ve:
        logger.error("Invalid price value", error=str(ve))
        return jsonify({
            'success': False,
            'error': 'Invalid price value'
        }), 400
    except Exception as e:
        logger.error("Create package failed", error=str(e), exc_info=True)
        return jsonify({
            'success': False,
            'error': f'Internal server error: {str(e)}'
        }), 500


@radius_mgmt_bp.route('/packages/list', methods=['POST'])
@api_endpoint(
    require_auth=True,
    require_json=True,
    required_fields=['username']
)
def list_packages():
    """
    List all packages for an ISP owner

    Request:
    {
        "username": "abutis"
    }

    Response:
    {
        "success": true,
        "packages": [
            {
                "id": 1,
                "package_name": "bronze",
                "download_speed": "5M",
                "upload_speed": "5M",
                "price": 500.00,
                "description": "Bronze package",
                "created_at": "2024-01-01 10:00:00"
            }
        ],
        "count": 1
    }
    """
    try:
        data = request.get_json()
        username = data['username']

        logger.info("List packages request", username=username)

        service = RadiusManagementService(current_app)
        result = service.list_packages(username=username)

        status_code = 200 if result['success'] else 400
        return jsonify(result), status_code

    except Exception as e:
        logger.error("List packages failed", error=str(e), exc_info=True)
        return jsonify({
            'success': False,
            'error': f'Internal server error: {str(e)}'
        }), 500


@radius_mgmt_bp.route('/packages/<int:package_id>', methods=['GET'])
@api_endpoint(require_auth=True, require_json=False)
def get_package(package_id):
    """
    Get a specific package

    Query params: ?username=abutis

    Response:
    {
        "success": true,
        "package": {
            "id": 1,
            "package_name": "bronze",
            "download_speed": "5M",
            "upload_speed": "5M",
            "price": 500.00
        }
    }
    """
    try:
        username = request.args.get('username')
        if not username:
            return jsonify({
                'success': False,
                'error': 'Missing username parameter'
            }), 400

        logger.info("Get package request", username=username, package_id=package_id)

        service = RadiusManagementService(current_app)
        result = service.get_package(username=username, package_id=package_id)

        status_code = 200 if result['success'] else 404
        return jsonify(result), status_code

    except Exception as e:
        logger.error("Get package failed", error=str(e), exc_info=True)
        return jsonify({
            'success': False,
            'error': f'Internal server error: {str(e)}'
        }), 500


@radius_mgmt_bp.route('/packages/<int:package_id>', methods=['PUT'])
@api_endpoint(
    require_auth=True,
    require_json=True,
    required_fields=['username']
)
def update_package(package_id):
    """
    Update a package

    Request:
    {
        "username": "abutis",
        "download_speed": "10M",
        "upload_speed": "10M",
        "price": 800.00
    }

    Response:
    {
        "success": true,
        "message": "Package updated successfully"
    }
    """
    try:
        data = request.get_json()
        username = data['username']

        logger.info("Update package request", username=username, package_id=package_id)

        service = RadiusManagementService(current_app)
        result = service.update_package(
            username=username,
            package_id=package_id,
            download_speed=data.get('download_speed'),
            upload_speed=data.get('upload_speed'),
            price=data.get('price'),
            description=data.get('description')
        )

        status_code = 200 if result['success'] else 400
        return jsonify(result), status_code

    except Exception as e:
        logger.error("Update package failed", error=str(e), exc_info=True)
        return jsonify({
            'success': False,
            'error': f'Internal server error: {str(e)}'
        }), 500


@radius_mgmt_bp.route('/packages/<int:package_id>', methods=['DELETE'])
@api_endpoint(require_auth=True, require_json=False)
def delete_package(package_id):
    """
    Delete a package

    Query params: ?username=abutis

    Response:
    {
        "success": true,
        "message": "Package deleted successfully"
    }
    """
    try:
        username = request.args.get('username')
        if not username:
            return jsonify({
                'success': False,
                'error': 'Missing username parameter'
            }), 400

        logger.info("Delete package request", username=username, package_id=package_id)

        service = RadiusManagementService(current_app)
        result = service.delete_package(username=username, package_id=package_id)

        status_code = 200 if result['success'] else 400
        return jsonify(result), status_code

    except Exception as e:
        logger.error("Delete package failed", error=str(e), exc_info=True)
        return jsonify({
            'success': False,
            'error': f'Internal server error: {str(e)}'
        }), 500


# ==================== CUSTOMER ENDPOINTS ====================

@radius_mgmt_bp.route('/customers', methods=['POST'])
@api_endpoint(
    require_auth=True,
    require_json=True,
    required_fields=['username', 'customer_username', 'password']
)
def create_customer():
    """
    Create a new RADIUS customer (with or without package)

    Request (with package - create and assign):
    {
        "username": "abutis",
        "customer_username": "john",
        "password": "secret123",
        "package_id": 1
    }

    Request (without package - just create account):
    {
        "username": "abutis",
        "customer_username": "john",
        "password": "secret123"
    }

    Response:
    {
        "success": true,
        "customer": {
            "id": 1,
            "username": "john@abutis",
            "package_id": 1,
            "rate_limit": "5M/5M",
            "status": "active"
        }
    }
    """
    try:
        data = request.get_json()

        username = data['username']
        customer_username = data['customer_username']
        password = data['password']
        package_id = data.get('package_id')  # Optional

        # Convert to int if provided
        if package_id is not None:
            package_id = int(package_id)

        logger.info("Create customer request", username=username,
                   customer_username=customer_username)

        service = RadiusManagementService(current_app)
        result = service.create_customer(
            username=username,
            customer_username=customer_username,
            password=password,
            package_id=package_id
        )

        status_code = 200 if result['success'] else 400
        return jsonify(result), status_code

    except ValueError as ve:
        logger.error("Invalid package_id value", error=str(ve))
        return jsonify({
            'success': False,
            'error': 'Invalid package_id value'
        }), 400
    except Exception as e:
        logger.error("Create customer failed", error=str(e), exc_info=True)
        return jsonify({
            'success': False,
            'error': f'Internal server error: {str(e)}'
        }), 500


@radius_mgmt_bp.route('/customers/list', methods=['POST'])
@api_endpoint(
    require_auth=True,
    require_json=True,
    required_fields=['username']
)
def list_customers():
    """
    List all customers for an ISP owner

    Request:
    {
        "username": "abutis",
        "status": "active"  // optional: active, suspended, expired
    }

    Response:
    {
        "success": true,
        "customers": [
            {
                "id": 1,
                "username": "john@abutis",
                "package_id": 1,
                "package_name": "bronze",
                "download_speed": "5M",
                "upload_speed": "5M",
                "price": 500.00,
                "status": "active",
                "created_at": "2024-01-01 10:00:00"
            }
        ],
        "count": 1
    }
    """
    try:
        data = request.get_json()
        username = data['username']
        status = data.get('status')

        logger.info("List customers request", username=username, status=status)

        service = RadiusManagementService(current_app)
        result = service.list_customers(username=username, status=status)

        status_code = 200 if result['success'] else 400
        return jsonify(result), status_code

    except Exception as e:
        logger.error("List customers failed", error=str(e), exc_info=True)
        return jsonify({
            'success': False,
            'error': f'Internal server error: {str(e)}'
        }), 500


@radius_mgmt_bp.route('/customers/<customer_username>', methods=['GET'])
@api_endpoint(require_auth=True, require_json=False)
def get_customer(customer_username):
    """
    Get a specific customer

    Query params: ?username=abutis

    Response:
    {
        "success": true,
        "customer": {
            "id": 1,
            "username": "john@abutis",
            "package_id": 1,
            "package_name": "bronze",
            "status": "active"
        }
    }
    """
    try:
        username = request.args.get('username')
        if not username:
            return jsonify({
                'success': False,
                'error': 'Missing username parameter'
            }), 400

        logger.info("Get customer request", username=username,
                   customer_username=customer_username)

        service = RadiusManagementService(current_app)
        result = service.get_customer(username=username,
                                      customer_username=customer_username)

        status_code = 200 if result['success'] else 404
        return jsonify(result), status_code

    except Exception as e:
        logger.error("Get customer failed", error=str(e), exc_info=True)
        return jsonify({
            'success': False,
            'error': f'Internal server error: {str(e)}'
        }), 500


@radius_mgmt_bp.route('/customers/<customer_username>/package', methods=['PUT'])
@api_endpoint(
    require_auth=True,
    require_json=True,
    required_fields=['username', 'package_id']
)
def update_customer_package(customer_username):
    """
    Update a customer's package (change speed)

    Request:
    {
        "username": "abutis",
        "package_id": 2
    }

    Response:
    {
        "success": true,
        "message": "Customer package updated successfully",
        "new_rate_limit": "10M/10M"
    }
    """
    try:
        data = request.get_json()
        username = data['username']
        package_id = int(data['package_id'])

        logger.info("Update customer package request", username=username,
                   customer_username=customer_username, package_id=package_id)

        service = RadiusManagementService(current_app)
        result = service.update_customer_package(
            username=username,
            customer_username=customer_username,
            package_id=package_id
        )

        status_code = 200 if result['success'] else 400
        return jsonify(result), status_code

    except ValueError as ve:
        logger.error("Invalid package_id value", error=str(ve))
        return jsonify({
            'success': False,
            'error': 'Invalid package_id value'
        }), 400
    except Exception as e:
        logger.error("Update customer package failed", error=str(e), exc_info=True)
        return jsonify({
            'success': False,
            'error': f'Internal server error: {str(e)}'
        }), 500


@radius_mgmt_bp.route('/customers/<customer_username>/password', methods=['PUT'])
@api_endpoint(
    require_auth=True,
    require_json=True,
    required_fields=['username', 'new_password']
)
def update_customer_password(customer_username):
    """
    Update a customer's password

    Request:
    {
        "username": "abutis",
        "new_password": "newpass456"
    }

    Response:
    {
        "success": true,
        "message": "Customer password updated successfully"
    }
    """
    try:
        data = request.get_json()
        username = data['username']
        new_password = data['new_password']

        logger.info("Update customer password request", username=username,
                   customer_username=customer_username)

        service = RadiusManagementService(current_app)
        result = service.update_customer_password(
            username=username,
            customer_username=customer_username,
            new_password=new_password
        )

        status_code = 200 if result['success'] else 400
        return jsonify(result), status_code

    except Exception as e:
        logger.error("Update customer password failed", error=str(e), exc_info=True)
        return jsonify({
            'success': False,
            'error': f'Internal server error: {str(e)}'
        }), 500


@radius_mgmt_bp.route('/customers/<customer_username>/status', methods=['PUT'])
@api_endpoint(
    require_auth=True,
    require_json=True,
    required_fields=['username', 'status']
)
def update_customer_status(customer_username):
    """
    Update a customer's status

    Request:
    {
        "username": "abutis",
        "status": "suspended"  // active, suspended, expired
    }

    Response:
    {
        "success": true,
        "message": "Customer status updated to suspended"
    }
    """
    try:
        data = request.get_json()
        username = data['username']
        status = data['status']

        logger.info("Update customer status request", username=username,
                   customer_username=customer_username, status=status)

        service = RadiusManagementService(current_app)
        result = service.update_customer_status(
            username=username,
            customer_username=customer_username,
            status=status
        )

        status_code = 200 if result['success'] else 400
        return jsonify(result), status_code

    except Exception as e:
        logger.error("Update customer status failed", error=str(e), exc_info=True)
        return jsonify({
            'success': False,
            'error': f'Internal server error: {str(e)}'
        }), 500


@radius_mgmt_bp.route('/customers/<customer_username>', methods=['DELETE'])
@api_endpoint(require_auth=True, require_json=False)
def delete_customer(customer_username):
    """
    Delete a customer

    Query params: ?username=abutis

    Response:
    {
        "success": true,
        "message": "Customer deleted successfully"
    }
    """
    try:
        username = request.args.get('username')
        if not username:
            return jsonify({
                'success': False,
                'error': 'Missing username parameter'
            }), 400

        logger.info("Delete customer request", username=username,
                   customer_username=customer_username)

        service = RadiusManagementService(current_app)
        result = service.delete_customer(username=username,
                                        customer_username=customer_username)

        status_code = 200 if result['success'] else 400
        return jsonify(result), status_code

    except Exception as e:
        logger.error("Delete customer failed", error=str(e), exc_info=True)
        return jsonify({
            'success': False,
            'error': f'Internal server error: {str(e)}'
        }), 500


# ==================== HOTSPOT AUTHORIZATION ENDPOINT ====================

@radius_mgmt_bp.route('/hotspot/authorize', methods=['POST'])
@api_endpoint(
    require_auth=True,
    require_json=True,
    required_fields=['mac_address', 'download_speed', 'upload_speed', 'company_slug']
)
def authorize_hotspot():
    """
    Authorize hotspot user MAC address in RADIUS

    Request:
    {
        "mac_address": "AA:BB:CC:DD:EE:FF",
        "download_speed": 10485760,
        "upload_speed": 5242880,
        "data_limit": 1073741824,
        "time_limit": 3600,
        "expires_at": "2025-01-20T10:00:00Z",
        "company_slug": "abutis"
    }

    Response:
    {
        "success": true,
        "message": "Hotspot user authorized",
        "mac_address": "AA:BB:CC:DD:EE:FF",
        "rate_limit": "5M/10M"
    }
    """
    try:
        data = request.get_json()
        
        mac_address = data['mac_address']
        download_speed = data['download_speed']
        upload_speed = data['upload_speed']
        data_limit = data.get('data_limit')
        time_limit = data.get('time_limit')
        expires_at = data.get('expires_at')
        company_slug = data['company_slug']

        logger.info("Authorize hotspot request", mac_address=mac_address, company_slug=company_slug)

        service = RadiusManagementService(current_app)
        result = service.authorize_hotspot_user(
            mac_address=mac_address,
            download_speed=download_speed,
            upload_speed=upload_speed,
            data_limit=data_limit,
            time_limit=time_limit,
            expires_at=expires_at,
            company_slug=company_slug
        )

        status_code = 200 if result['success'] else 400
        return jsonify(result), status_code

    except Exception as e:
        logger.error("Authorize hotspot failed", error=str(e), exc_info=True)
        return jsonify({
            'success': False,
            'error': f'Internal server error: {str(e)}'
        }), 500


# ==================== MIKROTIK RADIUS CLIENT ENDPOINTS ====================

@radius_mgmt_bp.route('/register-mikrotik', methods=['POST'])
@api_endpoint(
    require_auth=True,
    require_json=True,
    required_fields=['username', 'identity', 'secret', 'ip_address']
)
def register_mikrotik():
    """
    Register a MikroTik device as a RADIUS client

    Request body:
    {
        "username": "abutis",
        "identity": "abutis_Mikrotik2727",
        "secret": "dZ9YIY1Ymc0j1NII",
        "ip_address": "41.90.x.x"
    }

    Response:
    {
        "success": true,
        "message": "MikroTik abutis_Mikrotik2727 registered as RADIUS client",
        "identity": "abutis_Mikrotik2727",
        "ip_address": "41.90.x.x"
    }
    """
    try:
        data = request.get_json()
        username = data['username']
        identity = data['identity']
        secret = data['secret']
        ip_address = data['ip_address']

        logger.info("Register MikroTik request",
                   username=username, identity=identity, ip_address=ip_address)

        service = RadiusManagementService(current_app)
        result = service.register_mikrotik_radius_client(
            username=username,
            identity=identity,
            secret=secret,
            ip_address=ip_address
        )

        status_code = 200 if result['success'] else 400
        return jsonify(result), status_code

    except Exception as e:
        logger.error("Register MikroTik failed", error=str(e), exc_info=True)
        return jsonify({
            'success': False,
            'error': f'Internal server error: {str(e)}'
        }), 500
