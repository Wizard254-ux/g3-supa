"""
RADIUS Management Service for ISP Middleware
Handles RADIUS packages and customer management with multi-tenant support
"""

import structlog
from datetime import datetime
from typing import Dict, List, Optional, Any
import pymysql
from contextlib import contextmanager

logger = structlog.get_logger()


class RadiusManagementService:
    """Service for managing RADIUS packages and customers with username-based multi-tenancy"""

    def __init__(self, app=None):
        self.app = app
        self.radius_db_config = None

        if app:
            self.init_app(app)

    def init_app(self, app):
        """Initialize the service with Flask app"""
        self.app = app
        self.radius_db_config = {
            'host': app.config.get('RADIUS_DB_HOST', 'localhost'),
            'port': app.config.get('RADIUS_DB_PORT', 3306),
            'user': app.config.get('RADIUS_DB_USER', 'radius'),
            'password': app.config.get('RADIUS_DB_PASS', ''),
            'database': app.config.get('RADIUS_DB_NAME', 'radius'),
            'charset': 'utf8mb4',
            'cursorclass': pymysql.cursors.DictCursor
        }

    @contextmanager
    def get_db_connection(self):
        """Context manager for database connections"""
        connection = pymysql.connect(**self.radius_db_config)
        try:
            yield connection
        finally:
            connection.close()

    # ==================== PACKAGE MANAGEMENT ====================

    def create_package(self, username: str, package_name: str, download_speed: str,
                      upload_speed: str, price: float, description: str = None) -> Dict[str, Any]:
        """
        Create a new bandwidth package for an ISP owner

        Args:
            username: ISP owner username
            package_name: Name of the package (e.g., 'bronze', '5mbps')
            download_speed: Download speed (e.g., '5M', '10M')
            upload_speed: Upload speed (e.g., '5M', '10M')
            price: Package price
            description: Optional description

        Returns:
            Dict with success status and package details
        """
        logger.info("Creating package", username=username, package_name=package_name)

        try:
            with self.get_db_connection() as conn:
                with conn.cursor() as cursor:
                    # Check if package already exists for this username
                    cursor.execute("""
                        SELECT id FROM packages
                        WHERE username = %s AND package_name = %s
                    """, (username, package_name))

                    if cursor.fetchone():
                        return {
                            'success': False,
                            'error': f'Package "{package_name}" already exists for user {username}'
                        }

                    # Create package
                    cursor.execute("""
                        INSERT INTO packages
                        (username, package_name, download_speed, upload_speed, description, price)
                        VALUES (%s, %s, %s, %s, %s, %s)
                    """, (username, package_name, download_speed, upload_speed, description, price))

                    conn.commit()
                    package_id = cursor.lastrowid

                    logger.info("Package created successfully", package_id=package_id)

                    return {
                        'success': True,
                        'package': {
                            'id': package_id,
                            'username': username,
                            'package_name': package_name,
                            'download_speed': download_speed,
                            'upload_speed': upload_speed,
                            'price': price,
                            'description': description
                        }
                    }

        except Exception as e:
            logger.error("Failed to create package", error=str(e), exc_info=True)
            return {
                'success': False,
                'error': f'Failed to create package: {str(e)}'
            }

    def list_packages(self, username: str) -> Dict[str, Any]:
        """
        List all packages for an ISP owner

        Args:
            username: ISP owner username

        Returns:
            Dict with success status and list of packages
        """
        logger.info("Listing packages", username=username)

        try:
            with self.get_db_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute("""
                        SELECT id, package_name, download_speed, upload_speed,
                               description, price, created_at, updated_at
                        FROM packages
                        WHERE username = %s
                        ORDER BY package_name
                    """, (username,))

                    packages = cursor.fetchall()

                    logger.info("Packages retrieved", count=len(packages))

                    return {
                        'success': True,
                        'packages': packages,
                        'count': len(packages)
                    }

        except Exception as e:
            logger.error("Failed to list packages", error=str(e), exc_info=True)
            return {
                'success': False,
                'error': f'Failed to list packages: {str(e)}'
            }

    def get_package(self, username: str, package_id: int) -> Dict[str, Any]:
        """
        Get a specific package by ID (with ownership verification)

        Args:
            username: ISP owner username
            package_id: Package ID

        Returns:
            Dict with success status and package details
        """
        logger.info("Getting package", username=username, package_id=package_id)

        try:
            with self.get_db_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute("""
                        SELECT id, package_name, download_speed, upload_speed,
                               description, price, created_at, updated_at
                        FROM packages
                        WHERE id = %s AND username = %s
                    """, (package_id, username))

                    package = cursor.fetchone()

                    if not package:
                        return {
                            'success': False,
                            'error': 'Package not found or does not belong to you'
                        }

                    return {
                        'success': True,
                        'package': package
                    }

        except Exception as e:
            logger.error("Failed to get package", error=str(e), exc_info=True)
            return {
                'success': False,
                'error': f'Failed to get package: {str(e)}'
            }

    def update_package(self, username: str, package_id: int,
                      download_speed: str = None, upload_speed: str = None,
                      price: float = None, description: str = None) -> Dict[str, Any]:
        """
        Update an existing package

        Args:
            username: ISP owner username
            package_id: Package ID
            download_speed: New download speed (optional)
            upload_speed: New upload speed (optional)
            price: New price (optional)
            description: New description (optional)

        Returns:
            Dict with success status
        """
        logger.info("Updating package", username=username, package_id=package_id)

        try:
            with self.get_db_connection() as conn:
                with conn.cursor() as cursor:
                    # Verify ownership
                    cursor.execute("""
                        SELECT id FROM packages
                        WHERE id = %s AND username = %s
                    """, (package_id, username))

                    if not cursor.fetchone():
                        return {
                            'success': False,
                            'error': 'Package not found or does not belong to you'
                        }

                    # Build update query dynamically
                    updates = []
                    params = []

                    if download_speed is not None:
                        updates.append("download_speed = %s")
                        params.append(download_speed)

                    if upload_speed is not None:
                        updates.append("upload_speed = %s")
                        params.append(upload_speed)

                    if price is not None:
                        updates.append("price = %s")
                        params.append(price)

                    if description is not None:
                        updates.append("description = %s")
                        params.append(description)

                    if not updates:
                        return {
                            'success': False,
                            'error': 'No fields to update'
                        }

                    params.extend([package_id, username])

                    query = f"""
                        UPDATE packages
                        SET {', '.join(updates)}
                        WHERE id = %s AND username = %s
                    """

                    cursor.execute(query, params)
                    conn.commit()

                    logger.info("Package updated successfully")

                    return {
                        'success': True,
                        'message': 'Package updated successfully'
                    }

        except Exception as e:
            logger.error("Failed to update package", error=str(e), exc_info=True)
            return {
                'success': False,
                'error': f'Failed to update package: {str(e)}'
            }

    def delete_package(self, username: str, package_id: int) -> Dict[str, Any]:
        """
        Delete a package (only if no customers are using it)

        Args:
            username: ISP owner username
            package_id: Package ID

        Returns:
            Dict with success status
        """
        logger.info("Deleting package", username=username, package_id=package_id)

        try:
            with self.get_db_connection() as conn:
                with conn.cursor() as cursor:
                    # Verify ownership
                    cursor.execute("""
                        SELECT id FROM packages
                        WHERE id = %s AND username = %s
                    """, (package_id, username))

                    if not cursor.fetchone():
                        return {
                            'success': False,
                            'error': 'Package not found or does not belong to you'
                        }

                    # Check if any customers are using this package
                    cursor.execute("""
                        SELECT COUNT(*) as count FROM radcheck
                        WHERE package_id = %s AND username_owner = %s
                    """, (package_id, username))

                    result = cursor.fetchone()
                    if result['count'] > 0:
                        return {
                            'success': False,
                            'error': f'Cannot delete package: {result["count"]} customers are using it'
                        }

                    # Delete package
                    cursor.execute("""
                        DELETE FROM packages
                        WHERE id = %s AND username = %s
                    """, (package_id, username))

                    conn.commit()

                    logger.info("Package deleted successfully")

                    return {
                        'success': True,
                        'message': 'Package deleted successfully'
                    }

        except Exception as e:
            logger.error("Failed to delete package", error=str(e), exc_info=True)
            return {
                'success': False,
                'error': f'Failed to delete package: {str(e)}'
            }

    # ==================== CUSTOMER MANAGEMENT ====================

    def create_customer(self, username: str, customer_username: str,
                       password: str, package_id: int = None) -> Dict[str, Any]:
        """
        Create a new RADIUS customer (with or without package assignment)

        Args:
            username: ISP owner username
            customer_username: Customer's username (will be appended with @username)
            password: Customer's password
            package_id: Package ID to assign (optional - can assign later)

        Returns:
            Dict with success status and customer details
        """
        logger.info("Creating customer", username=username, customer_username=customer_username,
                   package_id=package_id)

        try:
            with self.get_db_connection() as conn:
                with conn.cursor() as cursor:
                    package = None
                    rate_limit = None

                    # If package_id provided, verify it belongs to this username
                    if package_id is not None:
                        cursor.execute("""
                            SELECT id, download_speed, upload_speed FROM packages
                            WHERE id = %s AND username = %s
                        """, (package_id, username))

                        package = cursor.fetchone()
                        if not package:
                            return {
                                'success': False,
                                'error': 'Package not found or does not belong to you'
                            }
                        rate_limit = f"{package['download_speed']}/{package['upload_speed']}"

                    # Build full customer username with realm
                    full_username = f"{customer_username}@{username}"

                    # Check if customer already exists
                    cursor.execute("""
                        SELECT id FROM radcheck
                        WHERE username = %s
                    """, (full_username,))

                    if cursor.fetchone():
                        return {
                            'success': False,
                            'error': f'Customer "{full_username}" already exists'
                        }

                    # Insert customer into radcheck
                    cursor.execute("""
                        INSERT INTO radcheck
                        (username, attribute, op, value, username_owner, package_id, status)
                        VALUES (%s, 'Cleartext-Password', ':=', %s, %s, %s, 'active')
                    """, (full_username, password, username, package_id))

                    customer_id = cursor.lastrowid

                    # Insert rate limit into radreply ONLY if package assigned
                    if rate_limit:
                        cursor.execute("""
                            INSERT INTO radreply
                            (username, attribute, op, value)
                            VALUES (%s, 'Mikrotik-Rate-Limit', ':=', %s)
                        """, (full_username, rate_limit))

                    conn.commit()

                    logger.info("Customer created successfully", customer_id=customer_id,
                              full_username=full_username, has_package=package is not None)

                    response = {
                        'success': True,
                        'customer': {
                            'id': customer_id,
                            'username': full_username,
                            'package_id': package_id,
                            'status': 'active'
                        }
                    }

                    if rate_limit:
                        response['customer']['rate_limit'] = rate_limit
                    else:
                        response['customer']['rate_limit'] = None
                        response['message'] = 'Customer created without package. Assign package later.'

                    return response

        except Exception as e:
            logger.error("Failed to create customer", error=str(e), exc_info=True)
            return {
                'success': False,
                'error': f'Failed to create customer: {str(e)}'
            }

    def list_customers(self, username: str, status: str = None) -> Dict[str, Any]:
        """
        List all customers for an ISP owner

        Args:
            username: ISP owner username
            status: Optional filter by status (active, suspended, expired)

        Returns:
            Dict with success status and list of customers
        """
        logger.info("Listing customers", username=username, status=status)

        try:
            with self.get_db_connection() as conn:
                with conn.cursor() as cursor:
                    query = """
                        SELECT
                            rc.id,
                            rc.username,
                            rc.package_id,
                            rc.status,
                            rc.created_at,
                            p.package_name,
                            p.download_speed,
                            p.upload_speed,
                            p.price
                        FROM radcheck rc
                        LEFT JOIN packages p ON rc.package_id = p.id
                        WHERE rc.username_owner = %s
                    """
                    params = [username]

                    if status:
                        query += " AND rc.status = %s"
                        params.append(status)

                    query += " ORDER BY rc.username"

                    cursor.execute(query, params)
                    customers = cursor.fetchall()

                    logger.info("Customers retrieved", count=len(customers))

                    return {
                        'success': True,
                        'customers': customers,
                        'count': len(customers)
                    }

        except Exception as e:
            logger.error("Failed to list customers", error=str(e), exc_info=True)
            return {
                'success': False,
                'error': f'Failed to list customers: {str(e)}'
            }

    def get_customer(self, username: str, customer_username: str) -> Dict[str, Any]:
        """
        Get a specific customer's details

        Args:
            username: ISP owner username
            customer_username: Full customer username (with @realm)

        Returns:
            Dict with success status and customer details
        """
        logger.info("Getting customer", username=username, customer_username=customer_username)

        try:
            with self.get_db_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute("""
                        SELECT
                            rc.id,
                            rc.username,
                            rc.package_id,
                            rc.status,
                            rc.created_at,
                            p.package_name,
                            p.download_speed,
                            p.upload_speed,
                            p.price
                        FROM radcheck rc
                        LEFT JOIN packages p ON rc.package_id = p.id
                        WHERE rc.username = %s AND rc.username_owner = %s
                    """, (customer_username, username))

                    customer = cursor.fetchone()

                    if not customer:
                        return {
                            'success': False,
                            'error': 'Customer not found or does not belong to you'
                        }

                    return {
                        'success': True,
                        'customer': customer
                    }

        except Exception as e:
            logger.error("Failed to get customer", error=str(e), exc_info=True)
            return {
                'success': False,
                'error': f'Failed to get customer: {str(e)}'
            }

    def update_customer_package(self, username: str, customer_username: str,
                               package_id: int) -> Dict[str, Any]:
        """
        Update a customer's package (changes their speed)

        Args:
            username: ISP owner username
            customer_username: Full customer username
            package_id: New package ID

        Returns:
            Dict with success status
        """
        logger.info("Updating customer package", username=username,
                   customer_username=customer_username, package_id=package_id)

        try:
            with self.get_db_connection() as conn:
                with conn.cursor() as cursor:
                    # Verify package belongs to this username
                    cursor.execute("""
                        SELECT id, download_speed, upload_speed FROM packages
                        WHERE id = %s AND username = %s
                    """, (package_id, username))

                    package = cursor.fetchone()
                    if not package:
                        return {
                            'success': False,
                            'error': 'Package not found or does not belong to you'
                        }

                    # Verify customer belongs to this username
                    cursor.execute("""
                        SELECT id FROM radcheck
                        WHERE username = %s AND username_owner = %s
                    """, (customer_username, username))

                    if not cursor.fetchone():
                        return {
                            'success': False,
                            'error': 'Customer not found or does not belong to you'
                        }

                    # Update package in radcheck
                    cursor.execute("""
                        UPDATE radcheck
                        SET package_id = %s
                        WHERE username = %s AND username_owner = %s
                    """, (package_id, customer_username, username))

                    # Update rate limit in radreply
                    rate_limit = f"{package['download_speed']}/{package['upload_speed']}"
                    cursor.execute("""
                        UPDATE radreply
                        SET value = %s
                        WHERE username = %s AND attribute = 'Mikrotik-Rate-Limit'
                    """, (rate_limit, customer_username))

                    if cursor.rowcount == 0:
                        # Insert if doesn't exist
                        cursor.execute("""
                            INSERT INTO radreply
                            (username, attribute, op, value)
                            VALUES (%s, 'Mikrotik-Rate-Limit', ':=', %s)
                        """, (customer_username, rate_limit))

                    conn.commit()

                    logger.info("Customer package updated successfully")

                    return {
                        'success': True,
                        'message': 'Customer package updated successfully',
                        'new_rate_limit': rate_limit
                    }

        except Exception as e:
            logger.error("Failed to update customer package", error=str(e), exc_info=True)
            return {
                'success': False,
                'error': f'Failed to update customer package: {str(e)}'
            }

    def update_customer_password(self, username: str, customer_username: str,
                                new_password: str) -> Dict[str, Any]:
        """
        Update a customer's password

        Args:
            username: ISP owner username
            customer_username: Full customer username
            new_password: New password

        Returns:
            Dict with success status
        """
        logger.info("Updating customer password", username=username,
                   customer_username=customer_username)

        try:
            with self.get_db_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute("""
                        UPDATE radcheck
                        SET value = %s
                        WHERE username = %s AND username_owner = %s AND attribute = 'Cleartext-Password'
                    """, (new_password, customer_username, username))

                    if cursor.rowcount == 0:
                        return {
                            'success': False,
                            'error': 'Customer not found or does not belong to you'
                        }

                    conn.commit()

                    logger.info("Customer password updated successfully")

                    return {
                        'success': True,
                        'message': 'Customer password updated successfully'
                    }

        except Exception as e:
            logger.error("Failed to update customer password", error=str(e), exc_info=True)
            return {
                'success': False,
                'error': f'Failed to update customer password: {str(e)}'
            }

    def update_customer_status(self, username: str, customer_username: str,
                              status: str) -> Dict[str, Any]:
        """
        Update a customer's status (active, suspended, expired)

        Args:
            username: ISP owner username
            customer_username: Full customer username
            status: New status (active, suspended, expired)

        Returns:
            Dict with success status
        """
        logger.info("Updating customer status", username=username,
                   customer_username=customer_username, status=status)

        if status not in ['active', 'suspended', 'expired']:
            return {
                'success': False,
                'error': 'Invalid status. Must be one of: active, suspended, expired'
            }

        try:
            with self.get_db_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute("""
                        UPDATE radcheck
                        SET status = %s
                        WHERE username = %s AND username_owner = %s
                    """, (status, customer_username, username))

                    if cursor.rowcount == 0:
                        return {
                            'success': False,
                            'error': 'Customer not found or does not belong to you'
                        }

                    conn.commit()

                    logger.info("Customer status updated successfully")

                    return {
                        'success': True,
                        'message': f'Customer status updated to {status}'
                    }

        except Exception as e:
            logger.error("Failed to update customer status", error=str(e), exc_info=True)
            return {
                'success': False,
                'error': f'Failed to update customer status: {str(e)}'
            }

    def delete_customer(self, username: str, customer_username: str) -> Dict[str, Any]:
        """
        Delete a customer

        Args:
            username: ISP owner username
            customer_username: Full customer username

        Returns:
            Dict with success status
        """
        logger.info("Deleting customer", username=username, customer_username=customer_username)

        try:
            with self.get_db_connection() as conn:
                with conn.cursor() as cursor:
                    # Delete from radcheck
                    cursor.execute("""
                        DELETE FROM radcheck
                        WHERE username = %s AND username_owner = %s
                    """, (customer_username, username))

                    if cursor.rowcount == 0:
                        return {
                            'success': False,
                            'error': 'Customer not found or does not belong to you'
                        }

                    # Delete from radreply
                    cursor.execute("""
                        DELETE FROM radreply
                        WHERE username = %s
                    """, (customer_username,))

                    conn.commit()

                    logger.info("Customer deleted successfully")

                    return {
                        'success': True,
                        'message': 'Customer deleted successfully'
                    }

        except Exception as e:
            logger.error("Failed to delete customer", error=str(e), exc_info=True)
            return {
                'success': False,
                'error': f'Failed to delete customer: {str(e)}'
            }
