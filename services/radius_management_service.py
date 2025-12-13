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
        logger.info("[DB_CONNECTION] Attempting to connect to RADIUS database", 
                   host=self.radius_db_config.get('host'),
                   port=self.radius_db_config.get('port'),
                   database=self.radius_db_config.get('database'))
        try:
            connection = pymysql.connect(**self.radius_db_config)
            logger.info("[DB_CONNECTION] Successfully connected to RADIUS database")
            try:
                yield connection
            finally:
                logger.info("[DB_CONNECTION] Closing database connection")
                connection.close()
        except Exception as e:
            logger.error("[DB_CONNECTION] Failed to connect to RADIUS database", 
                        error=str(e),
                        config={
                            'host': self.radius_db_config.get('host'),
                            'port': self.radius_db_config.get('port'),
                            'database': self.radius_db_config.get('database'),
                            'user': self.radius_db_config.get('user')
                        },
                        exc_info=True)
            raise

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

    # ==================== HOTSPOT USER AUTHORIZATION ====================

    def authorize_hotspot_user(self, mac_address: str, download_speed: int,
                              upload_speed: int, data_limit: int = None,
                              time_limit: int = None, expires_at: str = None,
                              company_slug: str = None) -> Dict[str, Any]:
        """
        Authorize hotspot user MAC address in RADIUS

        Args:
            mac_address: MAC address (e.g., "AA:BB:CC:DD:EE:FF")
            download_speed: Download speed in bytes/sec
            upload_speed: Upload speed in bytes/sec
            data_limit: Data limit in bytes (optional)
            time_limit: Time limit in seconds (optional)
            expires_at: Expiry datetime ISO string (optional)
            company_slug: Company identifier for multi-tenancy

        Returns:
            Dict with success status
        """
        logger.info("[RADIUS_SERVICE] Starting hotspot user authorization",
                   mac_address=mac_address,
                   company_slug=company_slug,
                   download_speed=download_speed,
                   upload_speed=upload_speed,
                   expires_at=expires_at)

        try:
            logger.info("[RADIUS_SERVICE] Getting database connection...")
            with self.get_db_connection() as conn:
                logger.info("[RADIUS_SERVICE] Database connection established")
                with conn.cursor() as cursor:
                    logger.info("[RADIUS_SERVICE] Database cursor created")
                    
                    # Convert speeds to Mikrotik format (bytes/sec to Mbps)
                    download_mbps = download_speed / (1024 * 1024)  # bytes/sec to MB/sec
                    upload_mbps = upload_speed / (1024 * 1024)     # bytes/sec to MB/sec
                    
                    # Ensure minimum 1M if speed is very low
                    download_mbps = max(1, int(download_mbps))
                    upload_mbps = max(1, int(upload_mbps))
                    
                    rate_limit = f"{upload_mbps}M/{download_mbps}M"
                    
                    logger.info("[RADIUS_SERVICE] Calculated rate limit", 
                               download_mbps=download_mbps,
                               upload_mbps=upload_mbps,
                               rate_limit=rate_limit)

                    # Check if MAC already exists
                    logger.info("[RADIUS_SERVICE] Checking if MAC address exists in radcheck...")
                    cursor.execute("""
                        SELECT id FROM radcheck
                        WHERE username = %s
                    """, (mac_address,))

                    existing_user = cursor.fetchone()
                    logger.info("[RADIUS_SERVICE] MAC address check result", exists=bool(existing_user))

                    if existing_user:
                        logger.info("[RADIUS_SERVICE] Updating existing user...")
                        # Update existing
                        cursor.execute("""
                            UPDATE radcheck
                            SET status = 'active', username_owner = %s
                            WHERE username = %s
                        """, (company_slug, mac_address))
                        logger.info("[RADIUS_SERVICE] Updated radcheck table", rows_affected=cursor.rowcount)

                        # Update rate limit
                        logger.info("[RADIUS_SERVICE] Updating rate limit in radreply...")
                        cursor.execute("""
                            UPDATE radreply
                            SET value = %s
                            WHERE username = %s AND attribute = 'Mikrotik-Rate-Limit'
                        """, (rate_limit, mac_address))
                        
                        update_rows = cursor.rowcount
                        logger.info("[RADIUS_SERVICE] Rate limit update result", rows_affected=update_rows)

                        if update_rows == 0:
                            logger.info("[RADIUS_SERVICE] No existing rate limit found, inserting new one...")
                            cursor.execute("""
                                INSERT INTO radreply (username, attribute, op, value)
                                VALUES (%s, 'Mikrotik-Rate-Limit', ':=', %s)
                            """, (mac_address, rate_limit))
                            logger.info("[RADIUS_SERVICE] Inserted new rate limit")
                    else:
                        logger.info("[RADIUS_SERVICE] Creating new hotspot user...")
                        # Create new hotspot user
                        cursor.execute("""
                            INSERT INTO radcheck (username, attribute, op, value, username_owner, status)
                            VALUES (%s, 'Auth-Type', ':=', 'Accept', %s, 'active')
                        """, (mac_address, company_slug))
                        logger.info("[RADIUS_SERVICE] Inserted into radcheck table")

                        # Add rate limit
                        logger.info("[RADIUS_SERVICE] Adding rate limit to radreply...")
                        cursor.execute("""
                            INSERT INTO radreply (username, attribute, op, value)
                            VALUES (%s, 'Mikrotik-Rate-Limit', ':=', %s)
                        """, (mac_address, rate_limit))
                        logger.info("[RADIUS_SERVICE] Inserted rate limit into radreply")

                    # Add Session-Timeout (static value - FreeRADIUS will calculate dynamic value from expires_at)
                    if time_limit:
                        logger.info("[RADIUS_SERVICE] Adding session timeout", time_limit=time_limit)
                        cursor.execute("""
                            INSERT INTO radreply (username, attribute, op, value)
                            VALUES (%s, 'Session-Timeout', ':=', %s)
                            ON DUPLICATE KEY UPDATE value = %s
                        """, (mac_address, str(time_limit), str(time_limit)))
                        logger.info("[RADIUS_SERVICE] Session timeout added")

                    # Store expires_at timestamp - FreeRADIUS will use this to calculate dynamic timeout
                    if expires_at:
                        logger.info("[RADIUS_SERVICE] Storing expiry timestamp in radcheck", expires_at=expires_at)

                        # Convert ISO 8601 format to MySQL datetime format
                        # Input: "2025-12-08T15:49:51Z" -> Output: "2025-12-08 15:49:51"
                        try:
                            # Parse ISO format (handles both with and without timezone)
                            if expires_at.endswith('Z'):
                                expires_at_clean = expires_at[:-1]  # Remove 'Z'
                            else:
                                expires_at_clean = expires_at

                            dt = datetime.fromisoformat(expires_at_clean)
                            mysql_datetime = dt.strftime('%Y-%m-%d %H:%M:%S')

                            logger.info("[RADIUS_SERVICE] Converted datetime format",
                                       original=expires_at,
                                       mysql_format=mysql_datetime)

                            cursor.execute("""
                                UPDATE radcheck
                                SET expires_at = %s
                                WHERE username = %s
                            """, (mysql_datetime, mac_address))
                            logger.info("[RADIUS_SERVICE] Expiry timestamp stored - FreeRADIUS will calculate remaining time")
                        except (ValueError, AttributeError) as e:
                            logger.error("[RADIUS_SERVICE] Failed to parse expires_at datetime",
                                        expires_at=expires_at,
                                        error=str(e))
                            # Continue without setting expires_at - will use static timeout

                    logger.info("[RADIUS_SERVICE] Committing database transaction...")
                    conn.commit()
                    logger.info("[RADIUS_SERVICE] Database transaction committed successfully")

                    logger.info("[RADIUS_SERVICE] Hotspot user authorized successfully", 
                               mac_address=mac_address, 
                               rate_limit=rate_limit)

                    return {
                        'success': True,
                        'message': 'Hotspot user authorized',
                        'mac_address': mac_address,
                        'rate_limit': rate_limit
                    }

        except Exception as e:
            logger.error("[RADIUS_SERVICE] Failed to authorize hotspot user", 
                        error=str(e), 
                        mac_address=mac_address,
                        company_slug=company_slug,
                        exc_info=True)
            return {
                'success': False,
                'error': f'Failed to authorize hotspot user: {str(e)}'
            }

    # ==================== MIKROTIK RADIUS CLIENT MANAGEMENT ====================

    def lookup_nas_by_ip(self, nas_ip: str) -> Dict[str, Any]:
        """
        Lookup NAS (router) details by IP address from RADIUS nas table

        Args:
            nas_ip: NAS IP address (e.g., "10.8.0.45")

        Returns:
            Dict with NAS details or error
        """
        logger.info("Looking up NAS by IP", nas_ip=nas_ip)

        try:
            with self.get_db_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute("""
                        SELECT nasname, shortname, secret, type
                        FROM nas
                        WHERE nasname = %s
                    """, (nas_ip,))

                    nas = cursor.fetchone()

                    if not nas:
                        logger.warning("NAS not found", nas_ip=nas_ip)
                        return {
                            'success': False,
                            'error': f'NAS with IP {nas_ip} not found in database'
                        }

                    logger.info("NAS found", nas_ip=nas_ip, shortname=nas['shortname'])

                    return {
                        'success': True,
                        'nasname': nas['nasname'],
                        'shortname': nas['shortname'],
                        'secret': nas['secret'],
                        'type': nas['type'],
                        'client_name': nas['shortname']  # Alias for device identity
                    }

        except Exception as e:
            logger.error("NAS lookup failed", error=str(e), exc_info=True)
            return {
                'success': False,
                'error': f'Database error: {str(e)}'
            }

    def register_mikrotik_radius_client(self, username: str, identity: str,
                                       secret: str, ip_address: str) -> Dict[str, Any]:
        """
        Register a MikroTik device as a RADIUS client in FreeRADIUS

        Args:
            username: ISP owner username (e.g., "abutis")
            identity: Unique device identifier (e.g., "abutis_Mikrotik2727")
            secret: RADIUS shared secret for this device
            ip_address: MikroTik device IP address

        Returns:
            Dict with success status
        """
        import subprocess
        import os

        logger.info("Registering MikroTik RADIUS client",
                   username=username, identity=identity, ip_address=ip_address)

        try:
            clients_conf = '/etc/freeradius/3.0/clients.conf'

            # Create client configuration block
            client_config = f"""
# MikroTik for {username} - {identity}
client {identity} {{
    ipaddr = {ip_address}
    secret = {secret}
    shortname = {identity}
    nas_type = other
}}
"""

            # Check if this client already exists
            if os.path.exists(clients_conf):
                with open(clients_conf, 'r') as f:
                    content = f.read()
                    if f'client {identity}' in content:
                        logger.warning("Client already exists, updating...", identity=identity)
                        # Remove old config
                        lines = content.split('\n')
                        new_lines = []
                        skip = False
                        for line in lines:
                            if f'client {identity}' in line:
                                skip = True
                            elif skip and line.strip() == '}':
                                skip = False
                                continue
                            if not skip:
                                new_lines.append(line)
                        content = '\n'.join(new_lines)

                    # Append new config
                    with open(clients_conf, 'w') as fw:
                        fw.write(content)
                        if not content.endswith('\n'):
                            fw.write('\n')
                        fw.write(client_config)
            else:
                # File doesn't exist, create it
                with open(clients_conf, 'w') as f:
                    f.write(client_config)

            # Reload FreeRADIUS to apply changes
            logger.info("Reloading FreeRADIUS service...")
            result = subprocess.run(
                ['/usr/bin/sudo', '/bin/systemctl', 'reload', 'freeradius'],
                capture_output=True,
                text=True,
                timeout=10
            )

            if result.returncode != 0:
                logger.error("Failed to reload FreeRADIUS",
                           stderr=result.stderr, stdout=result.stdout)
                return {
                    'success': False,
                    'error': f'Failed to reload FreeRADIUS: {result.stderr}'
                }

            logger.info("MikroTik RADIUS client registered successfully")

            return {
                'success': True,
                'message': f'MikroTik {identity} registered as RADIUS client',
                'identity': identity,
                'ip_address': ip_address
            }

        except PermissionError:
            logger.error("Permission denied writing to FreeRADIUS config")
            return {
                'success': False,
                'error': 'Permission denied. Ensure Flask app runs with appropriate privileges.'
            }
        except Exception as e:
            logger.error("Failed to register MikroTik RADIUS client",
                        error=str(e), exc_info=True)
            return {
                'success': False,
                'error': f'Failed to register RADIUS client: {str(e)}'
            }

    def register_nas_client(self, nas_ip: str, shortname: str, secret: str,
                           nas_type: str = 'other', description: str = '') -> Dict[str, Any]:
        """
        Register NAS client in RADIUS nas table (for SQL client loading)

        Args:
            nas_ip: NAS IP address (VPN IP like 10.8.0.45)
            shortname: Router identity (e.g., abutis_Mikrotik123)
            secret: RADIUS shared secret
            nas_type: NAS type (default: 'other')
            description: Description of this NAS

        Returns:
            Dict with success status and message
        """
        logger.info("Registering NAS client in SQL table", nas_ip=nas_ip, shortname=shortname)

        try:
            with self.get_db_connection() as conn:
                with conn.cursor() as cursor:
                    # Check if NAS already exists
                    cursor.execute("SELECT id FROM nas WHERE nasname = %s", (nas_ip,))
                    existing = cursor.fetchone()

                    if existing:
                        # Update existing NAS
                        cursor.execute("""
                            UPDATE nas SET shortname = %s, secret = %s,
                                   type = %s, description = %s
                            WHERE nasname = %s
                        """, (shortname, secret, nas_type, description, nas_ip))
                        conn.commit()
                        logger.info("NAS client updated in SQL table", nas_ip=nas_ip)
                        return {
                            'success': True,
                            'message': f'NAS {nas_ip} updated successfully',
                            'nas_ip': nas_ip,
                            'shortname': shortname
                        }
                    else:
                        # Insert new NAS
                        cursor.execute("""
                            INSERT INTO nas (nasname, shortname, secret, type, description)
                            VALUES (%s, %s, %s, %s, %s)
                        """, (nas_ip, shortname, secret, nas_type, description))
                        conn.commit()
                        logger.info("NAS client registered in SQL table", nas_ip=nas_ip)
                        return {
                            'success': True,
                            'message': f'NAS {nas_ip} registered successfully',
                            'nas_ip': nas_ip,
                            'shortname': shortname
                        }

        except Exception as e:
            logger.error("NAS registration failed", error=str(e), exc_info=True)
            return {
                'success': False,
                'error': f'Database error: {str(e)}'
            }

    def unregister_nas_client(self, nas_ip: str) -> Dict[str, Any]:
        """
        Remove NAS client from RADIUS nas table

        Args:
            nas_ip: NAS IP address to remove

        Returns:
            Dict with success status
        """
        logger.info("Unregistering NAS client from SQL table", nas_ip=nas_ip)

        try:
            with self.get_db_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute("DELETE FROM nas WHERE nasname = %s", (nas_ip,))
                    conn.commit()

                    if cursor.rowcount > 0:
                        logger.info("NAS client unregistered from SQL table", nas_ip=nas_ip)
                        return {
                            'success': True,
                            'message': f'NAS {nas_ip} removed successfully'
                        }
                    else:
                        logger.warning("NAS not found in SQL table", nas_ip=nas_ip)
                        return {
                            'success': False,
                            'error': f'NAS {nas_ip} not found'
                        }

        except Exception as e:
            logger.error("NAS unregistration failed", error=str(e), exc_info=True)
            return {
                'success': False,
                'error': f'Database error: {str(e)}'
            }
