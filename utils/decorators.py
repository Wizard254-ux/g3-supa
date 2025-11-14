"""
Utility decorators for ISP Middleware Flask Application
"""

from functools import wraps
from flask import request, jsonify, current_app, g
import structlog
from datetime import datetime
import time
import ipaddress

logger = structlog.get_logger()


def require_api_key(f):
    """
    Decorator to require API key authentication
    """

    @wraps(f)
    def decorated_function(*args, **kwargs):
        api_key_header = current_app.config.get('API_KEY_HEADER', 'X-API-Key')
        provided_key = request.headers.get(api_key_header)
        expected_key = current_app.config.get('DJANGO_API_KEY')

        if not provided_key:
            logger.warning("API request without key", endpoint=request.endpoint)
            return jsonify({
                'error': 'API key required',
                'message': f'Please provide API key in {api_key_header} header'
            }), 401

        if not expected_key or provided_key != expected_key:
            logger.warning(
                "API request with invalid key",
                endpoint=request.endpoint,
                provided_key_prefix=provided_key[:8] + "..." if provided_key else None
            )
            return jsonify({
                'error': 'Invalid API key',
                'message': 'The provided API key is not valid'
            }), 403

        return f(*args, **kwargs)

    return decorated_function


def require_ip_whitelist(f):
    """
    Decorator to require IP address to be in whitelist
    """

    @wraps(f)
    def decorated_function(*args, **kwargs):
        client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.environ.get('REMOTE_ADDR'))

        # Get allowed IPs from config
        allowed_ips = current_app.config.get('ALLOWED_IPS', [])

        if not allowed_ips:
            # If no whitelist is configured, allow all
            return f(*args, **kwargs)

        # Check if client IP is in whitelist
        try:
            client_ip_obj = ipaddress.ip_address(client_ip)

            for allowed_ip in allowed_ips:
                if '/' in allowed_ip:
                    # CIDR notation
                    if client_ip_obj in ipaddress.ip_network(allowed_ip, strict=False):
                        return f(*args, **kwargs)
                else:
                    # Single IP
                    if client_ip_obj == ipaddress.ip_address(allowed_ip):
                        return f(*args, **kwargs)

            logger.warning(
                "Request from non-whitelisted IP",
                client_ip=client_ip,
                endpoint=request.endpoint
            )

            return jsonify({
                'error': 'Access denied',
                'message': 'Your IP address is not authorized'
            }), 403

        except ValueError as e:
            logger.error("Invalid IP address format", client_ip=client_ip, error=str(e))
            return jsonify({
                'error': 'Invalid request',
                'message': 'Unable to determine client IP'
            }), 400

    return decorated_function


def log_api_call(f):
    """
    Decorator to log API calls with timing and details
    """

    @wraps(f)
    def decorated_function(*args, **kwargs):
        start_time = time.time()

        # Get client information
        client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.environ.get('REMOTE_ADDR'))
        user_agent = request.headers.get('User-Agent', 'Unknown')

        # Log request start
        logger.info(
            "API request started",
            endpoint=request.endpoint,
            method=request.method,
            client_ip=client_ip,
            user_agent=user_agent,
            content_length=request.content_length
        )

        try:
            # Execute the function
            result = f(*args, **kwargs)

            # Calculate execution time
            execution_time = time.time() - start_time

            # Determine response status
            if isinstance(result, tuple) and len(result) >= 2:
                status_code = result[1]
            else:
                status_code = 200

            # Log successful completion
            logger.info(
                "API request completed",
                endpoint=request.endpoint,
                method=request.method,
                client_ip=client_ip,
                status_code=status_code,
                execution_time=round(execution_time, 3)
            )

            return result

        except Exception as e:
            # Calculate execution time for failed requests
            execution_time = time.time() - start_time

            # Log error
            logger.error(
                "API request failed",
                endpoint=request.endpoint,
                method=request.method,
                client_ip=client_ip,
                execution_time=round(execution_time, 3),
                error=str(e)
            )

            # Re-raise the exception
            raise

    return decorated_function


def validate_json(required_fields=None, optional_fields=None):
    """
    Decorator to validate JSON input

    Args:
        required_fields (list): List of required field names
        optional_fields (list): List of optional field names
    """

    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not request.is_json:
                return jsonify({
                    'error': 'Invalid content type',
                    'message': 'Content-Type must be application/json'
                }), 400

            try:
                data = request.get_json()
            except Exception as e:
                return jsonify({
                    'error': 'Invalid JSON',
                    'message': str(e)
                }), 400

            if not data:
                return jsonify({
                    'error': 'Empty request body',
                    'message': 'Request body cannot be empty'
                }), 400

            # Check required fields
            if required_fields:
                missing_fields = []
                for field in required_fields:
                    if field not in data or data[field] is None or data[field] == '':
                        missing_fields.append(field)

                if missing_fields:
                    return jsonify({
                        'error': 'Missing required fields',
                        'message': f'The following fields are required: {", ".join(missing_fields)}',
                        'missing_fields': missing_fields
                    }), 400

            # Store validated data in Flask's g object
            g.validated_data = data

            return f(*args, **kwargs)

        return decorated_function

    return decorator


def rate_limit_by_ip(requests_per_minute=60):
    """
    Decorator for IP-based rate limiting
    """

    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.environ.get('REMOTE_ADDR'))

            # Use Redis for rate limiting
            try:
                from flask import current_app
                import redis

                redis_client = redis.from_url(current_app.config.get('REDIS_URL'))
                key = f"rate_limit:{client_ip}:{request.endpoint}"

                # Get current request count
                current_requests = redis_client.get(key)

                if current_requests is None:
                    # First request in this minute
                    redis_client.setex(key, 60, 1)
                else:
                    current_requests = int(current_requests)

                    if current_requests >= requests_per_minute:
                        logger.warning(
                            "Rate limit exceeded",
                            client_ip=client_ip,
                            endpoint=request.endpoint,
                            requests=current_requests,
                            limit=requests_per_minute
                        )

                        return jsonify({
                            'error': 'Rate limit exceeded',
                            'message': f'Maximum {requests_per_minute} requests per minute allowed',
                            'retry_after': 60
                        }), 429

                    # Increment request count
                    redis_client.incr(key)

            except Exception as e:
                # If Redis is unavailable, log error but don't block request
                logger.warning("Rate limiting unavailable", error=str(e))

            return f(*args, **kwargs)

        return decorated_function

    return decorator


def cache_response(timeout=300):
    """
    Decorator to cache API responses in Redis

    Args:
        timeout (int): Cache timeout in seconds
    """

    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Create cache key from endpoint and request parameters
            cache_key_parts = [
                request.endpoint,
                request.method,
                str(sorted(request.args.items())),
                str(sorted(request.form.items())) if request.form else '',
            ]

            # Include JSON data in cache key if present
            if request.is_json:
                try:
                    json_data = request.get_json()
                    cache_key_parts.append(str(sorted(json_data.items())) if json_data else '')
                except:
                    pass

            cache_key = f"api_cache:{':'.join(cache_key_parts)}"

            try:
                import redis
                redis_client = redis.from_url(current_app.config.get('REDIS_URL'))

                # Try to get cached response
                cached_response = redis_client.get(cache_key)

                if cached_response:
                    logger.debug("Returning cached response", cache_key=cache_key)
                    return cached_response, 200, {'Content-Type': 'application/json'}

                # Execute function and cache result
                result = f(*args, **kwargs)

                # Only cache successful responses
                if isinstance(result, tuple) and len(result) >= 2:
                    response_data, status_code = result[0], result[1]
                    if status_code == 200:
                        redis_client.setex(cache_key, timeout, response_data)
                else:
                    redis_client.setex(cache_key, timeout, result)

                return result

            except Exception as e:
                # If caching fails, log error but return original response
                logger.warning("Response caching failed", error=str(e))
                return f(*args, **kwargs)

        return decorated_function

    return decorator


def monitor_performance(f):
    """
    Decorator to monitor API performance and log slow requests
    """

    @wraps(f)
    def decorated_function(*args, **kwargs):
        start_time = time.time()
        start_memory = None

        try:
            import psutil
            process = psutil.Process()
            start_memory = process.memory_info().rss
        except ImportError:
            pass

        try:
            result = f(*args, **kwargs)

            # Calculate metrics
            execution_time = time.time() - start_time

            memory_used = None
            if start_memory:
                try:
                    end_memory = process.memory_info().rss
                    memory_used = end_memory - start_memory
                except:
                    pass

            # Log performance metrics
            performance_data = {
                'endpoint': request.endpoint,
                'method': request.method,
                'execution_time': round(execution_time, 3),
                'memory_used': memory_used,
                'timestamp': datetime.utcnow().isoformat()
            }

            # Log warning for slow requests (> 2 seconds)
            if execution_time > 2.0:
                logger.warning("Slow API request detected", **performance_data)
            else:
                logger.debug("API performance metrics", **performance_data)

            # Store metrics in Redis for monitoring dashboard
            try:
                import redis
                redis_client = redis.from_url(current_app.config.get('REDIS_URL'))

                # Store last 100 performance metrics
                metrics_key = f"performance_metrics:{request.endpoint}"
                redis_client.lpush(metrics_key, str(performance_data))
                redis_client.ltrim(metrics_key, 0, 99)  # Keep only last 100
                redis_client.expire(metrics_key, 3600)  # Expire after 1 hour

            except Exception as e:
                logger.debug("Failed to store performance metrics", error=str(e))

            return result

        except Exception as e:
            execution_time = time.time() - start_time

            logger.error(
                "API request failed with performance data",
                endpoint=request.endpoint,
                method=request.method,
                execution_time=round(execution_time, 3),
                error=str(e)
            )

            raise

    return decorated_function


def require_content_type(content_type='application/json'):
    """
    Decorator to require specific content type
    """

    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if request.content_type != content_type:
                return jsonify({
                    'error': 'Invalid content type',
                    'message': f'Content-Type must be {content_type}',
                    'received': request.content_type
                }), 400

            return f(*args, **kwargs)

        return decorated_function

    return decorator


def handle_exceptions(f):
    """
    Decorator to handle common exceptions and return appropriate JSON responses
    """

    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            return f(*args, **kwargs)

        except ValueError as e:
            logger.warning("ValueError in API request", error=str(e), endpoint=request.endpoint)
            return jsonify({
                'error': 'Invalid input',
                'message': str(e)
            }), 400

        except KeyError as e:
            logger.warning("KeyError in API request", error=str(e), endpoint=request.endpoint)
            return jsonify({
                'error': 'Missing required data',
                'message': f'Required key not found: {str(e)}'
            }), 400

        except PermissionError as e:
            logger.warning("PermissionError in API request", error=str(e), endpoint=request.endpoint)
            return jsonify({
                'error': 'Permission denied',
                'message': str(e)
            }), 403

        except ConnectionError as e:
            logger.error("ConnectionError in API request", error=str(e), endpoint=request.endpoint)
            return jsonify({
                'error': 'Service unavailable',
                'message': 'Unable to connect to required service'
            }), 503

        except TimeoutError as e:
            logger.error("TimeoutError in API request", error=str(e), endpoint=request.endpoint)
            return jsonify({
                'error': 'Request timeout',
                'message': 'The request took too long to process'
            }), 504

        except Exception as e:
            logger.error("Unexpected error in API request", error=str(e), endpoint=request.endpoint)
            return jsonify({
                'error': 'Internal server error',
                'message': 'An unexpected error occurred'
            }), 500

    return decorated_function


# Utility function to combine multiple decorators
def api_endpoint(require_auth=True, require_json=True, required_fields=None,
                 cache_timeout=None, rate_limit=None):
    """
    Convenience decorator that combines multiple common decorators

    Args:
        require_auth (bool): Whether to require API key authentication
        require_json (bool): Whether to require JSON content type
        required_fields (list): List of required JSON fields
        cache_timeout (int): Cache timeout in seconds
        rate_limit (int): Rate limit in requests per minute
    """

    def decorator(f):
        # Start with the original function
        decorated = f

        # Apply decorators in reverse order (since they wrap from inside out)
        decorated = handle_exceptions(decorated)
        decorated = monitor_performance(decorated)
        decorated = log_api_call(decorated)

        if cache_timeout:
            decorated = cache_response(cache_timeout)(decorated)

        if rate_limit:
            decorated = rate_limit_by_ip(rate_limit)(decorated)

        if require_json:
            if required_fields:
                decorated = validate_json(required_fields)(decorated)
            else:
                decorated = require_content_type('application/json')(decorated)

        if require_auth:
            decorated = require_api_key(decorated)

        return decorated

    return decorator