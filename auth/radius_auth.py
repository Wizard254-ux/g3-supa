"""
RADIUS Authentication Service for ISP Middleware
Handles user authentication and communicates with Django backend
"""

import requests
import hashlib
import hmac
import structlog
from typing import Dict, Optional, Any
from datetime import datetime, timedelta
import bcrypt
from flask import current_app
import redis
import json

logger = structlog.get_logger()


class RadiusAuth:
    """RADIUS Authentication service"""

    def __init__(self, app=None):
        self.app = app
        self.redis_client = None
        self.django_api_url = None
        self.django_api_key = None

        if app:
            self.init_app(app)

    def init_app(self, app):
        """Initialize the service with Flask app"""
        self.app = app
        self.django_api_url = app.config.get('DJANGO_API_URL')
        self.django_api_key = app.config.get('DJANGO_API_KEY')

        # Initialize Redis for caching
        redis_url = app.config.get('REDIS_URL', 'redis://localhost:6379/0')
        self.redis_client = redis.from_url(redis_url)

        logger.info("RADIUS Authentication service initialized")

    def authenticate_user(self, username: str, password: str, nas_ip: str = None,
                         nas_port: str = None, mac_address: str = None) -> Dict[str, Any]:
        """
        Authenticate user credentials and return package information
        """
        try:
            # Check for rate limiting
            if self._is_rate_limited(username, nas_ip):
                return {
                    'success': False,
                    'reason': 'Too many authentication attempts',
                    'retry_after': 300
                }

            # Check cache first for recent authentication
            cache_key = f"auth:{username}:{hashlib.md5(password.encode()).hexdigest()}"
            cached_auth = self._get_cached_auth(cache_key)

            if cached_auth:
                logger.info(f"Using cached authentication for user: {username}")
                return cached_auth

            # Authenticate with Django backend
            auth_result = self._authenticate_with_django(username, password, nas_ip, nas_port, mac_address)

            if auth_result['success']:
                # Cache successful authentication for 5 minutes
                self._cache_auth_result(cache_key, auth_result, timeout=300)

                # Reset failed attempts counter
                self._reset_failed_attempts(username, nas_ip)

                logger.info(f"Authentication successful for user: {username}")
            else:
                # Increment failed attempts counter
                self._increment_failed_attempts(username, nas_ip)

                logger.warning(f"Authentication failed for user: {username}", reason=auth_result.get('reason'))

            return auth_result

        except Exception as e:
            logger.error(f"Authentication error for user {username}", error=str(e))
            return {
                'success': False,
                'reason': 'Authentication service error'
            }

    def _authenticate_with_django(self, username: str, password: str, nas_ip: str = None,
                                 nas_port: str = None, mac_address: str = None) -> Dict[str, Any]:
        """Authenticate user with Django backend API"""
        try:
            headers = {
                'Authorization': f'Bearer {self.django_api_key}',
                'Content-Type': 'application/json'
            }

            payload = {
                'username': username,
                'password': password,
                'nas_ip': nas_ip,
                'nas_port': nas_port,
                'mac_address': mac_address,
                'auth_type': 'radius'
            }

            response = requests.post(
                f"{self.django_api_url}/auth/radius/",
                json=payload,
                headers=headers,
                timeout=self.app.config.get('DJANGO_API_TIMEOUT', 30)
            )

            if response.status_code == 200:
                data = response.json()

                if data.get('success'):
                    return {
                        'success': True,
                        'user_id': data.get('user_id'),
                        'customer_id': data.get('customer_id'),
                        'subscription_id': data.get('subscription_id'),
                        'package_info': {
                            'package_id': data.get('package', {}).get('id'),
                            'package_name': data.get('package', {}).get('name'),
                            'package_type': data.get('package', {}).get('package_type'),
                            'download_speed': data.get('package', {}).get('download_speed', 1),
                            'upload_speed': data.get('package', {}).get('upload_speed', 1),
                            'data_limit': data.get('package', {}).get('data_limit'),
                            'time_limit': data.get('package', {}).get('time_limit'),
                            'session_timeout': data.get('package', {}).get('session_timeout', 3600),
                            'idle_timeout': data.get('package', {}).get('idle_timeout', 600),
                            'priority_level': data.get('package', {}).get('priority_level', 8),
                            'burst_speed': data.get('package', {}).get('burst_speed'),
                            'hotspot_profile': data.get('package', {}).get('hotspot_profile', 'default'),
                            'pppoe_profile': data.get('package', {}).get('pppoe_profile', 'default')
                        },
                        'user_info': {
                            'full_name': data.get('user', {}).get('full_name'),
                            'email': data.get('user', {}).get('email'),
                            'phone': data.get('user', {}).get('phone'),
                            'status': data.get('user', {}).get('status'),
                            'max_concurrent_sessions': data.get('user', {}).get('max_concurrent_sessions', 1)
                        }
                    }
                else:
                    return {
                        'success': False,
                        'reason': data.get('reason', 'Invalid credentials')
                    }

            elif response.status_code == 401:
                return {
                    'success': False,
                    'reason': 'Invalid credentials'
                }

            elif response.status_code == 403:
                return {
                    'success': False,
                    'reason': 'Account suspended or inactive'
                }

            elif response.status_code == 429:
                return {
                    'success': False,
                    'reason': 'Too many requests',
                    'retry_after': 60
                }

            else:
                logger.error(f"Django API authentication failed with status {response.status_code}")
                return {
                    'success': False,
                    'reason': 'Authentication service unavailable'
                }

        except requests.exceptions.Timeout:
            logger.error("Django API timeout during authentication")
            return {
                'success': False,
                'reason': 'Authentication timeout'
            }

        except requests.exceptions.ConnectionError:
            logger.error("Django API connection error during authentication")
            return {
                'success': False,
                'reason': 'Authentication service unavailable'
            }

        except Exception as e:
            logger.error(f"Unexpected error during Django authentication", error=str(e))
            return {
                'success': False,
                'reason': 'Authentication error'
            }

    def validate_session(self, username: str, session_id: str) -> Dict[str, Any]:
        """Validate active user session"""
        try:
            # Check local session cache first
            session_key = f"session:{username}:{session_id}"
            cached_session = self.redis_client.get(session_key)

            if cached_session:
                session_data = json.loads(cached_session)

                # Check if session is still valid
                if session_data.get('expires_at'):
                    expires_at = datetime.fromisoformat(session_data['expires_at'])
                    if datetime.utcnow() > expires_at:
                        self.redis_client.delete(session_key)
                        return {
                            'valid': False,
                            'reason': 'Session expired'
                        }

                return {
                    'valid': True,
                    'session_data': session_data
                }

            # If not in cache, validate with Django backend
            return self._validate_session_with_django(username, session_id)

        except Exception as e:
            logger.error(f"Session validation error for {username}", error=str(e))
            return {
                'valid': False,
                'reason': 'Session validation error'
            }

    def _validate_session_with_django(self, username: str, session_id: str) -> Dict[str, Any]:
        """Validate session with Django backend"""
        try:
            headers = {
                'Authorization': f'Bearer {self.django_api_key}',
                'Content-Type': 'application/json'
            }

            payload = {
                'username': username,
                'session_id': session_id
            }

            response = requests.post(
                f"{self.django_api_url}/auth/validate-session/",
                json=payload,
                headers=headers,
                timeout=self.app.config.get('DJANGO_API_TIMEOUT', 30)
            )

            if response.status_code == 200:
                data = response.json()

                if data.get('valid'):
                    # Cache the session for faster future lookups
                    session_key = f"session:{username}:{session_id}"
                    session_data = data.get('session_data', {})

                    self.redis_client.setex(
                        session_key,
                        300,  # 5 minutes cache
                        json.dumps(session_data)
                    )

                    return {
                        'valid': True,
                        'session_data': session_data
                    }
                else:
                    return {
                        'valid': False,
                        'reason': data.get('reason', 'Invalid session')
                    }
            else:
                return {
                    'valid': False,
                    'reason': 'Session validation failed'
                }

        except Exception as e:
            logger.error(f"Django session validation error", error=str(e))
            return {
                'valid': False,
                'reason': 'Session validation error'
            }

    def check_concurrent_sessions(self, username: str) -> Dict[str, Any]:
        """Check how many concurrent sessions user has"""
        try:
            # Get user's max concurrent sessions from cache or Django
            user_info = self._get_user_info(username)
            max_sessions = user_info.get('max_concurrent_sessions', 1)

            # Count active sessions from Redis
            session_pattern = f"session:{username}:*"
            active_sessions = len(self.redis_client.keys(session_pattern))

            return {
                'active_sessions': active_sessions,
                'max_sessions': max_sessions,
                'can_login': active_sessions < max_sessions
            }

        except Exception as e:
            logger.error(f"Error checking concurrent sessions for {username}", error=str(e))
            return {
                'active_sessions': 0,
                'max_sessions': 1,
                'can_login': True
            }

    def terminate_session(self, username: str, session_id: str) -> bool:
        """Terminate a user session"""
        try:
            # Remove from local cache
            session_key = f"session:{username}:{session_id}"
            self.redis_client.delete(session_key)

            # Notify Django backend
            headers = {
                'Authorization': f'Bearer {self.django_api_key}',
                'Content-Type': 'application/json'
            }

            payload = {
                'username': username,
                'session_id': session_id,
                'reason': 'Manual termination'
            }

            response = requests.post(
                f"{self.django_api_url}/auth/terminate-session/",
                json=payload,
                headers=headers,
                timeout=self.app.config.get('DJANGO_API_TIMEOUT', 30)
            )

            return response.status_code == 200

        except Exception as e:
            logger.error(f"Error terminating session for {username}", error=str(e))
            return False

    def _get_cached_auth(self, cache_key: str) -> Optional[Dict[str, Any]]:
        """Get cached authentication result"""
        try:
            cached_data = self.redis_client.get(cache_key)
            if cached_data:
                return json.loads(cached_data)
            return None
        except Exception:
            return None

    def _cache_auth_result(self, cache_key: str, auth_result: Dict[str, Any], timeout: int = 300):
        """Cache authentication result"""
        try:
            self.redis_client.setex(cache_key, timeout, json.dumps(auth_result))
        except Exception as e:
            logger.warning("Failed to cache auth result", error=str(e))

    def _is_rate_limited(self, username: str, nas_ip: str = None) -> bool:
        """Check if user/IP is rate limited"""
        try:
            # Check failed attempts for username
            username_key = f"failed_auth:{username}"
            failed_attempts = self.redis_client.get(username_key)

            if failed_attempts and int(failed_attempts) >= self.app.config.get('MAX_LOGIN_ATTEMPTS', 5):
                return True

            # Check failed attempts for NAS IP (if provided)
            if nas_ip:
                ip_key = f"failed_auth_ip:{nas_ip}"
                ip_failed_attempts = self.redis_client.get(ip_key)

                if ip_failed_attempts and int(ip_failed_attempts) >= (self.app.config.get('MAX_LOGIN_ATTEMPTS', 5) * 3):
                    return True

            return False

        except Exception:
            return False

    def _increment_failed_attempts(self, username: str, nas_ip: str = None):
        """Increment failed authentication attempts counter"""
        try:
            window = self.app.config.get('LOGIN_ATTEMPT_WINDOW', 900)  # 15 minutes

            # Increment for username
            username_key = f"failed_auth:{username}"
            pipe = self.redis_client.pipeline()
            pipe.incr(username_key)
            pipe.expire(username_key, window)
            pipe.execute()

            # Increment for NAS IP (if provided)
            if nas_ip:
                ip_key = f"failed_auth_ip:{nas_ip}"
                pipe = self.redis_client.pipeline()
                pipe.incr(ip_key)
                pipe.expire(ip_key, window)
                pipe.execute()

        except Exception as e:
            logger.warning("Failed to increment auth attempts", error=str(e))

    def _reset_failed_attempts(self, username: str, nas_ip: str = None):
        """Reset failed authentication attempts counter"""
        try:
            # Reset for username
            username_key = f"failed_auth:{username}"
            self.redis_client.delete(username_key)

            # Reset for NAS IP (if provided)
            if nas_ip:
                ip_key = f"failed_auth_ip:{nas_ip}"
                self.redis_client.delete(ip_key)

        except Exception as e:
            logger.warning("Failed to reset auth attempts", error=str(e))

    def _get_user_info(self, username: str) -> Dict[str, Any]:
        """Get user information from cache or Django"""
        try:
            # Check cache first
            cache_key = f"user_info:{username}"
            cached_info = self.redis_client.get(cache_key)

            if cached_info:
                return json.loads(cached_info)

            # Fetch from Django
            headers = {
                'Authorization': f'Bearer {self.django_api_key}',
                'Content-Type': 'application/json'
            }

            response = requests.get(
                f"{self.django_api_url}/users/{username}/",
                headers=headers,
                timeout=self.app.config.get('DJANGO_API_TIMEOUT', 30)
            )

            if response.status_code == 200:
                user_info = response.json()

                # Cache for 10 minutes
                self.redis_client.setex(cache_key, 600, json.dumps(user_info))

                return user_info

            return {}

        except Exception as e:
            logger.error(f"Error getting user info for {username}", error=str(e))
            return {}

    def get_auth_stats(self) -> Dict[str, Any]:
        """Get authentication statistics"""
        try:
            # Count cached authentications
            auth_keys = self.redis_client.keys("auth:*")
            cached_auths = len(auth_keys)

            # Count active sessions
            session_keys = self.redis_client.keys("session:*")
            active_sessions = len(session_keys)

            # Count failed attempts
            failed_keys = self.redis_client.keys("failed_auth:*")
            failed_attempts = len(failed_keys)

            return {
                'cached_authentications': cached_auths,
                'active_sessions': active_sessions,
                'failed_attempts': failed_attempts,
                'timestamp': datetime.utcnow().isoformat()
            }

        except Exception as e:
            logger.error("Error getting auth stats", error=str(e))
            return {
                'cached_authentications': 0,
                'active_sessions': 0,
                'failed_attempts': 0,
                'timestamp': datetime.utcnow().isoformat()
            }