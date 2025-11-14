# security/rate_limiter.py
from functools import wraps
from flask import request, jsonify
import time
from collections import defaultdict, deque

from flask_jwt_extended import get_jwt_identity


class RateLimiter:
    """Rate limiter for system operations"""

    def __init__(self):
        self.requests = defaultdict(deque)
        self.limits = {
            'system_operations': {'calls': 10, 'window': 60},  # 10 calls per minute
            'cert_operations': {'calls': 5, 'window': 300},  # 5 calls per 5 minutes
            'network_operations': {'calls': 20, 'window': 60}  # 20 calls per minute
        }

    def is_allowed(self, key, limit_type='system_operations'):
        """Check if request is allowed under rate limit"""
        now = time.time()
        limit = self.limits.get(limit_type, self.limits['system_operations'])

        # Clean old requests
        while (self.requests[key] and
               self.requests[key][0] < now - limit['window']):
            self.requests[key].popleft()

        # Check if under limit
        if len(self.requests[key]) < limit['calls']:
            self.requests[key].append(now)
            return True

        return False


def rate_limit(limit_type='system_operations'):
    """Rate limiting decorator"""

    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            limiter = RateLimiter()

            # Use IP + user ID as key
            try:
                user_id = get_jwt_identity().get('user_id', 'anonymous')
            except:
                user_id = 'anonymous'

            key = f"{request.remote_addr}:{user_id}"

            if not limiter.is_allowed(key, limit_type):
                return jsonify({
                    'error': 'Rate limit exceeded',
                    'message': 'Too many system operations'
                }), 429

            return func(*args, **kwargs)

        return wrapper

    return decorator
