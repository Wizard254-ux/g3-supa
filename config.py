"""
ISP Middleware Flask Application Configuration
"""

import os
from datetime import timedelta
from decouple import config


class Config:
    """Base configuration class"""

    # Flask Configuration
    SECRET_KEY = config('SECRET_KEY', default='your-secret-key-change-in-production')
    FLASK_ENV = config('FLASK_ENV', default='development')
    DEBUG = config('DEBUG', default=False, cast=bool)

    # Database Configuration
    DATABASE_URL = config('DATABASE_URL', default='postgresql://user:password@localhost/isp_middleware')
    SQLALCHEMY_DATABASE_URI = DATABASE_URL
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        'pool_size': 10,
        'pool_recycle': 3600,
        'pool_pre_ping': True
    }

    # Redis Configuration
    REDIS_URL = config('REDIS_URL', default='redis://localhost:6379/0')
    CACHE_TYPE = 'redis'
    CACHE_REDIS_URL = REDIS_URL
    CACHE_DEFAULT_TIMEOUT = 300

    # JWT Configuration
    JWT_SECRET_KEY = config('JWT_SECRET_KEY', default='jwt-secret-change-in-production')
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=1)
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=30)

    # CORS Configuration
    CORS_ORIGINS = config('CORS_ORIGINS', default='*').split(',')

    # Rate Limiting
    RATELIMIT_STORAGE_URL = REDIS_URL
    RATELIMIT_STRATEGY = 'fixed-window'

    # Logging Configuration
    LOG_LEVEL = config('LOG_LEVEL', default='INFO')
    LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    LOG_FILE = config('LOG_FILE', default='/var/log/isp_middleware/app.log')

    # RADIUS Configuration
    RADIUS_SERVER_IP = config('RADIUS_SERVER_IP', default='127.0.0.1')
    RADIUS_SERVER_PORT = config('RADIUS_SERVER_PORT', default=1812, cast=int)
    RADIUS_ACCOUNTING_PORT = config('RADIUS_ACCOUNTING_PORT', default=1813, cast=int)
    RADIUS_SECRET = config('RADIUS_SECRET', default='testing123')
    RADIUS_TIMEOUT = config('RADIUS_TIMEOUT', default=5, cast=int)
    RADIUS_RETRIES = config('RADIUS_RETRIES', default=3, cast=int)

    # MikroTik Configuration
    MIKROTIK_DEVICES = [
        {
            'name': 'core_router',
            'host': config('MIKROTIK_CORE_HOST', default='192.168.1.1'),
            'username': config('MIKROTIK_CORE_USER', default='admin'),
            'password': config('MIKROTIK_CORE_PASS', default=''),
            'port': config('MIKROTIK_CORE_PORT', default=8728, cast=int),
            'use_ssl': config('MIKROTIK_CORE_SSL', default=False, cast=bool)
        },
        # Add more MikroTik devices as needed
    ]

    # OpenVPN Configuration
    OPENVPN_CONFIG_DIR = config('OPENVPN_CONFIG_DIR', default='/etc/openvpn')
    OPENVPN_CLIENT_CONFIG_DIR = config('OPENVPN_CLIENT_CONFIG_DIR', default='/etc/openvpn/clients')
    OPENVPN_CA_CERT = config('OPENVPN_CA_CERT', default='/etc/openvpn/ca.crt')
    OPENVPN_SERVER_CERT = config('OPENVPN_SERVER_CERT', default='/etc/openvpn/server.crt')
    OPENVPN_SERVER_KEY = config('OPENVPN_SERVER_KEY', default='/etc/openvpn/server.key')
    OPENVPN_DH_PARAMS = config('OPENVPN_DH_PARAMS', default='/etc/openvpn/dh2048.pem')
    OPENVPN_SERVER_IP = config('OPENVPN_SERVER_IP', default='10.8.0.0')
    OPENVPN_SERVER_MASK = config('OPENVPN_SERVER_MASK', default='255.255.255.0')

    # Django API Configuration (for communication with customer management system)
    DJANGO_API_URL = config('DJANGO_API_URL', default='http://localhost:8000/api')
    DJANGO_API_KEY = config('DJANGO_API_KEY', default='your-django-api-key')
    DJANGO_API_TIMEOUT = config('DJANGO_API_TIMEOUT', default=30, cast=int)

    # Network Configuration
    NETWORK_INTERFACE = config('NETWORK_INTERFACE', default='eth0')
    DEFAULT_GATEWAY = config('DEFAULT_GATEWAY', default='192.168.1.1')
    DNS_SERVERS = config('DNS_SERVERS', default='8.8.8.8,8.8.4.4').split(',')

    # Bandwidth Management
    DEFAULT_DOWNLOAD_SPEED = config('DEFAULT_DOWNLOAD_SPEED', default=1, cast=int)  # Mbps
    DEFAULT_UPLOAD_SPEED = config('DEFAULT_UPLOAD_SPEED', default=1, cast=int)  # Mbps
    MAX_DOWNLOAD_SPEED = config('MAX_DOWNLOAD_SPEED', default=100, cast=int)  # Mbps
    MAX_UPLOAD_SPEED = config('MAX_UPLOAD_SPEED', default=100, cast=int)  # Mbps

    # Session Management
    DEFAULT_SESSION_TIMEOUT = config('DEFAULT_SESSION_TIMEOUT', default=3600, cast=int)  # seconds
    DEFAULT_IDLE_TIMEOUT = config('DEFAULT_IDLE_TIMEOUT', default=600, cast=int)  # seconds
    MAX_CONCURRENT_SESSIONS = config('MAX_CONCURRENT_SESSIONS', default=1, cast=int)

    # Monitoring Configuration
    MONITORING_INTERVAL = config('MONITORING_INTERVAL', default=60, cast=int)  # seconds
    HEALTH_CHECK_INTERVAL = config('HEALTH_CHECK_INTERVAL', default=30, cast=int)  # seconds

    # Security Configuration
    API_KEY_HEADER = 'X-API-Key'
    ALLOWED_IPS = config('ALLOWED_IPS', default='').split(',') if config('ALLOWED_IPS', default='') else []
    BLOCK_SUSPICIOUS_IPS = config('BLOCK_SUSPICIOUS_IPS', default=True, cast=bool)
    MAX_LOGIN_ATTEMPTS = config('MAX_LOGIN_ATTEMPTS', default=5, cast=int)
    LOGIN_ATTEMPT_WINDOW = config('LOGIN_ATTEMPT_WINDOW', default=900, cast=int)  # seconds

    # Notification Configuration
    SMTP_SERVER = config('SMTP_SERVER', default='localhost')
    SMTP_PORT = config('SMTP_PORT', default=587, cast=int)
    SMTP_USERNAME = config('SMTP_USERNAME', default='')
    SMTP_PASSWORD = config('SMTP_PASSWORD', default='')
    SMTP_USE_TLS = config('SMTP_USE_TLS', default=True, cast=bool)

    # SMS Configuration (for notifications)
    SMS_PROVIDER = config('SMS_PROVIDER', default='africastalking')  # or 'twilio'
    SMS_API_KEY = config('SMS_API_KEY', default='')
    SMS_USERNAME = config('SMS_USERNAME', default='')
    SMS_SENDER_ID = config('SMS_SENDER_ID', default='ISP')

    # File Upload Configuration
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max file size
    UPLOAD_FOLDER = config('UPLOAD_FOLDER', default='/var/uploads/isp_middleware')
    ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'csv', 'xlsx'}

    # Celery Configuration (for background tasks)
    CELERY_BROKER_URL = REDIS_URL
    CELERY_RESULT_BACKEND = REDIS_URL
    CELERY_TASK_SERIALIZER = 'json'
    CELERY_RESULT_SERIALIZER = 'json'
    CELERY_ACCEPT_CONTENT = ['json']
    CELERY_TIMEZONE = 'UTC'
    CELERY_ENABLE_UTC = True

    # Prometheus Metrics
    PROMETHEUS_METRICS = config('PROMETHEUS_METRICS', default=True, cast=bool)
    METRICS_PORT = config('METRICS_PORT', default=9090, cast=int)


class DevelopmentConfig(Config):
    """Development configuration"""
    DEBUG = True
    SQLALCHEMY_ECHO = True
    LOG_LEVEL = 'DEBUG'


class ProductionConfig(Config):
    """Production configuration"""
    DEBUG = False
    SQLALCHEMY_ECHO = False
    LOG_LEVEL = 'WARNING'

    # Enhanced security for production
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'


class TestingConfig(Config):
    """Testing configuration"""
    TESTING = True
    DEBUG = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    WTF_CSRF_ENABLED = False


# Configuration dictionary
config_dict = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
}