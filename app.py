"""
ISP Middleware Flask Application
Main application file for RADIUS/MikroTik/OpenVPN integration
"""

from flask import Flask, jsonify, request, render_template
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_cors import CORS
from flask_jwt_extended import JWTManager
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_caching import Cache
import logging
import structlog
from datetime import datetime, timedelta
import os
from decouple import config
from celery import Celery
from flask_vite import Vite
from sqlalchemy import text
# Import local modules
from config import Config
from models import init_db, db, migrate
# from utils.logging import setup_logging
from services.radius_service import RadiusService
from services.mikrotik_service import MikroTikService
from services.bandwidth_service import BandwidthService
from auth.radius_auth import RadiusAuth

# Initialize extensions
jwt = JWTManager()
cache = Cache()
celery = Celery(__name__)
vite = Vite()

# Initialize rate limiter
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["1000 per hour"]
)


def create_app(config_class=Config):
    """Application factory pattern"""
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Initialize extensions
    init_db(app)
    vite.init_app(app)
    app.config['VITE_DEV_MODE'] = True
    app.config['CORS_ORIGINS'] = ['http://localhost:5173','http://localhost:5174']

    CORS(app, origins=app.config['CORS_ORIGINS'])
    jwt.init_app(app)
    limiter.init_app(app)
    cache.init_app(app)

    # Configure Celery
    celery.conf.update(app.config)

    class ContextTask(celery.Task):
        def __call__(self, *args, **kwargs):
            with app.app_context():
                return self.run(*args, **kwargs)

    celery.Task = ContextTask

    # Setup logging
    # setup_logging(app)
    logger = structlog.get_logger()

    # Initialize services
    radius_service = RadiusService(app)
    mikrotik_service = MikroTikService(app)
    bandwidth_service = BandwidthService(app)
    radius_auth = RadiusAuth(app)

    # Register blueprints
    from api.auth_api import auth_bp
    from api.mikrotik_api import mikrotik_bp
    from api.usage_api import usage_bp
    from api.vpn_api import vpn_bp
    from api.bandwidth_api import bandwidth_bp

    app.register_blueprint(auth_bp, url_prefix='/api/auth')
    app.register_blueprint(mikrotik_bp, url_prefix='/api/mikrotik')
    app.register_blueprint(usage_bp, url_prefix='/api/usage')
    app.register_blueprint(vpn_bp, url_prefix='/api/vpn')
    app.register_blueprint(bandwidth_bp, url_prefix='/api/bandwidth')

    # @app.route("/")
    # def home():
    #     return render_template("base.html")
    # Health check endpoint
    @app.route('/health')
    def health_check():
        """Health check endpoint for monitoring"""
        try:
            # Check database connection
            db.session.execute(text('SELECT 1'))

            # Check Redis connection
            cache.get('health_check')

            # Check services
            radius_status = radius_service.check_status()
            mikrotik_status = mikrotik_service.check_connection()

            return jsonify({
                'status': 'healthy',
                'timestamp': datetime.utcnow().isoformat(),
                'services': {
                    'database': 'up',
                    'redis': 'up',
                    'radius': 'up' if radius_status else 'down',
                    'mikrotik': 'up' if mikrotik_status else 'down'
                }
            }), 200

        except Exception as e:
            logger.error("Health check failed", error=str(e))
            return jsonify({
                'status': 'unhealthy',
                'timestamp': datetime.utcnow().isoformat(),
                'error': str(e)
            }), 500

    # Metrics endpoint for Prometheus
    @app.route('/metrics')
    def metrics():
        """Prometheus metrics endpoint"""
        from prometheus_client import generate_latest, CONTENT_TYPE_LATEST
        return generate_latest(), 200, {'Content-Type': CONTENT_TYPE_LATEST}

    # Error handlers
    @app.errorhandler(404)
    def not_found(error):
        return jsonify({'error': 'Not found'}), 404

    @app.errorhandler(500)
    def internal_error(error):
        logger.error("Internal server error", error=str(error))
        return jsonify({'error': 'Internal server error'}), 500

    @app.errorhandler(429)
    def ratelimit_handler(e):
        return jsonify({'error': 'Rate limit exceeded', 'retry_after': str(e.retry_after)}), 429

    # JWT error handlers
    @jwt.expired_token_loader
    def expired_token_callback(jwt_header, jwt_payload):
        return jsonify({'error': 'Token has expired'}), 401

    @jwt.invalid_token_loader
    def invalid_token_callback(error):
        return jsonify({'error': 'Invalid token'}), 401

    @jwt.unauthorized_loader
    def missing_token_callback(error):
        return jsonify({'error': 'Authorization token required'}), 401

    # Request logging middleware
    @app.before_request
    def log_request_info():
        logger.info(
            "Request received",
            method=request.method,
            url=request.url,
            remote_addr=request.remote_addr,
            user_agent=request.headers.get('User-Agent')
        )

    @app.after_request
    def log_response_info(response):
        logger.info(
            "Response sent",
            status_code=response.status_code,
            content_length=response.content_length
        )
        return response




    # RADIUS Authentication Endpoint (for FreeRADIUS integration)
    @app.route('/radius/auth', methods=['POST'])
    @limiter.limit("100 per minute")
    def radius_authenticate():
        """
        RADIUS authentication endpoint
        Called by FreeRADIUS server for user authentication
        """
        try:
            data = request.get_json()
            username = data.get('username')
            password = data.get('password')
            nas_ip = data.get('nas_ip_address')
            nas_port = data.get('nas_port')

            logger.info(
                "RADIUS authentication request",
                username=username,
                nas_ip=nas_ip,
                nas_port=nas_port
            )

            # Authenticate user
            auth_result = radius_auth.authenticate_user(
                username=username,
                password=password,
                nas_ip=nas_ip,
                nas_port=nas_port
            )

            if auth_result['success']:
                # Create user session
                session_data = {
                    'username': username,
                    'nas_ip': nas_ip,
                    'nas_port': nas_port,
                    'start_time': datetime.utcnow(),
                    'package_info': auth_result['package_info']
                }

                # Store session in cache for quick access
                cache.set(f"session:{username}", session_data, timeout=3600)

                # Configure MikroTik for this user
                mikrotik_result = mikrotik_service.create_user_queue(
                    username=username,
                    package_info=auth_result['package_info']
                )

                response = {
                    'access': 'accept',
                    'attributes': {
                        'Mikrotik-Rate-Limit': f"{auth_result['package_info']['download_speed']}M/{auth_result['package_info']['upload_speed']}M",
                        'Session-Timeout': auth_result['package_info'].get('session_timeout', 3600),
                        'Idle-Timeout': auth_result['package_info'].get('idle_timeout', 600)
                    }
                }

                logger.info("RADIUS authentication successful", username=username)
                return jsonify(response), 200
            else:
                logger.warning("RADIUS authentication failed", username=username, reason=auth_result['reason'])
                return jsonify({'access': 'reject', 'reason': auth_result['reason']}), 200

        except Exception as e:
            logger.error("RADIUS authentication error", error=str(e))
            return jsonify({'access': 'reject', 'reason': 'Internal server error'}), 500


    # RADIUS Accounting Endpoint
    @app.route('/radius/accounting', methods=['POST'])
    @limiter.limit("200 per minute")
    def radius_accounting():
        """
        RADIUS accounting endpoint
        Called by FreeRADIUS for session start/stop/update
        """
        try:
            data = request.get_json()
            acct_status_type = data.get('acct_status_type')
            username = data.get('username')
            session_id = data.get('acct_session_id')

            logger.info(
                "RADIUS accounting request",
                username=username,
                session_id=session_id,
                status_type=acct_status_type
            )

            if acct_status_type == 'Start':
                # Session start
                result = radius_service.session_start(data)
            elif acct_status_type == 'Stop':
                # Session stop
                result = radius_service.session_stop(data)
                # Clean up MikroTik queue
                mikrotik_service.remove_user_queue(username)
            elif acct_status_type == 'Interim-Update':
                # Session update
                result = radius_service.session_update(data)
            else:
                logger.warning("Unknown accounting status type", status_type=acct_status_type)
                return jsonify({'status': 'error', 'message': 'Unknown status type'}), 400

            return jsonify({'status': 'ok'}), 200

        except Exception as e:
            logger.error("RADIUS accounting error", error=str(e))
            return jsonify({'status': 'error', 'message': str(e)}), 500


    # Hotspot Login Endpoint
    @app.route('/hotspot/login', methods=['POST'])
    @limiter.limit("50 per minute")
    def hotspot_login():
        """
        Hotspot captive portal login endpoint
        """
        try:
            data = request.get_json()
            username = data.get('username')
            password = data.get('password')
            mac_address = data.get('mac')
            ip_address = data.get('ip')

            # Authenticate user
            auth_result = radius_auth.authenticate_user(username, password)

            if auth_result['success']:
                # Authorize user on MikroTik hotspot
                hotspot_result = mikrotik_service.hotspot_authorize(
                    username=username,
                    mac_address=mac_address,
                    ip_address=ip_address,
                    package_info=auth_result['package_info']
                )

                if hotspot_result['success']:
                    return jsonify({
                        'success': True,
                        'message': 'Login successful',
                        'redirect_url': data.get('link_orig', 'http://google.com')
                    }), 200
                else:
                    return jsonify({
                        'success': False,
                        'message': 'Failed to authorize on network'
                    }), 500
            else:
                return jsonify({
                    'success': False,
                    'message': 'Invalid username or password'
                }), 401

        except Exception as e:
            logger.error("Hotspot login error", error=str(e))
            return jsonify({
                'success': False,
                'message': 'Login failed due to server error'
            }), 500


    # WebSocket endpoint for real-time monitoring (optional)
    @app.route('/ws/monitoring')
    def monitoring_websocket():
        """
        WebSocket endpoint for real-time network monitoring
        """
        # This would typically use Flask-SocketIO for WebSocket support
        pass

    # Initialize database
    with app.app_context():
        try:
            db.create_all()
            logger.info("Database initialized successfully")
        except Exception as e:
            logger.error("Failed to initialize database", error=str(e))

    logger.info("ISP Middleware application started successfully")
    return app

if __name__ == '__main__':
    app = create_app()

    # Development server
    app.run(
        host=config('FLASK_HOST', default='0.0.0.0'),
        port=config('FLASK_PORT', default=5000, cast=int),
        debug=config('FLASK_DEBUG', default=False, cast=bool)
    )
