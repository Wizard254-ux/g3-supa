"""
RADIUS Service for ISP Middleware
Handles RADIUS accounting, session management, and usage tracking
"""

import structlog
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
import requests
import json
import redis
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
import uuid

from models import UserSession
from models import UsageLog
from models import RadiusLog

logger = structlog.get_logger()


class RadiusService:
    """Service for handling RADIUS operations and session management"""

    def __init__(self, app=None):
        self.app = app
        self.redis_client = None
        self.db_session = None
        self.django_api_url = None
        self.django_api_key = None

        if app:
            self.init_app(app)

    def init_app(self, app):
        """Initialize the service with Flask app"""
        self.app = app
        self.django_api_url = app.config.get('DJANGO_API_URL')
        self.django_api_key = app.config.get('DJANGO_API_KEY')

        # Initialize Redis for session storage
        redis_url = app.config.get('REDIS_URL', 'redis://localhost:6379/0')
        self.redis_client = redis.from_url(redis_url)

        # Initialize database session
        engine = create_engine(app.config.get('SQLALCHEMY_DATABASE_URI'))
        Session = sessionmaker(bind=engine)
        self.db_session = Session()

        logger.info("RADIUS service initialized")

    def check_status(self) -> bool:
        """Check if RADIUS service is healthy"""
        try:
            # Test Redis connection
            self.redis_client.ping()

            # Test database connection
            self.db_session.execute(text('SELECT 1'))

            return True
        except Exception as e:
            logger.error("RADIUS service health check failed", error=str(e))
            return False

    def handle_session_start(self, session_data: Dict[str, Any]) -> Dict[str, Any]:
        """Handle RADIUS session start"""
        try:
            username = session_data['username']
            session_id = session_data['session_id']

            logger.info(f"Starting session for user: {username}", session_id=session_id)

            # Create session record in database
            user_session = UserSession(
                username=username,
                session_id=session_id,
                nas_ip=session_data.get('nas_ip'),
                nas_port=session_data.get('nas_port'),
                framed_ip=session_data.get('framed_ip'),
                calling_station_id=session_data.get('calling_station_id'),
                called_station_id=session_data.get('called_station_id'),
                start_time=session_data.get('start_time', datetime.utcnow()),
                status='active'
            )

            self.db_session.add(user_session)
            self.db_session.commit()

            # Store session in Redis for quick access
            session_cache_data = {
                'username': username,
                'session_id': session_id,
                'nas_ip': session_data.get('nas_ip'),
                'framed_ip': session_data.get('framed_ip'),
                'start_time': session_data.get('start_time', datetime.utcnow()).isoformat(),
                'status': 'active'
            }

            self.redis_client.hset(
                f"session:{session_id}",
                mapping=session_cache_data
            )

            # Set session expiration (24 hours default)
            self.redis_client.expire(f"session:{session_id}", 86400)

            # Log to RADIUS accounting log
            self._log_radius_event('Start', session_data)

            # Notify Django backend about session start
            self._notify_django_session_event('start', session_data)

            return {
                'success': True,
                'session_id': session_id,
                'message': 'Session started successfully'
            }

        except Exception as e:
            logger.error(f"Failed to start session for {username}", error=str(e))
            self.db_session.rollback()
            return {
                'success': False,
                'error': str(e)
            }

    def handle_session_stop(self, session_data: Dict[str, Any]) -> Dict[str, Any]:
        """Handle RADIUS session stop"""
        try:
            username = session_data['username']
            session_id = session_data['session_id']

            logger.info(f"Stopping session for user: {username}", session_id=session_id)

            # Update session record in database
            user_session = self.db_session.query(UserSession).filter_by(
                session_id=session_id
            ).first()

            if user_session:
                user_session.stop_time = session_data.get('stop_time', datetime.utcnow())
                user_session.session_time = session_data.get('session_time', 0)
                user_session.input_octets = session_data.get('input_octets', 0)
                user_session.output_octets = session_data.get('output_octets', 0)
                user_session.input_packets = session_data.get('input_packets', 0)
                user_session.output_packets = session_data.get('output_packets', 0)
                user_session.terminate_cause = session_data.get('terminate_cause', 'Unknown')
                user_session.status = 'stopped'

                self.db_session.commit()

                # Create usage log entry
                self._create_usage_log(user_session, session_data)

            # Remove session from Redis
            self.redis_client.delete(f"session:{session_id}")

            # Log to RADIUS accounting log
            self._log_radius_event('Stop', session_data)

            # Notify Django backend about session stop
            self._notify_django_session_event('stop', session_data)

            return {
                'success': True,
                'session_id': session_id,
                'message': 'Session stopped successfully'
            }

        except Exception as e:
            logger.error(f"Failed to stop session for {username}", error=str(e))
            self.db_session.rollback()
            return {
                'success': False,
                'error': str(e)
            }

    def handle_session_update(self, session_data: Dict[str, Any]) -> Dict[str, Any]:
        """Handle RADIUS session interim update"""
        try:
            username = session_data['username']
            session_id = session_data['session_id']

            logger.debug(f"Updating session for user: {username}", session_id=session_id)

            # Update session record in database
            user_session = self.db_session.query(UserSession).filter_by(
                session_id=session_id
            ).first()

            if user_session:
                user_session.last_update = session_data.get('update_time', datetime.utcnow())
                user_session.session_time = session_data.get('session_time', 0)
                user_session.input_octets = session_data.get('input_octets', 0)
                user_session.output_octets = session_data.get('output_octets', 0)
                user_session.input_packets = session_data.get('input_packets', 0)
                user_session.output_packets = session_data.get('output_packets', 0)

                self.db_session.commit()

                # Update Redis cache
                self.redis_client.hset(
                    f"session:{session_id}",
                    mapping={
                        'last_update': session_data.get('update_time', datetime.utcnow()).isoformat(),
                        'session_time': session_data.get('session_time', 0),
                        'input_octets': session_data.get('input_octets', 0),
                        'output_octets': session_data.get('output_octets', 0)
                    }
                )

            # Log to RADIUS accounting log (optional for interim updates)
            # self._log_radius_event('Interim-Update', session_data)

            # Notify Django backend about session update (batched updates)
            self._notify_django_session_event('update', session_data)

            return {
                'success': True,
                'session_id': session_id,
                'message': 'Session updated successfully'
            }

        except Exception as e:
            logger.error(f"Failed to update session for {username}", error=str(e))
            self.db_session.rollback()
            return {
                'success': False,
                'error': str(e)
            }

    def get_active_sessions(self, username: str = None) -> List[Dict[str, Any]]:
        """Get active sessions, optionally filtered by username"""
        try:
            query = self.db_session.query(UserSession).filter_by(status='active')

            if username:
                query = query.filter_by(username=username)

            sessions = query.all()

            return [
                {
                    'username': session.username,
                    'session_id': session.session_id,
                    'nas_ip': session.nas_ip,
                    'framed_ip': session.framed_ip,
                    'start_time': session.start_time.isoformat() if session.start_time else None,
                    'session_time': session.session_time,
                    'input_octets': session.input_octets,
                    'output_octets': session.output_octets,
                    'last_update': session.last_update.isoformat() if session.last_update else None
                }
                for session in sessions
            ]

        except Exception as e:
            logger.error("Failed to get active sessions", error=str(e))
            return []

    def get_session_history(self, username: str, days: int = 30) -> List[Dict[str, Any]]:
        """Get session history for a user"""
        try:
            start_date = datetime.utcnow() - timedelta(days=days)

            sessions = self.db_session.query(UserSession).filter(
                UserSession.username == username,
                UserSession.start_time >= start_date
            ).order_by(UserSession.start_time.desc()).all()

            return [
                {
                    'session_id': session.session_id,
                    'start_time': session.start_time.isoformat() if session.start_time else None,
                    'stop_time': session.stop_time.isoformat() if session.stop_time else None,
                    'session_time': session.session_time,
                    'input_octets': session.input_octets,
                    'output_octets': session.output_octets,
                    'terminate_cause': session.terminate_cause,
                    'nas_ip': session.nas_ip,
                    'framed_ip': session.framed_ip,
                    'status': session.status
                }
                for session in sessions
            ]

        except Exception as e:
            logger.error(f"Failed to get session history for {username}", error=str(e))
            return []

    def get_usage_stats(self, username: str = None, days: int = 30) -> Dict[str, Any]:
        """Get usage statistics"""
        try:
            start_date = datetime.utcnow() - timedelta(days=days)

            query = self.db_session.query(UsageLog).filter(
                UsageLog.created_at >= start_date
            )

            if username:
                query = query.filter_by(username=username)

            usage_logs = query.all()

            total_input = sum(log.input_octets for log in usage_logs)
            total_output = sum(log.output_octets for log in usage_logs)
            total_session_time = sum(log.session_time for log in usage_logs)
            total_sessions = len(usage_logs)

            return {
                'username': username,
                'period_days': days,
                'total_sessions': total_sessions,
                'total_input_mb': round(total_input / (1024 * 1024), 2),
                'total_output_mb': round(total_output / (1024 * 1024), 2),
                'total_data_mb': round((total_input + total_output) / (1024 * 1024), 2),
                'total_session_time_hours': round(total_session_time / 3600, 2),
                'average_session_time_minutes': round(total_session_time / 60 / max(total_sessions, 1), 2),
                'start_date': start_date.isoformat(),
                'end_date': datetime.utcnow().isoformat()
            }

        except Exception as e:
            logger.error(f"Failed to get usage stats for {username}", error=str(e))
            return {}

    def terminate_user_sessions(self, username: str, reason: str = 'Admin termination') -> int:
        """Terminate all active sessions for a user"""
        try:
            active_sessions = self.db_session.query(UserSession).filter_by(
                username=username,
                status='active'
            ).all()

            terminated_count = 0

            for session in active_sessions:
                # Update database
                session.stop_time = datetime.utcnow()
                session.terminate_cause = reason
                session.status = 'terminated'

                # Remove from Redis
                self.redis_client.delete(f"session:{session.session_id}")

                # Create usage log
                self._create_usage_log(session, {
                    'username': username,
                    'session_id': session.session_id,
                    'terminate_cause': reason
                })

                terminated_count += 1

            self.db_session.commit()

            logger.info(f"Terminated {terminated_count} sessions for user: {username}")

            return terminated_count

        except Exception as e:
            logger.error(f"Failed to terminate sessions for {username}", error=str(e))
            self.db_session.rollback()
            return 0

    def cleanup_expired_sessions(self) -> int:
        """Clean up expired sessions from database and Redis"""
        try:
            # Find sessions older than 24 hours without stop time
            cutoff_time = datetime.utcnow() - timedelta(hours=24)

            expired_sessions = self.db_session.query(UserSession).filter(
                UserSession.status == 'active',
                UserSession.start_time < cutoff_time
            ).all()

            cleaned_count = 0

            for session in expired_sessions:
                # Update database
                session.stop_time = datetime.utcnow()
                session.terminate_cause = 'Session timeout'
                session.status = 'expired'

                # Remove from Redis
                self.redis_client.delete(f"session:{session.session_id}")

                # Create usage log
                self._create_usage_log(session, {
                    'username': session.username,
                    'session_id': session.session_id,
                    'terminate_cause': 'Session timeout'
                })

                cleaned_count += 1

            self.db_session.commit()

            if cleaned_count > 0:
                logger.info(f"Cleaned up {cleaned_count} expired sessions")

            return cleaned_count

        except Exception as e:
            logger.error("Failed to cleanup expired sessions", error=str(e))
            self.db_session.rollback()
            return 0

    def _create_usage_log(self, session: UserSession, session_data: Dict[str, Any]):
        """Create usage log entry from session data"""
        try:
            usage_log = UsageLog(
                username=session.username,
                session_id=session.session_id,
                start_time=session.start_time,
                stop_time=session.stop_time or datetime.utcnow(),
                session_time=session.session_time,
                input_octets=session.input_octets,
                output_octets=session.output_octets,
                input_packets=session.input_packets,
                output_packets=session.output_packets,
                nas_ip=session.nas_ip,
                framed_ip=session.framed_ip,
                calling_station_id=session.calling_station_id,
                terminate_cause=session.terminate_cause
            )

            self.db_session.add(usage_log)

        except Exception as e:
            logger.error("Failed to create usage log", error=str(e))

    def _log_radius_event(self, event_type: str, session_data: Dict[str, Any]):
        """Log RADIUS event to database"""
        try:
            radius_log = RadiusLog(
                username=session_data.get('username'),
                session_id=session_data.get('session_id'),
                event_type=event_type,
                nas_ip=session_data.get('nas_ip'),
                nas_port=session_data.get('nas_port'),
                framed_ip=session_data.get('framed_ip'),
                calling_station_id=session_data.get('calling_station_id'),
                event_data=json.dumps(session_data),
                timestamp=datetime.utcnow()
            )

            self.db_session.add(radius_log)

        except Exception as e:
            logger.error("Failed to log RADIUS event", error=str(e))

    def _notify_django_session_event(self, event_type: str, session_data: Dict[str, Any]):
        """Notify Django backend about session events"""
        try:
            if not self.django_api_url or not self.django_api_key:
                return

            headers = {
                'Authorization': f'Bearer {self.django_api_key}',
                'Content-Type': 'application/json'
            }

            payload = {
                'event_type': event_type,
                'session_data': session_data,
                'timestamp': datetime.utcnow().isoformat()
            }

            # Use async request to avoid blocking
            # In production, consider using Celery for this
            requests.post(
                f"{self.django_api_url}/radius/session-event/",
                json=payload,
                headers=headers,
                timeout=5  # Short timeout to avoid blocking
            )

        except Exception as e:
            # Don't fail if Django notification fails
            logger.warning("Failed to notify Django about session event", error=str(e))

    def get_service_stats(self) -> Dict[str, Any]:
        """Get RADIUS service statistics"""
        try:
            # Count active sessions
            active_sessions = self.db_session.query(UserSession).filter_by(status='active').count()

            # Count sessions today
            today = datetime.utcnow().date()
            sessions_today = self.db_session.query(UserSession).filter(
                UserSession.start_time >= today
            ).count()

            # Count total sessions this month
            first_of_month = today.replace(day=1)
            sessions_this_month = self.db_session.query(UserSession).filter(
                UserSession.start_time >= first_of_month
            ).count()

            # Get Redis stats
            redis_info = self.redis_client.info()
            redis_keys = len(self.redis_client.keys("session:*"))

            return {
                'active_sessions': active_sessions,
                'sessions_today': sessions_today,
                'sessions_this_month': sessions_this_month,
                'redis_connected_clients': redis_info.get('connected_clients', 0),
                'redis_memory_usage': redis_info.get('used_memory_human', '0B'),
                'redis_session_keys': redis_keys,
                'timestamp': datetime.utcnow().isoformat()
            }

        except Exception as e:
            logger.error("Failed to get service stats", error=str(e))
            return {
                'error': str(e),
                'timestamp': datetime.utcnow().isoformat()
            }