"""
Usage API Blueprint for ISP Middleware
Provides endpoints for usage tracking, statistics, and monitoring
"""

from flask import Blueprint, request, jsonify, current_app, g
import structlog
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from sqlalchemy import func, and_

from services.radius_service import RadiusService
from models import UserSession
from models import UsageLog
from models import BandwidthUsage
from models import AlertLog
from utils.decorators import (
    api_endpoint, require_api_key, log_api_call,
    validate_json, handle_exceptions, monitor_performance
)

logger = structlog.get_logger()

# Create blueprint
usage_bp = Blueprint('usage', __name__)


@usage_bp.route('/sessions/active', methods=['GET'])
@api_endpoint(require_auth=True, require_json=False, cache_timeout=30)
def get_active_sessions():
    """
    Get all active user sessions
    """
    try:
        username = request.args.get('username')
        device = request.args.get('device')
        limit = min(int(request.args.get('limit', 100)), 1000)  # Max 1000 sessions

        radius_service = RadiusService(current_app)

        # Get active sessions
        sessions = radius_service.get_active_sessions(username)

        # Filter by device if specified
        if device:
            sessions = [s for s in sessions if s.get('nas_ip') == device]

        # Apply limit
        sessions = sessions[:limit]

        # Calculate totals
        total_input = sum(s.get('input_octets', 0) for s in sessions)
        total_output = sum(s.get('output_octets', 0) for s in sessions)

        return jsonify({
            'success': True,
            'active_sessions': sessions,
            'total_sessions': len(sessions),
            'summary': {
                'total_input_mb': round(total_input / (1024 * 1024), 2),
                'total_output_mb': round(total_output / (1024 * 1024), 2),
                'total_data_mb': round((total_input + total_output) / (1024 * 1024), 2)
            },
            'timestamp': datetime.utcnow().isoformat()
        }), 200

    except Exception as e:
        logger.error("Error getting active sessions", error=str(e))
        return jsonify({
            'success': False,
            'error': 'Internal server error'
        }), 500


@usage_bp.route('/sessions/<username>/history', methods=['GET'])
@api_endpoint(require_auth=True, require_json=False, cache_timeout=300)
def get_user_session_history(username):
    """
    Get session history for a specific user
    """
    try:
        days = min(int(request.args.get('days', 30)), 365)  # Max 1 year

        radius_service = RadiusService(current_app)

        # Get session history
        sessions = radius_service.get_session_history(username, days)

        # Calculate statistics
        total_sessions = len(sessions)
        total_time = sum(s.get('session_time', 0) for s in sessions)
        total_input = sum(s.get('input_octets', 0) for s in sessions)
        total_output = sum(s.get('output_octets', 0) for s in sessions)

        # Calculate averages
        avg_session_time = total_time / max(total_sessions, 1)
        avg_data_per_session = (total_input + total_output) / max(total_sessions, 1)

        return jsonify({
            'success': True,
            'username': username,
            'period_days': days,
            'sessions': sessions,
            'statistics': {
                'total_sessions': total_sessions,
                'total_session_time_hours': round(total_time / 3600, 2),
                'total_input_mb': round(total_input / (1024 * 1024), 2),
                'total_output_mb': round(total_output / (1024 * 1024), 2),
                'total_data_mb': round((total_input + total_output) / (1024 * 1024), 2),
                'average_session_time_minutes': round(avg_session_time / 60, 2),
                'average_data_per_session_mb': round(avg_data_per_session / (1024 * 1024), 2)
            },
            'timestamp': datetime.utcnow().isoformat()
        }), 200

    except Exception as e:
        logger.error(f"Error getting session history for {username}", error=str(e))
        return jsonify({
            'success': False,
            'error': 'Internal server error'
        }), 500


@usage_bp.route('/stats/summary', methods=['GET'])
@api_endpoint(require_auth=True, require_json=False, cache_timeout=300)
def get_usage_summary():
    """
    Get overall usage statistics summary
    """
    try:
        days = min(int(request.args.get('days', 7)), 90)  # Max 90 days

        radius_service = RadiusService(current_app)

        # Get usage statistics
        stats = radius_service.get_usage_stats(days=days)

        # Get additional database statistics
        from flask_sqlalchemy import SQLAlchemy
        db = SQLAlchemy(current_app)

        start_date = datetime.utcnow() - timedelta(days=days)

        # Count unique users
        unique_users = db.session.query(
            func.count(func.distinct(UsageLog.username))
        ).filter(UsageLog.created_at >= start_date).scalar()

        # Count sessions by day
        daily_sessions = db.session.query(
            func.date(UsageLog.start_time).label('date'),
            func.count(UsageLog.id).label('sessions'),
            func.sum(UsageLog.input_octets + UsageLog.output_octets).label('total_bytes')
        ).filter(UsageLog.start_time >= start_date).group_by(
            func.date(UsageLog.start_time)
        ).order_by('date').all()

        # Format daily statistics
        daily_stats = []
        for day in daily_sessions:
            daily_stats.append({
                'date': day.date.isoformat(),
                'sessions': day.sessions,
                'total_mb': round((day.total_bytes or 0) / (1024 * 1024), 2)
            })

        # Get current active sessions count
        active_sessions_count = db.session.query(UserSession).filter_by(status='active').count()

        response_data = {
            'success': True,
            'period_days': days,
            'summary': stats,
            'unique_users': unique_users,
            'active_sessions': active_sessions_count,
            'daily_statistics': daily_stats,
            'timestamp': datetime.utcnow().isoformat()
        }

        return jsonify(response_data), 200

    except Exception as e:
        logger.error("Error getting usage summary", error=str(e))
        return jsonify({
            'success': False,
            'error': 'Internal server error'
        }), 500


@usage_bp.route('/bandwidth/real-time', methods=['GET'])
@api_endpoint(require_auth=True, require_json=False, cache_timeout=10)
def get_real_time_bandwidth():
    """
    Get real-time bandwidth usage data
    """
    try:
        username = request.args.get('username')
        device = request.args.get('device')
        minutes = min(int(request.args.get('minutes', 60)), 1440)  # Max 24 hours

        from flask_sqlalchemy import SQLAlchemy
        db = SQLAlchemy(current_app)

        # Query bandwidth usage from last N minutes
        start_time = datetime.utcnow() - timedelta(minutes=minutes)

        query = db.session.query(BandwidthUsage).filter(
            BandwidthUsage.timestamp >= start_time
        )

        if username:
            query = query.filter(BandwidthUsage.username == username)

        if device:
            query = query.filter(BandwidthUsage.nas_ip == device)

        bandwidth_data = query.order_by(BandwidthUsage.timestamp.desc()).limit(1000).all()

        # Format response
        data_points = []
        for point in bandwidth_data:
            data_points.append({
                'timestamp': point.timestamp.isoformat(),
                'username': point.username,
                'input_speed_mbps': point.input_speed_mbps,
                'output_speed_mbps': point.output_speed_mbps,
                'total_speed_mbps': point.input_speed_mbps + point.output_speed_mbps,
                'latency': point.latency,
                'packet_loss': point.packet_loss,
                'nas_ip': point.nas_ip,
                'framed_ip': point.framed_ip
            })

        # Calculate summary statistics
        if data_points:
            avg_input = sum(p['input_speed_mbps'] for p in data_points) / len(data_points)
            avg_output = sum(p['output_speed_mbps'] for p in data_points) / len(data_points)
            max_input = max(p['input_speed_mbps'] for p in data_points)
            max_output = max(p['output_speed_mbps'] for p in data_points)

            summary = {
                'average_input_mbps': round(avg_input, 2),
                'average_output_mbps': round(avg_output, 2),
                'peak_input_mbps': round(max_input, 2),
                'peak_output_mbps': round(max_output, 2),
                'total_data_points': len(data_points)
            }
        else:
            summary = {
                'average_input_mbps': 0,
                'average_output_mbps': 0,
                'peak_input_mbps': 0,
                'peak_output_mbps': 0,
                'total_data_points': 0
            }

        return jsonify({
            'success': True,
            'period_minutes': minutes,
            'username_filter': username,
            'device_filter': device,
            'bandwidth_data': data_points,
            'summary': summary,
            'timestamp': datetime.utcnow().isoformat()
        }), 200

    except Exception as e:
        logger.error("Error getting real-time bandwidth data", error=str(e))
        return jsonify({
            'success': False,
            'error': 'Internal server error'
        }), 500


@usage_bp.route('/usage/top-users', methods=['GET'])
@api_endpoint(require_auth=True, require_json=False, cache_timeout=300)
def get_top_users():
    """
    Get top users by data usage
    """
    try:
        days = min(int(request.args.get('days', 7)), 90)
        limit = min(int(request.args.get('limit', 20)), 100)
        sort_by = request.args.get('sort_by', 'data')  # data, sessions, time

        from flask_sqlalchemy import SQLAlchemy
        db = SQLAlchemy(current_app)

        start_date = datetime.utcnow() - timedelta(days=days)

        # Build query based on sort criteria
        if sort_by == 'data':
            # Sort by total data usage
            query = db.session.query(
                UsageLog.username,
                func.sum(UsageLog.input_octets + UsageLog.output_octets).label('total_bytes'),
                func.count(UsageLog.id).label('total_sessions'),
                func.sum(UsageLog.session_time).label('total_time')
            ).filter(UsageLog.start_time >= start_date).group_by(
                UsageLog.username
            ).order_by(func.sum(UsageLog.input_octets + UsageLog.output_octets).desc())

        elif sort_by == 'sessions':
            # Sort by number of sessions
            query = db.session.query(
                UsageLog.username,
                func.sum(UsageLog.input_octets + UsageLog.output_octets).label('total_bytes'),
                func.count(UsageLog.id).label('total_sessions'),
                func.sum(UsageLog.session_time).label('total_time')
            ).filter(UsageLog.start_time >= start_date).group_by(
                UsageLog.username
            ).order_by(func.count(UsageLog.id).desc())

        else:  # time
            # Sort by total session time
            query = db.session.query(
                UsageLog.username,
                func.sum(UsageLog.input_octets + UsageLog.output_octets).label('total_bytes'),
                func.count(UsageLog.id).label('total_sessions'),
                func.sum(UsageLog.session_time).label('total_time')
            ).filter(UsageLog.start_time >= start_date).group_by(
                UsageLog.username
            ).order_by(func.sum(UsageLog.session_time).desc())

        results = query.limit(limit).all()

        # Format results
        top_users = []
        for user in results:
            top_users.append({
                'username': user.username,
                'total_data_mb': round((user.total_bytes or 0) / (1024 * 1024), 2),
                'total_sessions': user.total_sessions,
                'total_time_hours': round((user.total_time or 0) / 3600, 2),
                'average_session_mb': round((user.total_bytes or 0) / (1024 * 1024) / max(user.total_sessions, 1), 2),
                'average_session_minutes': round((user.total_time or 0) / 60 / max(user.total_sessions, 1), 2)
            })

        return jsonify({
            'success': True,
            'period_days': days,
            'sort_by': sort_by,
            'top_users': top_users,
            'total_users': len(top_users),
            'timestamp': datetime.utcnow().isoformat()
        }), 200

    except Exception as e:
        logger.error("Error getting top users", error=str(e))
        return jsonify({
            'success': False,
            'error': 'Internal server error'
        }), 500


@usage_bp.route('/alerts', methods=['GET'])
@api_endpoint(require_auth=True, require_json=False, cache_timeout=60)
def get_alerts():
    """
    Get system alerts and notifications
    """
    try:
        status = request.args.get('status', 'active')
        severity = request.args.get('severity')
        alert_type = request.args.get('type')
        limit = min(int(request.args.get('limit', 50)), 200)

        from flask_sqlalchemy import SQLAlchemy
        db = SQLAlchemy(current_app)

        # Build query
        query = db.session.query(AlertLog)

        if status:
            query = query.filter(AlertLog.status == status)

        if severity:
            query = query.filter(AlertLog.severity == severity)

        if alert_type:
            query = query.filter(AlertLog.alert_type == alert_type)

        alerts = query.order_by(AlertLog.created_at.desc()).limit(limit).all()

        # Format alerts
        alert_list = []
        for alert in alerts:
            alert_list.append({
                'id': alert.id,
                'type': alert.alert_type,
                'severity': alert.severity,
                'title': alert.title,
                'message': alert.message,
                'username': alert.username,
                'device_ip': alert.device_ip,
                'status': alert.status,
                'created_at': alert.created_at.isoformat(),
                'acknowledged_by': alert.acknowledged_by,
                'acknowledged_at': alert.acknowledged_at.isoformat() if alert.acknowledged_at else None
            })

        # Get alert summary
        alert_summary = db.session.query(
            AlertLog.severity,
            func.count(AlertLog.id).label('count')
        ).filter(AlertLog.status == 'active').group_by(AlertLog.severity).all()

        summary = {row.severity: row.count for row in alert_summary}

        return jsonify({
            'success': True,
            'alerts': alert_list,
            'total_alerts': len(alert_list),
            'summary': summary,
            'filters': {
                'status': status,
                'severity': severity,
                'type': alert_type
            },
            'timestamp': datetime.utcnow().isoformat()
        }), 200

    except Exception as e:
        logger.error("Error getting alerts", error=str(e))
        return jsonify({
            'success': False,
            'error': 'Internal server error'
        }), 500


@usage_bp.route('/sessions/terminate', methods=['POST'])
@api_endpoint(
    require_auth=True,
    require_json=True,
    required_fields=['username']
)
def terminate_user_sessions():
    """
    Terminate all active sessions for a user
    """
    try:
        data = g.validated_data
        username = data['username']
        reason = data.get('reason', 'Administrative termination')

        radius_service = RadiusService(current_app)

        # Terminate all sessions for user
        terminated_count = radius_service.terminate_user_sessions(username, reason)

        logger.info(f"Terminated {terminated_count} sessions for user: {username}", reason=reason)

        return jsonify({
            'success': True,
            'username': username,
            'terminated_sessions': terminated_count,
            'reason': reason,
            'timestamp': datetime.utcnow().isoformat()
        }), 200

    except Exception as e:
        logger.error("Error terminating user sessions", error=str(e))
        return jsonify({
            'success': False,
            'error': 'Internal server error'
        }), 500


@usage_bp.route('/maintenance/cleanup', methods=['POST'])
@api_endpoint(require_auth=True, require_json=False, rate_limit=5)
def cleanup_expired_sessions():
    """
    Clean up expired sessions (maintenance endpoint)
    """
    try:
        radius_service = RadiusService(current_app)

        # Clean up expired sessions
        cleaned_count = radius_service.cleanup_expired_sessions()

        logger.info(f"Cleaned up {cleaned_count} expired sessions")

        return jsonify({
            'success': True,
            'cleaned_sessions': cleaned_count,
            'message': f'Successfully cleaned up {cleaned_count} expired sessions',
            'timestamp': datetime.utcnow().isoformat()
        }), 200

    except Exception as e:
        logger.error("Error cleaning up expired sessions", error=str(e))
        return jsonify({
            'success': False,
            'error': 'Internal server error'
        }), 500


@usage_bp.route('/reports/daily', methods=['GET'])
@api_endpoint(require_auth=True, require_json=False, cache_timeout=3600)
def get_daily_report():
    """
    Get daily usage report
    """
    try:
        date_str = request.args.get('date', datetime.utcnow().date().isoformat())
        report_date = datetime.strptime(date_str, '%Y-%m-%d').date()

        from flask_sqlalchemy import SQLAlchemy
        db = SQLAlchemy(current_app)

        # Get daily statistics
        start_time = datetime.combine(report_date, datetime.min.time())
        end_time = start_time + timedelta(days=1)

        # Total sessions
        total_sessions = db.session.query(UsageLog).filter(
            and_(UsageLog.start_time >= start_time, UsageLog.start_time < end_time)
        ).count()

        # Unique users
        unique_users = db.session.query(
            func.count(func.distinct(UsageLog.username))
        ).filter(
            and_(UsageLog.start_time >= start_time, UsageLog.start_time < end_time)
        ).scalar()

        # Total data usage
        data_stats = db.session.query(
            func.sum(UsageLog.input_octets).label('total_input'),
            func.sum(UsageLog.output_octets).label('total_output'),
            func.sum(UsageLog.session_time).label('total_time')
        ).filter(
            and_(UsageLog.start_time >= start_time, UsageLog.start_time < end_time)
        ).first()

        # Peak concurrent sessions
        peak_sessions = db.session.query(
            func.max(UserSession.id)
        ).filter(
            and_(
                UserSession.start_time <= end_time,
                func.coalesce(UserSession.stop_time, datetime.utcnow()) >= start_time
            )
        ).scalar() or 0

        # Top users by data usage
        top_users_query = db.session.query(
            UsageLog.username,
            func.sum(UsageLog.input_octets + UsageLog.output_octets).label('total_bytes')
        ).filter(
            and_(UsageLog.start_time >= start_time, UsageLog.start_time < end_time)
        ).group_by(UsageLog.username).order_by(
            func.sum(UsageLog.input_octets + UsageLog.output_octets).desc()
        ).limit(10).all()

        top_users = []
        for user in top_users_query:
            top_users.append({
                'username': user.username,
                'data_mb': round((user.total_bytes or 0) / (1024 * 1024), 2)
            })

        # Format report
        report = {
            'date': date_str,
            'summary': {
                'total_sessions': total_sessions,
                'unique_users': unique_users,
                'peak_concurrent_sessions': peak_sessions,
                'total_data_gb': round(
                    (data_stats.total_input or 0 + data_stats.total_output or 0) / (1024 * 1024 * 1024), 2),
                'total_session_hours': round((data_stats.total_time or 0) / 3600, 2),
                'average_session_minutes': round((data_stats.total_time or 0) / 60 / max(total_sessions, 1), 2)
            },
            'top_users': top_users
        }

        return jsonify({
            'success': True,
            'report': report,
            'timestamp': datetime.utcnow().isoformat()
        }), 200

    except Exception as e:
        logger.error("Error generating daily report", error=str(e))
        return jsonify({
            'success': False,
            'error': 'Internal server error'
        }), 500


@usage_bp.route('/health', methods=['GET'])
@api_endpoint(require_auth=False, require_json=False, cache_timeout=30)
def usage_health():
    """
    Usage service health check
    """
    try:
        radius_service = RadiusService(current_app)

        # Check service status
        service_status = radius_service.check_status()

        # Get service stats
        stats = radius_service.get_service_stats()

        return jsonify({
            'status': 'healthy' if service_status else 'unhealthy',
            'service': 'usage_tracking',
            'timestamp': datetime.utcnow().isoformat(),
            'stats': stats
        }), 200

    except Exception as e:
        logger.error("Usage health check failed", error=str(e))
        return jsonify({
            'status': 'unhealthy',
            'service': 'usage_tracking',
            'timestamp': datetime.utcnow().isoformat(),
            'error': str(e)
        }), 500


# Error handlers for this blueprint
@usage_bp.errorhandler(404)
def not_found_handler(e):
    return jsonify({
        'success': False,
        'error': 'Not found',
        'message': 'The requested usage data was not found'
    }), 404


@usage_bp.errorhandler(429)
def ratelimit_handler(e):
    return jsonify({
        'success': False,
        'error': 'Rate limit exceeded',
        'message': 'Too many usage API requests',
        'retry_after': str(e.retry_after)
    }), 429


@usage_bp.errorhandler(500)
def internal_error_handler(e):
    logger.error("Internal server error in usage API", error=str(e))
    return jsonify({
        'success': False,
        'error': 'Internal server error',
        'message': 'Usage tracking service error'
    }), 500