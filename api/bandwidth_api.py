"""
Bandwidth API Blueprint for ISP Middleware
Provides endpoints for bandwidth management and monitoring
"""

from flask import Blueprint, request, jsonify, current_app, g
import structlog
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from sqlalchemy import func, and_, desc

from services.mikrotik_service import MikroTikService
from services.bandwidth_service import BandwidthService
from models import BandwidthUsage
from models import UserSession
from utils.decorators import (
    api_endpoint, require_api_key, log_api_call,
    validate_json, handle_exceptions, monitor_performance
)

logger = structlog.get_logger()

# Create blueprint
bandwidth_bp = Blueprint('bandwidth', __name__)





@bandwidth_bp.route('/usage/real-time', methods=['GET'])
@api_endpoint(require_auth=True, require_json=False, cache_timeout=10)
def get_real_time_bandwidth():
    """
    Get real-time bandwidth usage
    """
    try:
        username = request.args.get('username')
        minutes = min(int(request.args.get('minutes', 60)), 1440)  # Max 24 hours
        device = request.args.get('device')

        bandwidth_service = BandwidthService(current_app)

        # Get real-time usage data
        usage_data = bandwidth_service.get_real_time_usage(username, minutes)

        # Filter by device if specified
        if device:
            usage_data = [u for u in usage_data if u.nas_ip == device]

        # Format response
        bandwidth_points = []
        for point in usage_data:
            bandwidth_points.append({
                'timestamp': point.timestamp.isoformat(),
                'username': point.username,
                'download_mbps': point.input_speed_mbps,
                'upload_mbps': point.output_speed_mbps,
                'total_mbps': point.input_speed_mbps + point.output_speed_mbps,
                'latency_ms': point.latency,
                'packet_loss_percent': point.packet_loss,
                'nas_ip': point.nas_ip,
                'user_ip': point.framed_ip
            })

        # Calculate summary statistics
        if bandwidth_points:
            downloads = [p['download_mbps'] for p in bandwidth_points]
            uploads = [p['upload_mbps'] for p in bandwidth_points]

            summary = {
                'peak_download_mbps': max(downloads),
                'peak_upload_mbps': max(uploads),
                'avg_download_mbps': round(sum(downloads) / len(downloads), 2),
                'avg_upload_mbps': round(sum(uploads) / len(uploads), 2),
                'min_download_mbps': min(downloads),
                'min_upload_mbps': min(uploads),
                'data_points': len(bandwidth_points)
            }
        else:
            summary = {
                'peak_download_mbps': 0,
                'peak_upload_mbps': 0,
                'avg_download_mbps': 0,
                'avg_upload_mbps': 0,
                'min_download_mbps': 0,
                'min_upload_mbps': 0,
                'data_points': 0
            }

        return jsonify({
            'success': True,
            'period_minutes': minutes,
            'username_filter': username,
            'device_filter': device,
            'bandwidth_data': bandwidth_points,
            'summary': summary,
            'timestamp': datetime.utcnow().isoformat()
        }), 200

    except Exception as e:
        logger.error("Error getting real-time bandwidth", error=str(e))
        return jsonify({
            'success': False,
            'error': 'Internal server error'
        }), 500


@bandwidth_bp.route('/usage/peak', methods=['GET'])
@api_endpoint(require_auth=True, require_json=False, cache_timeout=300)
def get_peak_usage():
    """
    Get peak bandwidth usage statistics
    """
    try:
        username = request.args.get('username')
        hours = min(int(request.args.get('hours', 24)), 168)  # Max 1 week

        bandwidth_service = BandwidthService(current_app)

        # Calculate peak usage
        peak_stats = bandwidth_service.calculate_peak_usage(username, hours)

        return jsonify({
            'success': True,
            'username_filter': username,
            'peak_statistics': peak_stats,
            'timestamp': datetime.utcnow().isoformat()
        }), 200

    except Exception as e:
        logger.error("Error getting peak usage", error=str(e))
        return jsonify({
            'success': False,
            'error': 'Internal server error'
        }), 500


@bandwidth_bp.route('/monitoring/top-users', methods=['GET'])
@api_endpoint(require_auth=True, require_json=False, cache_timeout=300)
def get_top_bandwidth_users():
    """
    Get top users by current bandwidth usage
    """
    try:
        limit = min(int(request.args.get('limit', 20)), 100)
        sort_by = request.args.get('sort_by', 'total')  # total, download, upload
        minutes = min(int(request.args.get('minutes', 30)), 180)  # Max 3 hours

        from flask_sqlalchemy import SQLAlchemy
        db = SQLAlchemy(current_app)

        start_time = datetime.utcnow() - timedelta(minutes=minutes)

        # Query for average bandwidth per user in the specified time period
        if sort_by == 'download':
            order_by = func.avg(BandwidthUsage.input_speed).desc()
        elif sort_by == 'upload':
            order_by = func.avg(BandwidthUsage.output_speed).desc()
        else:  # total
            order_by = func.avg(BandwidthUsage.input_speed + BandwidthUsage.output_speed).desc()

        query = db.session.query(
            BandwidthUsage.username,
            func.avg(BandwidthUsage.input_speed).label('avg_download_bps'),
            func.avg(BandwidthUsage.output_speed).label('avg_upload_bps'),
            func.max(BandwidthUsage.input_speed).label('peak_download_bps'),
            func.max(BandwidthUsage.output_speed).label('peak_upload_bps'),
            func.count(BandwidthUsage.id).label('data_points')
        ).filter(
            BandwidthUsage.timestamp >= start_time
        ).group_by(
            BandwidthUsage.username
        ).order_by(order_by).limit(limit)

        results = query.all()

        # Format results
        top_users = []
        for user in results:
            top_users.append({
                'username': user.username,
                'avg_download_mbps': round(user.avg_download_bps / 1000000, 2),
                'avg_upload_mbps': round(user.avg_upload_bps / 1000000, 2),
                'avg_total_mbps': round((user.avg_download_bps + user.avg_upload_bps) / 1000000, 2),
                'peak_download_mbps': round(user.peak_download_bps / 1000000, 2),
                'peak_upload_mbps': round(user.peak_upload_bps / 1000000, 2),
                'peak_total_mbps': round((user.peak_download_bps + user.peak_upload_bps) / 1000000, 2),
                'data_points': user.data_points
            })

        return jsonify({
            'success': True,
            'period_minutes': minutes,
            'sort_by': sort_by,
            'top_users': top_users,
            'total_users': len(top_users),
            'timestamp': datetime.utcnow().isoformat()
        }), 200

    except Exception as e:
        logger.error("Error getting top bandwidth users", error=str(e))
        return jsonify({
            'success': False,
            'error': 'Internal server error'
        }), 500


@bandwidth_bp.route('/management/throttle', methods=['POST'])
@api_endpoint(
    require_auth=True,
    require_json=True,
    required_fields=['username', 'download_speed', 'upload_speed']
)
def throttle_user_bandwidth():
    """
    Throttle user bandwidth (create/update bandwidth limits)
    """
    try:
        data = g.validated_data
        username = data['username']
        download_speed = max(int(data['download_speed']), 1)  # Min 1 Mbps
        upload_speed = max(int(data['upload_speed']), 1)  # Min 1 Mbps
        device_name = data.get('device_name', 'core_router')

        # Validate speed limits
        max_download = current_app.config.get('MAX_DOWNLOAD_SPEED', 100)
        max_upload = current_app.config.get('MAX_UPLOAD_SPEED', 100)

        if download_speed > max_download or upload_speed > max_upload:
            return jsonify({
                'success': False,
                'error': f'Speed limits exceed maximum allowed (Download: {max_download}Mbps, Upload: {max_upload}Mbps)'
            }), 400

        mikrotik_service = MikroTikService(current_app)

        # Create package info for MikroTik
        package_info = {
            'download_speed': download_speed,
            'upload_speed': upload_speed,
            'package_name': f'Throttled-{download_speed}x{upload_speed}',
            'priority_level': 8  # Lower priority for throttled users
        }

        # Update user bandwidth on MikroTik
        result = mikrotik_service.update_user_bandwidth(username, package_info, device_name)

        if result:
            logger.info(
                f"Throttled user bandwidth: {username}",
                download_speed=download_speed,
                upload_speed=upload_speed,
                device=device_name
            )

            return jsonify({
                'success': True,
                'username': username,
                'new_limits': {
                    'download_mbps': download_speed,
                    'upload_mbps': upload_speed
                },
                'device': device_name,
                'message': f'User {username} bandwidth updated successfully',
                'timestamp': datetime.utcnow().isoformat()
            }), 200
        else:
            logger.error(f"Failed to throttle user bandwidth: {username}")

            return jsonify({
                'success': False,
                'error': 'Failed to update bandwidth limits'
            }), 500

    except Exception as e:
        logger.error("Error throttling user bandwidth", error=str(e))
        return jsonify({
            'success': False,
            'error': 'Internal server error'
        }), 500


@bandwidth_bp.route('/management/remove-throttle', methods=['POST'])
@api_endpoint(
    require_auth=True,
    require_json=True,
    required_fields=['username']
)
def remove_bandwidth_throttle():
    """
    Remove bandwidth throttling (remove queue)
    """
    try:
        data = g.validated_data
        username = data['username']
        device_name = data.get('device_name', 'core_router')

        mikrotik_service = MikroTikService(current_app)

        # Remove user queue
        result = mikrotik_service.remove_user_queue(username, device_name)

        if result:
            logger.info(f"Removed bandwidth throttling for user: {username}", device=device_name)

            return jsonify({
                'success': True,
                'username': username,
                'device': device_name,
                'message': f'Bandwidth throttling removed for user {username}',
                'timestamp': datetime.utcnow().isoformat()
            }), 200
        else:
            logger.warning(f"No bandwidth queue found for user: {username}")

            return jsonify({
                'success': False,
                'error': f'No bandwidth queue found for user {username}'
            }), 404

    except Exception as e:
        logger.error("Error removing bandwidth throttle", error=str(e))
        return jsonify({
            'success': False,
            'error': 'Internal server error'
        }), 500


@bandwidth_bp.route('/monitoring/network-summary', methods=['GET'])
@api_endpoint(require_auth=True, require_json=False, cache_timeout=60)
def get_network_bandwidth_summary():
    """
    Get network-wide bandwidth summary
    """
    try:
        minutes = min(int(request.args.get('minutes', 30)), 180)

        from flask_sqlalchemy import SQLAlchemy
        db = SQLAlchemy(current_app)

        start_time = datetime.utcnow() - timedelta(minutes=minutes)

        # Get aggregated bandwidth statistics
        network_stats = db.session.query(
            func.sum(BandwidthUsage.input_speed).label('total_download_bps'),
            func.sum(BandwidthUsage.output_speed).label('total_upload_bps'),
            func.avg(BandwidthUsage.input_speed).label('avg_download_bps'),
            func.avg(BandwidthUsage.output_speed).label('avg_upload_bps'),
            func.count(func.distinct(BandwidthUsage.username)).label('active_users'),
            func.count(BandwidthUsage.id).label('data_points')
        ).filter(BandwidthUsage.timestamp >= start_time).first()

        # Get per-device statistics
        device_stats = db.session.query(
            BandwidthUsage.nas_ip,
            func.sum(BandwidthUsage.input_speed).label('device_download_bps'),
            func.sum(BandwidthUsage.output_speed).label('device_upload_bps'),
            func.count(func.distinct(BandwidthUsage.username)).label('device_users')
        ).filter(
            BandwidthUsage.timestamp >= start_time
        ).group_by(BandwidthUsage.nas_ip).all()

        # Format network summary
        network_summary = {
            'total_download_mbps': round((network_stats.total_download_bps or 0) / 1000000, 2),
            'total_upload_mbps': round((network_stats.total_upload_bps or 0) / 1000000, 2),
            'total_bandwidth_mbps': round(
                ((network_stats.total_download_bps or 0) + (network_stats.total_upload_bps or 0)) / 1000000, 2),
            'avg_download_mbps': round((network_stats.avg_download_bps or 0) / 1000000, 2),
            'avg_upload_mbps': round((network_stats.avg_upload_bps or 0) / 1000000, 2),
            'active_users': network_stats.active_users or 0,
            'data_points': network_stats.data_points or 0
        }

        # Format device statistics
        device_breakdown = []
        for device in device_stats:
            device_breakdown.append({
                'device_ip': device.nas_ip,
                'download_mbps': round(device.device_download_bps / 1000000, 2),
                'upload_mbps': round(device.device_upload_bps / 1000000, 2),
                'total_mbps': round((device.device_download_bps + device.device_upload_bps) / 1000000, 2),
                'active_users': device.device_users
            })

        return jsonify({
            'success': True,
            'period_minutes': minutes,
            'network_summary': network_summary,
            'device_breakdown': device_breakdown,
            'timestamp': datetime.utcnow().isoformat()
        }), 200

    except Exception as e:
        logger.error("Error getting network bandwidth summary", error=str(e))
        return jsonify({
            'success': False,
            'error': 'Internal server error'
        }), 500


@bandwidth_bp.route('/monitoring/alerts', methods=['GET'])
@api_endpoint(require_auth=True, require_json=False, cache_timeout=60)
def get_bandwidth_alerts():
    """
    Get bandwidth-related alerts and threshold violations
    """
    try:
        threshold_mbps = float(request.args.get('threshold', 50))  # Default 50 Mbps threshold
        minutes = min(int(request.args.get('minutes', 30)), 180)

        from flask_sqlalchemy import SQLAlchemy
        db = SQLAlchemy(current_app)

        start_time = datetime.utcnow() - timedelta(minutes=minutes)
        threshold_bps = threshold_mbps * 1000000  # Convert to bps

        # Find users exceeding bandwidth threshold
        high_usage_users = db.session.query(
            BandwidthUsage.username,
            func.max(BandwidthUsage.input_speed + BandwidthUsage.output_speed).label('peak_usage_bps'),
            func.avg(BandwidthUsage.input_speed + BandwidthUsage.output_speed).label('avg_usage_bps'),
            BandwidthUsage.nas_ip
        ).filter(
            and_(
                BandwidthUsage.timestamp >= start_time,
                BandwidthUsage.input_speed + BandwidthUsage.output_speed > threshold_bps
            )
        ).group_by(
            BandwidthUsage.username, BandwidthUsage.nas_ip
        ).all()

        # Format alerts
        bandwidth_alerts = []
        for user in high_usage_users:
            peak_mbps = round(user.peak_usage_bps / 1000000, 2)
            avg_mbps = round(user.avg_usage_bps / 1000000, 2)

            bandwidth_alerts.append({
                'username': user.username,
                'device_ip': user.nas_ip,
                'peak_usage_mbps': peak_mbps,
                'avg_usage_mbps': avg_mbps,
                'threshold_mbps': threshold_mbps,
                'exceeded_by_mbps': round(peak_mbps - threshold_mbps, 2),
                'severity': 'high' if peak_mbps > threshold_mbps * 2 else 'medium',
                'alert_type': 'bandwidth_threshold_exceeded'
            })

        # Sort by peak usage (highest first)
        bandwidth_alerts.sort(key=lambda x: x['peak_usage_mbps'], reverse=True)

        return jsonify({
            'success': True,
            'threshold_mbps': threshold_mbps,
            'period_minutes': minutes,
            'alerts': bandwidth_alerts,
            'total_alerts': len(bandwidth_alerts),
            'timestamp': datetime.utcnow().isoformat()
        }), 200

    except Exception as e:
        logger.error("Error getting bandwidth alerts", error=str(e))
        return jsonify({
            'success': False,
            'error': 'Internal server error'
        }), 500


@bandwidth_bp.route('/monitoring/quality', methods=['GET'])
@api_endpoint(require_auth=True, require_json=False, cache_timeout=30)
def get_network_quality():
    """
    Get network quality metrics (latency, packet loss)
    """
    try:
        minutes = min(int(request.args.get('minutes', 60)), 1440)
        username = request.args.get('username')

        from flask_sqlalchemy import SQLAlchemy
        db = SQLAlchemy(current_app)

        start_time = datetime.utcnow() - timedelta(minutes=minutes)

        query = db.session.query(
            func.avg(BandwidthUsage.latency).label('avg_latency'),
            func.min(BandwidthUsage.latency).label('min_latency'),
            func.max(BandwidthUsage.latency).label('max_latency'),
            func.avg(BandwidthUsage.packet_loss).label('avg_packet_loss'),
            func.max(BandwidthUsage.packet_loss).label('max_packet_loss'),
            func.count(BandwidthUsage.id).label('measurements')
        ).filter(
            and_(
                BandwidthUsage.timestamp >= start_time,
                BandwidthUsage.latency.isnot(None),
                BandwidthUsage.packet_loss.isnot(None)
            )
        )

        if username:
            query = query.filter(BandwidthUsage.username == username)

        result = query.first()

        # Determine quality rating
        avg_latency = result.avg_latency or 0
        avg_packet_loss = result.avg_packet_loss or 0

        if avg_latency < 50 and avg_packet_loss < 1:
            quality_rating = 'excellent'
        elif avg_latency < 100 and avg_packet_loss < 3:
            quality_rating = 'good'
        elif avg_latency < 200 and avg_packet_loss < 5:
            quality_rating = 'fair'
        else:
            quality_rating = 'poor'

        quality_metrics = {
            'latency': {
                'avg_ms': round(avg_latency, 2),
                'min_ms': round(result.min_latency or 0, 2),
                'max_ms': round(result.max_latency or 0, 2)
            },
            'packet_loss': {
                'avg_percent': round(avg_packet_loss, 2),
                'max_percent': round(result.max_packet_loss or 0, 2)
            },
            'quality_rating': quality_rating,
            'measurements': result.measurements or 0,
            'period_minutes': minutes
        }

        return jsonify({
            'success': True,
            'username_filter': username,
            'quality_metrics': quality_metrics,
            'timestamp': datetime.utcnow().isoformat()
        }), 200

    except Exception as e:
        logger.error("Error getting network quality metrics", error=str(e))
        return jsonify({
            'success': False,
            'error': 'Internal server error'
        }), 500


@bandwidth_bp.route('/health', methods=['GET'])
@api_endpoint(require_auth=False, require_json=False, cache_timeout=30)
def bandwidth_health():
    """
    Bandwidth service health check
    """
    try:
        # Check MikroTik connection
        mikrotik_service = MikroTikService(current_app)
        mikrotik_status = mikrotik_service.check_connection()

        # Check recent bandwidth data
        from flask_sqlalchemy import SQLAlchemy
        db = SQLAlchemy(current_app)

        recent_data_count = db.session.query(BandwidthUsage).filter(
            BandwidthUsage.timestamp >= datetime.utcnow() - timedelta(minutes=10)
        ).count()

        # Determine health status
        if mikrotik_status and recent_data_count > 0:
            health_status = 'healthy'
        elif mikrotik_status or recent_data_count > 0:
            health_status = 'degraded'
        else:
            health_status = 'unhealthy'

        return jsonify({
            'status': health_status,
            'service': 'bandwidth_monitoring',
            'timestamp': datetime.utcnow().isoformat(),
            'details': {
                'mikrotik_connected': mikrotik_status,
                'recent_data_points': recent_data_count,
                'data_collection_active': recent_data_count > 0
            }
        }), 200

    except Exception as e:
        logger.error("Bandwidth health check failed", error=str(e))
        return jsonify({
            'status': 'unhealthy',
            'service': 'bandwidth_monitoring',
            'timestamp': datetime.utcnow().isoformat(),
            'error': str(e)
        }), 500


# Error handlers for this blueprint
@bandwidth_bp.errorhandler(404)
def not_found_handler(e):
    return jsonify({
        'success': False,
        'error': 'Not found',
        'message': 'The requested bandwidth resource was not found'
    }), 404


@bandwidth_bp.errorhandler(429)
def ratelimit_handler(e):
    return jsonify({
        'success': False,
        'error': 'Rate limit exceeded',
        'message': 'Too many bandwidth API requests',
        'retry_after': str(e.retry_after)
    }), 429


@bandwidth_bp.errorhandler(500)
def internal_error_handler(e):
    logger.error("Internal server error in bandwidth API", error=str(e))
    return jsonify({
        'success': False,
        'error': 'Internal server error',
        'message': 'Bandwidth monitoring service error'
    }), 500