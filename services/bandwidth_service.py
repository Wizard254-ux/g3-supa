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
from models import BandwidthUsage

logger = structlog.get_logger()

# Create blueprint
bandwidth_bp = Blueprint('bandwidth', __name__)


class BandwidthService:
    """Service for bandwidth management and monitoring"""

    def __init__(self, app=None):
        self.app = app
        if app:
            self.init_app(app)

    def init_app(self, app):
        """Initialize the service with Flask app"""
        self.app = app
        self.mikrotik_service = MikroTikService(app)
        logger.info("Bandwidth service initialized")

    def get_real_time_usage(self, username: str = None, minutes: int = 60) -> List[Dict]:
        """Get real-time bandwidth usage data"""
        try:
            from flask_sqlalchemy import SQLAlchemy
            db = SQLAlchemy(self.app)

            start_time = datetime.utcnow() - timedelta(minutes=minutes)

            query = db.session.query(BandwidthUsage).filter(
                BandwidthUsage.timestamp >= start_time
            )

            if username:
                query = query.filter(BandwidthUsage.username == username)

            return query.order_by(BandwidthUsage.timestamp.desc()).limit(1000).all()

        except Exception as e:
            logger.error("Failed to get real-time usage", error=str(e))
            return []

    def calculate_peak_usage(self, username: str = None, hours: int = 24) -> Dict:
        """Calculate peak bandwidth usage"""
        try:
            from flask_sqlalchemy import SQLAlchemy
            db = SQLAlchemy(self.app)

            start_time = datetime.utcnow() - timedelta(hours=hours)

            query = db.session.query(
                func.max(BandwidthUsage.input_speed).label('peak_download'),
                func.max(BandwidthUsage.output_speed).label('peak_upload'),
                func.avg(BandwidthUsage.input_speed).label('avg_download'),
                func.avg(BandwidthUsage.output_speed).label('avg_upload')
            ).filter(BandwidthUsage.timestamp >= start_time)

            if username:
                query = query.filter(BandwidthUsage.username == username)

            result = query.first()

            return {
                'peak_download_mbps': round((result.peak_download or 0) / 1000000, 2),
                'peak_upload_mbps': round((result.peak_upload or 0) / 1000000, 2),
                'avg_download_mbps': round((result.avg_download or 0) / 1000000, 2),
                'avg_upload_mbps': round((result.avg_upload or 0) / 1000000, 2),
                'period_hours': hours
            }

        except Exception as e:
            logger.error("Failed to calculate peak usage", error=str(e))
            return {}