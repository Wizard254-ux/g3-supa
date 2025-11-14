"""
Database Models for ISP Middleware Flask Application
SQLAlchemy models for session tracking, usage logs, and RADIUS data
"""
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import uuid
import json
db = SQLAlchemy()
migrate = Migrate()


class User(db.Model):
    """User model for authentication and authorization"""
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False, index=True)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    password = db.Column(db.String(255), nullable=False)

    # User Type and Permissions
    user_type = db.Column(db.String(50), default='user')  # user, admin, super_admin

    # Account Status
    is_active = db.Column(db.Boolean, default=True)
    is_verified = db.Column(db.Boolean, default=False)

    # Profile Information
    first_name = db.Column(db.String(100))
    last_name = db.Column(db.String(100))
    phone = db.Column(db.String(50))

    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_login = db.Column(db.DateTime)

    def __repr__(self):
        return f'<User {self.username}>'

    @property
    def is_admin(self):
        return self.user_type in ('admin', 'super_admin')

    @property
    def is_super_admin(self):
        return self.user_type == 'super_admin'

    @property
    def full_name(self):
        if self.first_name and self.last_name:
            return f"{self.first_name} {self.last_name}"
        return self.username

    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'user_type': self.user_type,
            'is_active': self.is_active,
            'is_verified': self.is_verified,
            'first_name': self.first_name,
            'last_name': self.last_name,
            'phone': self.phone,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat(),
            'last_login': self.last_login.isoformat() if self.last_login else None
        }


class UserSession(db.Model):
    """User session model for tracking active RADIUS sessions"""
    __tablename__ = 'user_sessions'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False, index=True)
    session_id = db.Column(db.String(255), unique=True, nullable=False, index=True)

    # NAS Information
    nas_ip = db.Column(db.String(45))  # IPv6 support
    nas_port = db.Column(db.String(50))
    nas_identifier = db.Column(db.String(100))

    # User Network Information
    framed_ip = db.Column(db.String(45))  # IPv6 support
    calling_station_id = db.Column(db.String(50))  # MAC address
    called_station_id = db.Column(db.String(50))  # AP MAC/SSID

    # Session Timing
    start_time = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    stop_time = db.Column(db.DateTime)
    last_update = db.Column(db.DateTime, default=datetime.utcnow)
    session_time = db.Column(db.Integer, default=0)  # seconds

    # Usage Statistics
    input_octets = db.Column(db.BigInteger, default=0)
    output_octets = db.Column(db.BigInteger, default=0)
    input_packets = db.Column(db.Integer, default=0)
    output_packets = db.Column(db.Integer, default=0)

    # Session Status
    status = db.Column(
        db.String(20),
        default='active',
        nullable=False
    )  # active, stopped, terminated, expired
    terminate_cause = db.Column(db.String(100))

    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Indexes
    __table_args__ = (
        db.Index('idx_username_status', 'username', 'status'),
        db.Index('idx_start_time', 'start_time'),
        db.Index('idx_nas_ip', 'nas_ip'),
    )

    def __repr__(self):
        return f'<UserSession {self.username}:{self.session_id}>'

    @property
    def total_octets(self):
        return self.input_octets + self.output_octets

    @property
    def is_active(self):
        return self.status == 'active'

    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'session_id': self.session_id,
            'nas_ip': self.nas_ip,
            'framed_ip': self.framed_ip,
            'start_time': self.start_time.isoformat() if self.start_time else None,
            'stop_time': self.stop_time.isoformat() if self.stop_time else None,
            'session_time': self.session_time,
            'input_octets': self.input_octets,
            'output_octets': self.output_octets,
            'total_octets': self.total_octets,
            'status': self.status,
            'terminate_cause': self.terminate_cause
        }


class UsageLog(db.Model):
    """Usage log model for storing completed session data"""
    __tablename__ = 'usage_logs'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False, index=True)
    session_id = db.Column(db.String(255), nullable=False, index=True)

    # Session Timing
    start_time = db.Column(db.DateTime, nullable=False)
    stop_time = db.Column(db.DateTime, nullable=False)
    session_time = db.Column(db.Integer, default=0)  # seconds

    # Usage Statistics
    input_octets = db.Column(db.BigInteger, default=0)
    output_octets = db.Column(db.BigInteger, default=0)
    input_packets = db.Column(db.Integer, default=0)
    output_packets = db.Column(db.Integer, default=0)

    # Network Information
    nas_ip = db.Column(db.String(45))
    framed_ip = db.Column(db.String(45))
    calling_station_id = db.Column(db.String(50))
    terminate_cause = db.Column(db.String(100))

    # Package Information (denormalized for faster queries)
    package_name = db.Column(db.String(200))
    package_type = db.Column(db.String(50))
    download_speed = db.Column(db.Integer)  # Mbps
    upload_speed = db.Column(db.Integer)  # Mbps

    # Billing Information
    billable = db.Column(db.Boolean, default=True)
    billed = db.Column(db.Boolean, default=False)
    billing_date = db.Column(db.DateTime)

    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    # Indexes
    __table_args__ = (
        db.Index('idx_username_date', 'username', 'start_time'),
        db.Index('idx_stop_time', 'stop_time'),
        db.Index('idx_billable', 'billable', 'billed'),
    )

    def __repr__(self):
        return f'<UsageLog {self.username}:{self.session_id}>'

    @property
    def total_octets(self):
        return self.input_octets + self.output_octets

    @property
    def total_mb(self):
        return round(self.total_octets / (1024 * 1024), 2)

    @property
    def session_duration_hours(self):
        return round(self.session_time / 3600, 2)

    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'session_id': self.session_id,
            'start_time': self.start_time.isoformat(),
            'stop_time': self.stop_time.isoformat(),
            'session_time': self.session_time,
            'session_duration_hours': self.session_duration_hours,
            'input_octets': self.input_octets,
            'output_octets': self.output_octets,
            'total_octets': self.total_octets,
            'total_mb': self.total_mb,
            'nas_ip': self.nas_ip,
            'framed_ip': self.framed_ip,
            'calling_station_id': self.calling_station_id,
            'terminate_cause': self.terminate_cause,
            'package_name': self.package_name,
            'package_type': self.package_type,
            'download_speed': self.download_speed,
            'upload_speed': self.upload_speed,
            'billable': self.billable,
            'billed': self.billed
        }


class RadiusLog(db.Model):
    """RADIUS event log model for audit trail"""
    __tablename__ = 'radius_logs'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), index=True)
    session_id = db.Column(db.String(255), index=True)

    # Event Information
    event_type = db.Column(db.String(50), nullable=False)  # Start, Stop, Interim-Update, Auth-Request
    event_result = db.Column(db.String(50))  # Accept, Reject, Challenge

    # NAS Information
    nas_ip = db.Column(db.String(45))
    nas_port = db.Column(db.String(50))
    nas_identifier = db.Column(db.String(100))

    # Network Information
    framed_ip = db.Column(db.String(45))
    calling_station_id = db.Column(db.String(50))
    called_station_id = db.Column(db.String(50))

    # Event Data (JSON)
    event_data = db.Column(db.Text)  # JSON string of all RADIUS attributes

    # Error Information
    error_message = db.Column(db.Text)

    # Timestamp
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)

    # Indexes
    __table_args__ = (
        db.Index('idx_username_timestamp', 'username', 'timestamp'),
        db.Index('idx_event_type_timestamp', 'event_type', 'timestamp'),
        db.Index('idx_nas_ip_timestamp', 'nas_ip', 'timestamp'),
    )

    def __repr__(self):
        return f'<RadiusLog {self.event_type}:{self.username}>'

    def get_event_data(self):
        """Parse JSON event data"""
        if self.event_data:
            try:
                return json.loads(self.event_data)
            except json.JSONDecodeError:
                return {}
        return {}

    def set_event_data(self, data):
        """Set event data as JSON"""
        self.event_data = json.dumps(data) if data else None

    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'session_id': self.session_id,
            'event_type': self.event_type,
            'event_result': self.event_result,
            'nas_ip': self.nas_ip,
            'framed_ip': self.framed_ip,
            'calling_station_id': self.calling_station_id,
            'event_data': self.get_event_data(),
            'error_message': self.error_message,
            'timestamp': self.timestamp.isoformat()
        }


class NetworkDevice(db.Model):
    """Network device model for tracking NAS devices"""
    __tablename__ = 'network_devices'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)

    # Network Information
    ip_address = db.Column(db.String(45), unique=True, nullable=False, index=True)
    nas_identifier = db.Column(db.String(100), unique=True)

    # Device Information
    device_type = db.Column(db.String(50))  # router, switch, access_point, nas
    vendor = db.Column(db.String(100))
    model = db.Column(db.String(100))
    location = db.Column(db.String(200))

    # RADIUS Configuration
    shared_secret = db.Column(db.String(255))  # Encrypted
    auth_port = db.Column(db.Integer, default=1812)
    acct_port = db.Column(db.Integer, default=1813)

    # Status and Health
    status = db.Column(db.String(20), default='active')  # active, inactive, maintenance
    last_seen = db.Column(db.DateTime)
    health_status = db.Column(db.String(20), default='unknown')  # healthy, warning, critical, unknown

    # Configuration
    config_backup = db.Column(db.Text)  # Last configuration backup
    backup_date = db.Column(db.DateTime)

    # Statistics
    total_sessions = db.Column(db.Integer, default=0)
    current_sessions = db.Column(db.Integer, default=0)

    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self):
        return f'<NetworkDevice {self.name}:{self.ip_address}>'

    @property
    def is_active(self):
        return self.status == 'active'

    @property
    def is_healthy(self):
        return self.health_status == 'healthy'

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'ip_address': self.ip_address,
            'nas_identifier': self.nas_identifier,
            'device_type': self.device_type,
            'vendor': self.vendor,
            'model': self.model,
            'location': self.location,
            'status': self.status,
            'health_status': self.health_status,
            'last_seen': self.last_seen.isoformat() if self.last_seen else None,
            'total_sessions': self.total_sessions,
            'current_sessions': self.current_sessions,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat()
        }


class BandwidthUsage(db.Model):
    """Bandwidth usage tracking for real-time monitoring"""
    __tablename__ = 'bandwidth_usage'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False, index=True)
    session_id = db.Column(db.String(255), index=True)

    # Timestamp (for time-series data)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)

    # Bandwidth Data (in bytes)
    input_octets = db.Column(db.BigInteger, default=0)
    output_octets = db.Column(db.BigInteger, default=0)

    # Speed Data (in bps - calculated)
    input_speed = db.Column(db.Integer, default=0)  # bps
    output_speed = db.Column(db.Integer, default=0)  # bps

    # Quality Metrics
    latency = db.Column(db.Integer)  # milliseconds
    packet_loss = db.Column(db.Float)  # percentage
    jitter = db.Column(db.Integer)  # milliseconds

    # Network Information
    nas_ip = db.Column(db.String(45))
    framed_ip = db.Column(db.String(45))

    # Indexes for time-series queries
    __table_args__ = (
        db.Index('idx_username_timestamp', 'username', 'timestamp'),
        db.Index('idx_session_timestamp', 'session_id', 'timestamp'),
        db.Index('idx_timestamp_only', 'timestamp'),
    )

    def __repr__(self):
        return f'<BandwidthUsage {self.username}:{self.timestamp}>'

    @property
    def total_octets(self):
        return self.input_octets + self.output_octets

    @property
    def input_speed_mbps(self):
        return round(self.input_speed / 1000000, 2) if self.input_speed else 0

    @property
    def output_speed_mbps(self):
        return round(self.output_speed / 1000000, 2) if self.output_speed else 0

    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'session_id': self.session_id,
            'timestamp': self.timestamp.isoformat(),
            'input_octets': self.input_octets,
            'output_octets': self.output_octets,
            'total_octets': self.total_octets,
            'input_speed': self.input_speed,
            'output_speed': self.output_speed,
            'input_speed_mbps': self.input_speed_mbps,
            'output_speed_mbps': self.output_speed_mbps,
            'latency': self.latency,
            'packet_loss': self.packet_loss,
            'jitter': self.jitter,
            'nas_ip': self.nas_ip,
            'framed_ip': self.framed_ip
        }


class AlertLog(db.Model):
    """Alert log for system notifications and warnings"""
    __tablename__ = 'alert_logs'

    id = db.Column(db.Integer, primary_key=True)

    # Alert Information
    alert_type = db.Column(db.String(50), nullable=False)  # bandwidth, usage, session, device
    severity = db.Column(db.String(20), nullable=False)  # info, warning, error, critical
    title = db.Column(db.String(200), nullable=False)
    message = db.Column(db.Text, nullable=False)

    # Related Objects
    username = db.Column(db.String(100), index=True)
    session_id = db.Column(db.String(255))
    device_ip = db.Column(db.String(45))

    # Alert Data (JSON)
    alert_data = db.Column(db.Text)  # JSON string with additional alert data

    # Status
    status = db.Column(db.String(20), default='active')  # active, acknowledged, resolved
    acknowledged_by = db.Column(db.String(100))
    acknowledged_at = db.Column(db.DateTime)
    resolved_at = db.Column(db.DateTime)

    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Indexes
    __table_args__ = (
        db.Index('idx_alert_type_severity', 'alert_type', 'severity'),
        db.Index('idx_status_created', 'status', 'created_at'),
        db.Index('idx_username_created', 'username', 'created_at'),
    )

    def __repr__(self):
        return f'<AlertLog {self.alert_type}:{self.severity}>'

    def get_alert_data(self):
        """Parse JSON alert data"""
        if self.alert_data:
            try:
                return json.loads(self.alert_data)
            except json.JSONDecodeError:
                return {}
        return {}

    def set_alert_data(self, data):
        """Set alert data as JSON"""
        self.alert_data = json.dumps(data) if data else None

    @property
    def is_active(self):
        return self.status == 'active'

    @property
    def is_critical(self):
        return self.severity == 'critical'

    def to_dict(self):
        return {
            'id': self.id,
            'alert_type': self.alert_type,
            'severity': self.severity,
            'title': self.title,
            'message': self.message,
            'username': self.username,
            'session_id': self.session_id,
            'device_ip': self.device_ip,
            'alert_data': self.get_alert_data(),
            'status': self.status,
            'acknowledged_by': self.acknowledged_by,
            'acknowledged_at': self.acknowledged_at.isoformat() if self.acknowledged_at else None,
            'resolved_at': self.resolved_at.isoformat() if self.resolved_at else None,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat()
        }


# Helper functions for database operations
def init_db(app):
    """Initialize database with Flask app"""
    db.init_app(app)
    migrate.init_app(app, db)
    # with app.app_context():
    #     db.create_all()


def get_db_stats():
    """Get database statistics"""
    try:
        stats = {
            'active_sessions': UserSession.query.filter_by(status='active').count(),
            'total_sessions_today': UserSession.query.filter(
                UserSession.start_time >= datetime.utcnow().date()
            ).count(),
            'usage_logs_count': UsageLog.query.count(),
            'radius_logs_count': RadiusLog.query.count(),
            'network_devices_count': NetworkDevice.query.count(),
            'active_devices_count': NetworkDevice.query.filter_by(status='active').count(),
            'active_alerts_count': AlertLog.query.filter_by(status='active').count(),
            'critical_alerts_count': AlertLog.query.filter_by(
                status='active',
                severity='critical'
            ).count()
        }
        return stats
    except Exception as e:
        return {'error': str(e)}
