# ISP Management System

A comprehensive Internet Service Provider (ISP) management platform consisting of a **Django customer management system** and a **Flask middleware application** for RADIUS authentication, MikroTik integration, and OpenVPN management.

## 🏗️ Architecture Overview

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Customer      │    │   Flask         │    │   Network       │
│   Portal        │◄──►│   Middleware    │◄──►│   Infrastructure│
│   (Django)      │    │   (RADIUS/API)  │    │   (MikroTik)    │
└─────────────────┘    └─────────────────┘    └─────────────────┘
        │                        │                        │
        ▼                        ▼                        ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   PostgreSQL    │    │   Redis Cache   │    │   OpenVPN       │
│   Database      │    │   & Sessions    │    │   Server        │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## 📋 Features

### Customer Management (Django)
- ✅ Multi-tenant ISP company support
- ✅ Customer registration and profile management
- ✅ Internet package configuration (Hotspot, PPPoE, Fiber)
- ✅ Subscription management and billing
- ✅ Support ticket system with SLA tracking
- ✅ Payment processing and invoicing
- ✅ Usage analytics and reporting
- ✅ Team and technician management
- ✅ Equipment inventory tracking

### Network Middleware (Flask)
- ✅ RADIUS authentication server integration
- ✅ MikroTik RouterOS API management
- ✅ Real-time bandwidth monitoring and control
- ✅ OpenVPN certificate and client management
- ✅ Session tracking and usage logging
- ✅ Network device monitoring
- ✅ Automated user provisioning/deprovisioning
- ✅ API gateway for network operations
- ✅ Prometheus metrics and monitoring

## 🚀 Quick Start

### Prerequisites

- Ubuntu 20.04+ or CentOS 8+ (recommended)
- Python 3.9+
- PostgreSQL 12+
- Redis 6+
- Docker & Docker Compose (for containerized deployment)

### Option 1: Automated Installation (Recommended)

```bash
# Clone the repository
git clone https://github.com/yourusername/isp-management-system.git
cd isp-management-system

# Run the automated installer (requires root)
sudo bash setup.sh
```

### Option 2: Docker Deployment

```bash
# Clone the repository
git clone https://github.com/yourusername/isp-management-system.git
cd isp-management-system

# Start with Docker Compose
bash docker-start.sh
```

### Option 3: Manual Installation

See the [Manual Installation Guide](#manual-installation) below.

## 📁 Project Structure

```
isp-management-system/
├── django_customer_portal/          # Django customer management
│   ├── manage.py
│   ├── core/                       # Main Django app
│   │   ├── models.py              # Database models
│   │   ├── admin.py               # Admin interface
│   │   ├── views.py               # API views
│   │   └── serializers.py         # DRF serializers
│   ├── requirements.txt           # Django dependencies
│   └── settings/                  # Django settings
├── flask_middleware/              # Flask RADIUS/API middleware
│   ├── app.py                    # Main Flask application
│   ├── config.py                 # Configuration
│   ├── models/                   # Database models
│   ├── services/                 # Business logic services
│   ├── api/                      # API blueprints
│   ├── auth/                     # Authentication modules
│   ├── utils/                    # Utilities and decorators
│   ├── requirements.txt          # Flask dependencies
│   └── openvpn_manager.py        # OpenVPN management
├── setup.sh                     # Automated installation script
├── docker-compose.yml           # Docker deployment
├── monitoring/                  # Prometheus/Grafana config
├── scripts/                     # Utility scripts
└── docs/                       # Documentation
```

## 🔧 Configuration

### Environment Variables

#### Django Application (.env)
```bash
# Django Configuration
SECRET_KEY=your-django-secret-key
DEBUG=False
ALLOWED_HOSTS=yourdomain.com,localhost

# Database
DATABASE_URL=postgresql://user:password@localhost:5432/isp_customer_db

# API Keys
DJANGO_API_KEY=your-api-key-for-flask-communication

# Email Configuration
EMAIL_HOST=smtp.gmail.com
EMAIL_PORT=587
EMAIL_HOST_USER=your-email@gmail.com
EMAIL_HOST_PASSWORD=your-password
```

#### Flask Middleware (.env)
```bash
# Flask Configuration
SECRET_KEY=your-flask-secret-key
JWT_SECRET_KEY=your-jwt-secret-key
FLASK_ENV=production

# Database
DATABASE_URL=postgresql://user:password@localhost:5432/isp_middleware_db

# Redis
REDIS_URL=redis://localhost:6379/0

# MikroTik Configuration
MIKROTIK_CORE_HOST=192.168.1.1
MIKROTIK_CORE_USER=admin
MIKROTIK_CORE_PASS=your_mikrotik_password

# Django API Integration
DJANGO_API_URL=http://localhost:8000/api
DJANGO_API_KEY=your-django-api-key

# OpenVPN
OPENVPN_SERVER_HOST=your-server-ip
OPENVPN_CONFIG_DIR=/etc/openvpn
```

## 📖 Manual Installation

### Step 1: System Dependencies

#### Ubuntu/Debian
```bash
sudo apt update
sudo apt install -y python3 python3-pip python3-venv postgresql \
    postgresql-contrib redis-server nginx git curl wget build-essential \
    libpq-dev libssl-dev libffi-dev openvpn easy-rsa freeradius \
    freeradius-utils freeradius-postgresql
```

#### CentOS/RHEL
```bash
sudo yum update -y
sudo yum groupinstall -y "Development Tools"
sudo yum install -y python3 python3-pip postgresql postgresql-server \
    postgresql-contrib redis nginx git curl wget openssl-devel \
    libffi-devel openvpn easy-rsa freeradius freeradius-utils \
    freeradius-postgresql
```

### Step 2: Database Setup

```bash
# Start PostgreSQL
sudo systemctl start postgresql
sudo systemctl enable postgresql

# Create databases
sudo -u postgres createdb isp_customer_db
sudo -u postgres createdb isp_middleware_db

# Create database user
sudo -u postgres psql -c "CREATE USER isp_user WITH PASSWORD 'secure_password';"
sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE isp_customer_db TO isp_user;"
sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE isp_middleware_db TO isp_user;"
```

### Step 3: Django Application Setup

```bash
# Create application directory
sudo mkdir -p /opt/isp_management
cd /opt/isp_management

# Clone repository
git clone https://github.com/yourusername/isp-management-system.git .

# Django setup
cd django_customer_portal
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Configure environment
cp .env.example .env
# Edit .env with your configuration

# Run migrations
python manage.py migrate
python manage.py collectstatic
python manage.py createsuperuser
```

### Step 4: Flask Middleware Setup

```bash
# Flask setup
cd ../flask_middleware
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Configure environment
cp .env.example .env
# Edit .env with your configuration

# Initialize database
python -c "
from app import create_app
from models import db
app = create_app()
with app.app_context():
    db.create_all()
"
```

### Step 5: Web Server Configuration

#### Nginx Configuration
```nginx
# /etc/nginx/sites-available/isp-management
server {
    listen 80;
    server_name yourdomain.com;

    # Django Customer Portal
    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }

    # Flask Middleware API
    location /middleware/ {
        proxy_pass http://127.0.0.1:5000/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }

    # Static files
    location /static/ {
        alias /opt/isp_management/django_customer_portal/staticfiles/;
    }
}
```

### Step 6: Service Configuration

#### Systemd Services

Create service files for automatic startup:

```bash
# Django service
sudo tee /etc/systemd/system/isp-django.service > /dev/null <<EOF
[Unit]
Description=ISP Management Django Application
After=network.target postgresql.service

[Service]
Type=exec
User=www-data
WorkingDirectory=/opt/isp_management/django_customer_portal
Environment=PATH=/opt/isp_management/django_customer_portal/venv/bin
ExecStart=/opt/isp_management/django_customer_portal/venv/bin/gunicorn --bind 127.0.0.1:8000 isp_management.wsgi:application
Restart=always

[Install]
WantedBy=multi-user.target
EOF

# Flask service
sudo tee /etc/systemd/system/isp-flask.service > /dev/null <<EOF
[Unit]
Description=ISP Management Flask Middleware
After=network.target postgresql.service redis.service

[Service]
Type=exec
User=www-data
WorkingDirectory=/opt/isp_management/flask_middleware
Environment=PATH=/opt/isp_management/flask_middleware/venv/bin
ExecStart=/opt/isp_management/flask_middleware/venv/bin/gunicorn --bind 127.0.0.1:5000 app:app
Restart=always

[Install]
WantedBy=multi-user.target
EOF

# Enable and start services
sudo systemctl daemon-reload
sudo systemctl enable isp-django isp-flask nginx postgresql redis
sudo systemctl start isp-django isp-flask nginx
```

## 🔐 Security Configuration

### 1. Firewall Setup
```bash
# Ubuntu/Debian
sudo ufw enable
sudo ufw allow ssh
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp

# CentOS/RHEL
sudo firewall-cmd --permanent --add-service=http
sudo firewall-cmd --permanent --add-service=https
sudo firewall-cmd --permanent --add-service=ssh
sudo firewall-cmd --reload
```

### 2. SSL/TLS Certificates
```bash
# Using Let's Encrypt
sudo apt install certbot python3-certbot-nginx
sudo certbot --nginx -d yourdomain.com
```

### 3. Database Security
```bash
# Secure PostgreSQL installation
sudo -u postgres psql -c "ALTER USER postgres PASSWORD 'secure_password';"

# Update pg_hba.conf for authentication
sudo nano /etc/postgresql/*/main/pg_hba.conf
```

## 🌐 Network Integration

### MikroTik Configuration

#### 1. Enable API Access
```routeros
/ip service
set api disabled=no port=8728

/user group
add name=api_users policy=api,read,write

/user
add name=api_user password=api_password group=api_users
```

#### 2. RADIUS Configuration
```routeros
/radius
add address=your-server-ip secret=radius_secret service=login,ppp
add address=your-server-ip secret=radius_secret service=login,hotspot

/ppp aaa
set use-radius=yes

/ip hotspot profile
set default use-radius=yes
```

### FreeRADIUS Configuration

#### 1. Enable Python Module
```bash
# /etc/freeradius/3.0/mods-enabled/python3
python3 {
    python_path = "/etc/freeradius/3.0/mods-config/python3/"
    module = "isp_auth"
    func_authenticate = "authenticate"
    func_accounting = "accounting"
}
```

#### 2. Configure Sites
```bash
# /etc/freeradius/3.0/sites-enabled/default
authorize {
    python3
}

authenticate {
    Auth-Type Python {
        python3
    }
}

accounting {
    python3
}
```

### OpenVPN Setup

#### 1. Initialize PKI
```bash
cd /etc/openvpn/easy-rsa
./easyrsa init-pki
./easyrsa build-ca nopass
./easyrsa gen-req server nopass
./easyrsa sign-req server server
./easyrsa gen-dh
```

#### 2. Server Configuration
```bash
# /etc/openvpn/server.conf
port 1194
proto udp
dev tun
ca ca.crt
cert server.crt
key server.key
dh dh2048.pem
server 10.8.0.0 255.255.255.0
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 8.8.8.8"
push "dhcp-option DNS 8.8.4.4"
client-config-dir ccd
status openvpn-status.log
log openvpn.log
management localhost 7505
```

## 📊 Monitoring and Maintenance

### Health Monitoring
```bash
# Run health checks
python scripts/health_check.py

# View system status
systemctl status isp-django isp-flask nginx postgresql redis

# Check logs
journalctl -u isp-django -f
journalctl -u isp-flask -f
```

### Performance Monitoring

Access monitoring dashboards:
- **Prometheus**: http://your-server:9090
- **Grafana**: http://your-server:3000 (admin/admin123)
- **Application Health**: http://your-server/health

### Backup Strategy

#### Automated Backup Script
```bash
#!/bin/bash
# backup.sh
BACKUP_DIR="/var/backups/isp_management"
DATE=$(date +%Y%m%d_%H%M%S)

# Database backups
pg_dump isp_customer_db > $BACKUP_DIR/customer_db_$DATE.sql
pg_dump isp_middleware_db > $BACKUP_DIR/middleware_db_$DATE.sql

# Configuration backups
tar -czf $BACKUP_DIR/config_$DATE.tar.gz /opt/isp_management/*/.*env /etc/nginx/sites-available/

# Cleanup old backups (keep 30 days)
find $BACKUP_DIR -type f -mtime +30 -delete
```

## 🧪 Testing

### Unit Tests
```bash
# Django tests
cd django_customer_portal
python manage.py test

# Flask tests
cd flask_middleware
python -m pytest tests/
```

### API Testing
```bash
# Test Django API
curl -X GET http://localhost:8000/api/customers/

# Test Flask middleware
curl -X GET http://localhost:5000/health

# Test RADIUS authentication
curl -X POST http://localhost:5000/api/auth/radius/authenticate \
  -H "Content-Type: application/json" \
  -d '{"username": "testuser", "password": "testpass"}'
```

## 📚 API Documentation

### Django Customer Portal API
- **Base URL**: `http://yourdomain.com/api/`
- **Documentation**: `http://yourdomain.com/api/docs/`

### Flask Middleware API
- **Base URL**: `http://yourdomain.com/middleware/api/`
- **Health Check**: `GET /health`
- **Authentication**: `POST /api/auth/radius/authenticate`
- **User Management**: `GET/POST /api/users/`
- **MikroTik Control**: `POST /api/mikrotik/users/queue/create`

## 🔍 Troubleshooting

### Common Issues

#### 1. Database Connection Errors
```bash
# Check PostgreSQL status
sudo systemctl status postgresql

# Check connection
sudo -u postgres psql -c "SELECT 1;"

# Review PostgreSQL logs
sudo tail -f /var/log/postgresql/postgresql-*.log
```

#### 2. RADIUS Authentication Failures
```bash
# Test RADIUS server
radtest username password localhost 1812 testing123

# Check FreeRADIUS logs
sudo tail -f /var/log/freeradius/radius.log

# Debug mode
sudo freeradius -X
```

#### 3. MikroTik API Connection Issues
```bash
# Test API connectivity
python -c "
import librouteros
api = librouteros.connect(host='192.168.1.1', username='admin', password='password')
print(api.path('/system/identity').get())
"
```

### Log Locations
- **Django**: `/var/log/isp_management/django.log`
- **Flask**: `/var/log/isp_management/flask.log`
- **Nginx**: `/var/log/nginx/`
- **PostgreSQL**: `/var/log/postgresql/`
- **FreeRADIUS**: `/var/log/freeradius/`

## 🚀 Production Deployment

### Performance Optimization

#### 1. Database Optimization
```sql
-- PostgreSQL tuning
ALTER SYSTEM SET shared_buffers = '256MB';
ALTER SYSTEM SET effective_cache_size = '1GB';
ALTER SYSTEM SET work_mem = '4MB';
SELECT pg_reload_conf();
```

#### 2. Redis Configuration
```bash
# /etc/redis/redis.conf
maxmemory 512mb
maxmemory-policy allkeys-lru
save 900 1
save 300 10
save 60 10000
```

#### 3. Application Scaling
```bash
# Increase Gunicorn workers
gunicorn --workers 4 --worker-class gevent --bind 0.0.0.0:8000 app:app

# Enable caching
redis-cli config set maxmemory-policy allkeys-lru
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/new-feature`)
3. Make your changes
4. Add tests for new functionality
5. Commit your changes (`git commit -am 'Add new feature'`)
6. Push to the branch (`git push origin feature/new-feature`)
7. Create a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

- **Documentation**: [Full Documentation](docs/)
- **Issues**: [GitHub Issues](https://github.com/yourusername/isp-management-system/issues)
- **Email**: support@yourisp.com

## 🙏 Acknowledgments

- Django and Flask communities
- FreeRADIUS project
- MikroTik RouterOS
- OpenVPN project
- All contributors and testers

---

**Happy ISP Management!** 🌐