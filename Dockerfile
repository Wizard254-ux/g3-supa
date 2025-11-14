# ISP Middleware Flask Application - Dockerfile

FROM python:3.11-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    FLASK_ENV=production \
    APP_DIR=/app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    postgresql-client \
    redis-tools \
    curl \
    wget \
    build-essential \
    libpq-dev \
    libssl-dev \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# Create app user
RUN groupadd -r appuser && useradd -r -g appuser appuser

# Set work directory
WORKDIR $APP_DIR

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt && \
    pip install --no-cache-dir gunicorn

# Copy application code
COPY . .

# Create necessary directories
RUN mkdir -p logs uploads && \
    chown -R appuser:appuser $APP_DIR

# Switch to app user
USER appuser

# Expose port
EXPOSE 5000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD curl -f http://localhost:5000/health || exit 1

# Default command
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "4", "--timeout", "60", "app:app"]

# =============================================================================
# Docker Compose Configuration
# =============================================================================

---
version: '3.8'

services:
  # PostgreSQL Database
  postgres:
    image: postgres:15
    container_name: isp_postgres
    environment:
      POSTGRES_DB: isp_middleware
      POSTGRES_USER: isp_user
      POSTGRES_PASSWORD: isp_password
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./scripts/init_db.sql:/docker-entrypoint-initdb.d/init_db.sql
    networks:
      - isp_network
    restart: unless-stopped
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U isp_user -d isp_middleware"]
      interval: 30s
      timeout: 10s
      retries: 5

  # Redis Cache & Message Broker
  redis:
    image: redis:7-alpine
    container_name: isp_redis
    command: redis-server --appendonly yes --maxmemory 256mb --maxmemory-policy allkeys-lru
    volumes:
      - redis_data:/data
    networks:
      - isp_network
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 30s
      timeout: 10s
      retries: 5

  # Flask Application
  app:
    build: .
    container_name: isp_middleware
    environment:
      - DATABASE_URL=postgresql://isp_user:isp_password@postgres:5432/isp_middleware
      - REDIS_URL=redis://redis:6379/0
      - FLASK_ENV=production
      - SECRET_KEY=${SECRET_KEY:-your-secret-key}
      - JWT_SECRET_KEY=${JWT_SECRET_KEY:-your-jwt-secret}
    volumes:
      - ./logs:/app/logs
      - ./uploads:/app/uploads
      - ./config:/app/config
    ports:
      - "5000:5000"
    networks:
      - isp_network
    depends_on:
      postgres:
        condition: service_healthy
      redis:
        condition: service_healthy
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:5000/health"]
      interval: 30s
      timeout: 10s
      retries: 3

  # Celery Worker
  celery:
    build: .
    container_name: isp_celery
    command: celery -A app.celery worker --loglevel=info
    environment:
      - DATABASE_URL=postgresql://isp_user:isp_password@postgres:5432/isp_middleware
      - REDIS_URL=redis://redis:6379/0
      - CELERY_BROKER_URL=redis://redis:6379/1
      - CELERY_RESULT_BACKEND=redis://redis:6379/1
    volumes:
      - ./logs:/app/logs
      - ./config:/app/config
    networks:
      - isp_network
    depends_on:
      - postgres
      - redis
      - app
    restart: unless-stopped

  # Celery Beat (Scheduler)
  celery-beat:
    build: .
    container_name: isp_celery_beat
    command: celery -A app.celery beat --loglevel=info
    environment:
      - DATABASE_URL=postgresql://isp_user:isp_password@postgres:5432/isp_middleware
      - REDIS_URL=redis://redis:6379/0
      - CELERY_BROKER_URL=redis://redis:6379/1
      - CELERY_RESULT_BACKEND=redis://redis:6379/1
    volumes:
      - ./logs:/app/logs
      - ./config:/app/config
    networks:
      - isp_network
    depends_on:
      - postgres
      - redis
      - app
    restart: unless-stopped

  # Nginx Reverse Proxy
  nginx:
    image: nginx:alpine
    container_name: isp_nginx
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf
      - ./logs/nginx:/var/log/nginx
      - ./ssl:/etc/nginx/ssl  # SSL certificates
    networks:
      - isp_network
    depends_on:
      - app
    restart: unless-stopped

  # Prometheus (Monitoring)
  prometheus:
    image: prom/prometheus:latest
    container_name: isp_prometheus
    ports:
      - "9090:9090"
    volumes:
      - ./monitoring/prometheus.yml:/etc/prometheus/prometheus.yml
      - prometheus_data:/prometheus
    networks:
      - isp_network
    restart: unless-stopped

  # Grafana (Dashboards)
  grafana:
    image: grafana/grafana:latest
    container_name: isp_grafana
    ports:
      - "3000:3000"
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=admin123
    volumes:
      - grafana_data:/var/lib/grafana
      - ./monitoring/grafana:/etc/grafana/provisioning
    networks:
      - isp_network
    depends_on:
      - prometheus
    restart: unless-stopped

volumes:
  postgres_data:
  redis_data:
  prometheus_data:
  grafana_data:

networks:
  isp_network:
    driver: bridge

# =============================================================================
# Docker Nginx Configuration
# =============================================================================

events {
    worker_connections 1024;
}

http {
    include       /etc/nginx/mime.types;
    default_type  application/octet-stream;

    # Logging
    log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                    '$status $body_bytes_sent "$http_referer" '
                    '"$http_user_agent" "$http_x_forwarded_for"';

    access_log /var/log/nginx/access.log main;
    error_log /var/log/nginx/error.log;

    # Basic settings
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    types_hash_max_size 2048;
    client_max_body_size 16M;

    # Security headers
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

    # Rate limiting
    limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;
    limit_req_zone $binary_remote_addr zone=auth:10m rate=5r/s;

    # Upstream backend
    upstream isp_backend {
        server app:5000;
    }

    server {
        listen 80;
        server_name _;

        # Redirect HTTP to HTTPS in production
        # return 301 https://$server_name$request_uri;

        # API endpoints
        location /api/ {
            limit_req zone=api burst=20 nodelay;

            proxy_pass http://isp_backend;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
            proxy_connect_timeout 60s;
            proxy_send_timeout 60s;
            proxy_read_timeout 60s;
        }

        # Authentication endpoints (stricter rate limiting)
        location /api/auth/ {
            limit_req zone=auth burst=10 nodelay;

            proxy_pass http://isp_backend;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }

        # Health check
        location /health {
            proxy_pass http://isp_backend;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        }

        # Metrics (restrict access)
        location /metrics {
            allow 127.0.0.1;
            allow 10.0.0.0/8;
            allow 192.168.0.0/16;
            allow 172.16.0.0/12;
            deny all;

            proxy_pass http://isp_backend;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        }

        # Static files
        location /static/ {
            alias /app/static/;
            expires 1y;
            add_header Cache-Control "public, immutable";
        }

        # Default response
        location / {
            return 404 '{"error": "Not found", "message": "ISP Middleware API"}';
            add_header Content-Type application/json;
        }
    }

    # HTTPS server (uncomment for SSL)
    # server {
    #     listen 443 ssl http2;
    #     server_name _;
    #
    #     ssl_certificate /etc/nginx/ssl/cert.pem;
    #     ssl_certificate_key /etc/nginx/ssl/key.pem;
    #     ssl_protocols TLSv1.2 TLSv1.3;
    #     ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384;
    #     ssl_prefer_server_ciphers off;
    #
    #     # Include the same location blocks as above
    # }
}

# =============================================================================
# Docker Environment File (.env.docker)
# =============================================================================

# Flask Application
SECRET_KEY=your-super-secret-key-change-this-in-production
JWT_SECRET_KEY=your-jwt-secret-key-also-change-this
FLASK_ENV=production
FLASK_DEBUG=False

# Database
POSTGRES_DB=isp_middleware
POSTGRES_USER=isp_user
POSTGRES_PASSWORD=isp_password
DATABASE_URL=postgresql://isp_user:isp_password@postgres:5432/isp_middleware

# Redis
REDIS_URL=redis://redis:6379/0

# Celery
CELERY_BROKER_URL=redis://redis:6379/1
CELERY_RESULT_BACKEND=redis://redis:6379/1

# MikroTik Configuration
MIKROTIK_CORE_HOST=192.168.1.1
MIKROTIK_CORE_USER=admin
MIKROTIK_CORE_PASS=your_mikrotik_password

# OpenVPN
OPENVPN_SERVER_HOST=your-server-ip
OPENVPN_SERVER_PORT=1194

# Django API (Customer Management)
DJANGO_API_URL=http://your-django-server:8000/api
DJANGO_API_KEY=your-django-api-key

# Security
ALLOWED_IPS=127.0.0.1,192.168.0.0/16,10.0.0.0/8,172.16.0.0/12
MAX_LOGIN_ATTEMPTS=5

# Monitoring
PROMETHEUS_METRICS=true
SENTRY_DSN=https://your-sentry-dsn@sentry.io/project-id

# Email (for notifications)
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=your-email@gmail.com
SMTP_PASSWORD=your-app-password

# =============================================================================
# Docker Startup Script (docker-start.sh)
# =============================================================================

#!/bin/bash

# ISP Middleware Docker Startup Script

set -e

echo "Starting ISP Middleware with Docker..."

# Check if .env.docker exists
if [ ! -f .env.docker ]; then
    echo "Creating .env.docker from template..."
    cp .env.docker.template .env.docker
    echo "Please edit .env.docker with your configuration"
    exit 1
fi

# Create necessary directories
mkdir -p logs/{nginx,app,celery}
mkdir -p uploads
mkdir -p config
mkdir -p ssl
mkdir -p monitoring/{prometheus,grafana}

# Set permissions
chmod 755 logs uploads config

# Pull latest images
docker-compose pull

# Build and start services
docker-compose --env-file .env.docker up -d --build

# Wait for services to be ready
echo "Waiting for services to start..."
sleep 30

# Check service health
echo "Checking service health..."
docker-compose ps

# Initialize database if needed
echo "Initializing database..."
docker-compose exec app python -c "
from app import create_app
from models import db

app = create_app()
with app.app_context():
    db.create_all()
    print('Database initialized')
"

# Create admin user
echo "Creating admin user..."
docker-compose exec app python -c "
from app import create_app
from models import db, User
from werkzeug.security import generate_password_hash

app = create_app()
with app.app_context():
    admin = User.query.filter_by(username='admin').first()
    if not admin:
        admin = User(
            username='admin',
            email='admin@localhost',
            password=generate_password_hash('admin123'),
            user_type='super_admin',
            is_active=True,
            is_verified=True
        )
        db.session.add(admin)
        db.session.commit()
        print('Admin user created: admin/admin123')
    else:
        print('Admin user already exists')
"

echo "ISP Middleware started successfully!"
echo ""
echo "Services:"
echo "  - API: http://localhost/api/"
echo "  - Health: http://localhost/health"
echo "  - Prometheus: http://localhost:9090"
echo "  - Grafana: http://localhost:3000 (admin/admin123)"
echo ""
echo "To view logs: docker-compose logs -f"
echo "To stop services: docker-compose down"

# =============================================================================
# Docker Stop Script (docker-stop.sh)
# =============================================================================

#!/bin/bash

# ISP Middleware Docker Stop Script

echo "Stopping ISP Middleware services..."

# Stop and remove containers
docker-compose down

# Optional: Remove volumes (uncomment if you want to delete all data)
# docker-compose down -v

echo "ISP Middleware stopped."

# =============================================================================
# Docker Update Script (docker-update.sh)
# =============================================================================

#!/bin/bash

# ISP Middleware Docker Update Script

echo "Updating ISP Middleware..."

# Pull latest changes
git pull

# Rebuild and restart services
docker-compose build --no-cache
docker-compose up -d

# Run any database migrations
docker-compose exec app python -c "
from app import create_app
from models import db

app = create_app()
with app.app_context():
    db.create_all()
    print('Database updated')
"

echo "ISP Middleware updated successfully!"