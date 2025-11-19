# F2Net ISP - Complete Command Reference Guide

## 📚 Table of Contents
1. [Installation Commands](#installation-commands)
2. [Nginx Commands](#nginx-commands)
3. [Service Management](#service-management)
4. [Flask Application Commands](#flask-application-commands)
5. [Logging & Real-time Monitoring](#logging--real-time-monitoring)
6. [Debugging Commands](#debugging-commands)
7. [Database Commands](#database-commands)
8. [Redis Commands](#redis-commands)
9. [Security & Firewall](#security--firewall)
10. [System Monitoring](#system-monitoring)
11. [Troubleshooting](#troubleshooting)
12. [Quick Reference](#quick-reference)

---

## 🔧 Installation Commands

### Complete Installation
```bash
# Make script executable
chmod +x install.sh

# Complete installation (all components)
sudo ./install.sh --all

# View help and available options
sudo ./install.sh --help
```

### Selective Installation
```bash
# Install system components only
sudo ./install.sh --system

# Install database components only
sudo ./install.sh --data

# Install application components
sudo ./install.sh --app

# Install web server components
sudo ./install.sh --web

# Install security components
sudo ./install.sh --security

# Install network services (OpenVPN, FreeRADIUS)
sudo ./install.sh --network
```

### Component-Specific Installation
```bash
# Install specific components
sudo ./install.sh --components "packages,user,database,nginx"

# Install individual components
sudo ./install.sh --packages
sudo ./install.sh --user
sudo ./install.sh --directories
sudo ./install.sh --database
sudo ./install.sh --redis
sudo ./install.sh --nginx
sudo ./install.sh --python-app
sudo ./install.sh --systemd
sudo ./install.sh --firewall
```

---

## 🌐 Nginx Commands

### Configuration Management
```bash
# Test Nginx configuration for syntax errors
sudo nginx -t

# Test and display configuration
sudo nginx -T

# Reload Nginx (graceful, no downtime)
sudo nginx -s reload
sudo systemctl reload nginx

# Restart Nginx (brief downtime)
sudo systemctl restart nginx

# Stop Nginx
sudo systemctl stop nginx

# Start Nginx
sudo systemctl start nginx

# Enable Nginx at boot
sudo systemctl enable nginx

# Disable Nginx at boot
sudo systemctl disable nginx

# Check Nginx status
sudo systemctl status nginx

# Check Nginx version
nginx -v
nginx -V  # verbose with compile options
```

### Configuration File Management
```bash
# Edit main Nginx configuration
sudo nano /etc/f2net_isp/nginx/f2net_isp.conf

# Edit global Nginx configuration
sudo nano /etc/nginx/nginx.conf

# Check configuration file locations
sudo nginx -T | grep "configuration file"

# Validate specific configuration file
sudo nginx -t -c /etc/f2net_isp/nginx/f2net_isp.conf

# Create symlink for site
sudo ln -sf /etc/f2net_isp/nginx/f2net_isp.conf /etc/nginx/sites-available/f2net_isp
sudo ln -sf /etc/nginx/sites-available/f2net_isp /etc/nginx/sites-enabled/f2net_isp

# Remove default site
sudo rm /etc/nginx/sites-enabled/default
```

### Nginx Logs
```bash
# View access logs (real-time)
sudo tail -f /var/log/f2net_isp/nginx/access.log

# View error logs (real-time)
sudo tail -f /var/log/f2net_isp/nginx/error.log

# View last 100 lines of access log
sudo tail -n 100 /var/log/f2net_isp/nginx/access.log

# View last 100 lines of error log
sudo tail -n 100 /var/log/f2net_isp/nginx/error.log

# Search for specific errors
sudo grep "error" /var/log/f2net_isp/nginx/error.log
sudo grep "404" /var/log/f2net_isp/nginx/access.log
sudo grep "500" /var/log/f2net_isp/nginx/access.log

# View both access and error logs simultaneously
sudo tail -f /var/log/f2net_isp/nginx/*.log

# Count requests by status code
sudo awk '{print $9}' /var/log/f2net_isp/nginx/access.log | sort | uniq -c | sort -rn

# Find most requested URLs
sudo awk '{print $7}' /var/log/f2net_isp/nginx/access.log | sort | uniq -c | sort -rn | head -20

# Find IPs with most requests
sudo awk '{print $1}' /var/log/f2net_isp/nginx/access.log | sort | uniq -c | sort -rn | head -20

# View logs by date range
sudo awk '/14\/Nov\/2025/ {print}' /var/log/f2net_isp/nginx/access.log
```

### Nginx Testing & Debugging
```bash
# Test upstream server connection
curl -I http://127.0.0.1:5000

# Test through Nginx
curl -I http://localhost/api/

# Test with headers
curl -H "Host: yourdomain.com" http://localhost/api/

# Test SSL/TLS (when configured)
curl -vI https://localhost/api/

# Check Nginx process
ps aux | grep nginx

# Check Nginx listening ports
sudo netstat -tlnp | grep nginx
sudo ss -tlnp | grep nginx

# Check worker connections
sudo nginx -T | grep worker_connections
```

---

## 📦 Service Management

### Flask Application Service
```bash
# Start Flask application
sudo systemctl start f2net-isp

# Stop Flask application
sudo systemctl stop f2net-isp

# Restart Flask application
sudo systemctl restart f2net-isp

# Reload Flask application (graceful)
sudo systemctl reload f2net-isp

# Check Flask application status
sudo systemctl status f2net-isp

# Enable Flask application at boot
sudo systemctl enable f2net-isp

# Disable Flask application at boot
sudo systemctl disable f2net-isp

# View Flask service configuration
sudo systemctl cat f2net-isp
```

### Celery Worker Service
```bash
# Start Celery worker
sudo systemctl start f2net-isp-celery

# Stop Celery worker
sudo systemctl stop f2net-isp-celery

# Restart Celery worker
sudo systemctl restart f2net-isp-celery

# Check Celery worker status
sudo systemctl status f2net-isp-celery

# Enable Celery worker at boot
sudo systemctl enable f2net-isp-celery

# View Celery worker configuration
sudo systemctl cat f2net-isp-celery
```

### Celery Beat Service (Scheduler)
```bash
# Start Celery beat
sudo systemctl start f2net-isp-celery-beat

# Stop Celery beat
sudo systemctl stop f2net-isp-celery-beat

# Restart Celery beat
sudo systemctl restart f2net-isp-celery-beat

# Check Celery beat status
sudo systemctl status f2net-isp-celery-beat

# Enable Celery beat at boot
sudo systemctl enable f2net-isp-celery-beat
```

### All Services Management
```bash
# Start all F2Net services
sudo systemctl start f2net-isp f2net-isp-celery f2net-isp-celery-beat

# Stop all F2Net services
sudo systemctl stop f2net-isp f2net-isp-celery f2net-isp-celery-beat

# Restart all F2Net services
sudo systemctl restart f2net-isp f2net-isp-celery f2net-isp-celery-beat

# Check status of all services
sudo systemctl status f2net-isp f2net-isp-celery f2net-isp-celery-beat nginx postgresql redis-server

# Reload systemd daemon (after editing service files)
sudo systemctl daemon-reload


sudo systemctl stop f2net-isp
sudo pkill -f gunicorn
sudo systemctl start f2net-isp


```

---

## 🐍 Flask Application Commands

### Virtual Environment
```bash
# Switch to application user
sudo -u f2net_isp bash

# Activate virtual environment
cd /opt/f2net_isp
source venv/bin/activate

# Deactivate virtual environment
deactivate

# Check Python version
python --version
which python

# Check pip version
pip --version

# List installed packages
pip list
pip freeze

# Install packages
pip install package_name
pip install -r requirements.txt

# Upgrade packages
pip install --upgrade package_name
pip install --upgrade pip
```

### Flask CLI Commands
```bash
# Run Flask shell (interactive Python with app context)
cd /opt/f2net_isp
source venv/bin/activate
flask shell

# Run Flask development server (NOT for production)
flask run

# Run with specific host and port
flask run --host=0.0.0.0 --port=5000

# Run in debug mode
flask run --debug

# Check Flask version
flask --version

# List all Flask routes
flask routes

# Create database tables
flask db upgrade  # if using Flask-Migrate

# Rollback database migration
flask db downgrade

# Create new migration
flask db migrate -m "migration message"
```

### Application Management
```bash
# Restart Flask app after code changes
sudo systemctl restart f2net-isp

# Graceful reload (if supported)
sudo systemctl reload f2net-isp

# Send SIGHUP to gunicorn for graceful reload
sudo kill -HUP $(cat /var/run/f2net-isp.pid)

# Check if app is responding
curl http://localhost:5000/health
curl http://localhost/health

# Test API endpoints
curl -X GET http://localhost/api/
curl -X POST http://localhost/api/endpoint -H "Content-Type: application/json" -d '{"key":"value"}'

# Check environment variables
sudo -u f2net_isp bash -c 'source /etc/f2net_isp/f2net_isp.env && env | grep FLASK'
```

### Python Application Testing
```bash
# Run Python tests (if configured)
cd /opt/f2net_isp
source venv/bin/activate
python -m pytest
python -m pytest tests/
python -m pytest -v  # verbose

# Run specific test file
python -m pytest tests/test_file.py

# Run with coverage
python -m pytest --cov=app tests/

# Run Python code directly
python -c "from app import create_app; app = create_app(); print(app.config)"

# Check for Python syntax errors
python -m py_compile app.py

# Run Python linter
flake8 app/
pylint app/
```

---

## 📋 Logging & Real-time Monitoring

### Application Logs (Real-time)
```bash
# Follow main application log
sudo tail -f /var/log/f2net_isp/app.log

# Follow Gunicorn access log
sudo tail -f /var/log/f2net_isp/gunicorn/access.log

# Follow Gunicorn error log
sudo tail -f /var/log/f2net_isp/gunicorn/error.log

 Follow Flask service logs via systemd (real-time)
sudo journalctl -u f2net-isp -f

# Follow Flask logs with last 100 lines then real-time
sudo journalctl -u f2net-isp -n 100 -f

# Follow Flask logs from last 10 minutes then real-time
sudo journalctl -u f2net-isp --since "10 minutes ago" -f

# Follow ALL Flask-related logs simultaneously
sudo tail -f /var/log/f2net_isp/app.log /var/log/f2net_isp/gunicorn/*.log

# Follow Flask logs and filter for errors only (real-time)
sudo tail -f /var/log/f2net_isp/app.log | grep --line-buffered "ERROR"


# Follow Celery worker log
sudo tail -f /var/log/f2net_isp/celery/worker.log

# Follow Celery beat log
sudo tail -f /var/log/f2net_isp/celery/beat.log

# Follow Nginx access log
sudo tail -f /var/log/f2net_isp/nginx/access.log

# Follow Nginx error log
sudo tail -f /var/log/f2net_isp/nginx/error.log

# Follow ALL logs simultaneously
sudo tail -f /var/log/f2net_isp/*.log /var/log/f2net_isp/*/*.log

# Follow multiple specific logs with labels
sudo tail -f /var/log/f2net_isp/app.log -f /var/log/f2net_isp/gunicorn/error.log
```

### Systemd Journal Logs (Real-time)
```bash
# Follow Flask app journal logs (real-time)
sudo journalctl -u f2net-isp -f

# Follow Celery worker journal logs (real-time)
sudo journalctl -u f2net-isp-celery -f

# Follow Celery beat journal logs (real-time)
sudo journalctl -u f2net-isp-celery-beat -f

# Follow Nginx journal logs (real-time)
sudo journalctl -u nginx -f

# Follow PostgreSQL journal logs (real-time)
sudo journalctl -u postgresql -f

# Follow Redis journal logs (real-time)
sudo journalctl -u redis-server -f

# Follow all F2Net services (real-time)
sudo journalctl -u f2net-isp -u f2net-isp-celery -u f2net-isp-celery-beat -f

# Follow system logs (real-time)
sudo journalctl -f
```

### Historical Log Viewing
```bash
# View last 100 lines of app log
sudo tail -n 100 /var/log/f2net_isp/app.log

# View last 500 lines
sudo tail -n 500 /var/log/f2net_isp/app.log

# View first 100 lines
sudo head -n 100 /var/log/f2net_isp/app.log

# View logs from specific service since boot
sudo journalctl -u f2net-isp -b

# View logs from last hour
sudo journalctl -u f2net-isp --since "1 hour ago"

# View logs from specific time range
sudo journalctl -u f2net-isp --since "2025-11-14 10:00:00" --until "2025-11-14 12:00:00"

# View logs from today
sudo journalctl -u f2net-isp --since today

# View logs from yesterday
sudo journalctl -u f2net-isp --since yesterday --until today

# View last 100 journal entries
sudo journalctl -u f2net-isp -n 100

# View logs with priority (errors only)
sudo journalctl -u f2net-isp -p err

# View logs in reverse order (newest first)
sudo journalctl -u f2net-isp -r
```

### Log Searching & Filtering
```bash
# Search for specific error in app log
sudo grep -i "error" /var/log/f2net_isp/app.log

# Search for specific error with context (5 lines before and after)
sudo grep -i "error" -C 5 /var/log/f2net_isp/app.log

# Search for 500 errors in Nginx access log
sudo grep " 500 " /var/log/f2net_isp/nginx/access.log

# Search for 404 errors
sudo grep " 404 " /var/log/f2net_isp/nginx/access.log

# Search for exception traceback
sudo grep -A 20 "Traceback" /var/log/f2net_isp/app.log

# Search for specific IP address
sudo grep "192.168.1.100" /var/log/f2net_isp/nginx/access.log

# Search in journal logs
sudo journalctl -u f2net-isp | grep -i "error"
sudo journalctl -u f2net-isp | grep -i "exception"

# Count occurrences of specific error
sudo grep -c "Connection refused" /var/log/f2net_isp/app.log

# Find unique errors
sudo grep "ERROR" /var/log/f2net_isp/app.log | sort | uniq

# Search for database errors
sudo grep -i "database" /var/log/f2net_isp/app.log | grep -i "error"

# Search for Redis errors
sudo grep -i "redis" /var/log/f2net_isp/app.log | grep -i "error"
```

### Log Analysis
```bash
# Count log entries by level
sudo grep -oP "(INFO|WARNING|ERROR|CRITICAL)" /var/log/f2net_isp/app.log | sort | uniq -c

# Show top 10 errors
sudo grep "ERROR" /var/log/f2net_isp/app.log | sort | uniq -c | sort -rn | head -10

# Analyze request response times from Nginx
sudo awk '{print $NF}' /var/log/f2net_isp/nginx/access.log | sort -n | tail -20

# Count requests per minute
sudo awk '{print $4}' /var/log/f2net_isp/nginx/access.log | cut -d: -f2 | sort | uniq -c

# Find slow requests (if request time is logged)
sudo awk '$NF > 1.0 {print}' /var/log/f2net_isp/nginx/access.log

# Get log file sizes
sudo du -sh /var/log/f2net_isp/*.log
sudo du -sh /var/log/f2net_isp/*/*.log

# Count total log lines
sudo wc -l /var/log/f2net_isp/app.log
```

### Live Log Monitoring with Filters
```bash
# Monitor only ERROR level logs
sudo tail -f /var/log/f2net_isp/app.log | grep --line-buffered "ERROR"

# Monitor multiple log levels
sudo tail -f /var/log/f2net_isp/app.log | grep --line-buffered -E "ERROR|WARNING|CRITICAL"

# Monitor specific endpoint
sudo tail -f /var/log/f2net_isp/nginx/access.log | grep --line-buffered "/api/endpoint"

# Monitor with colored output (requires ccze)
sudo tail -f /var/log/f2net_isp/app.log | ccze -A

# Monitor with highlighting (requires ack or grep --color)
sudo tail -f /var/log/f2net_isp/app.log | grep --color=always -E "ERROR|WARNING|$"

# Monitor with timestamp filtering
sudo journalctl -u f2net-isp -f --since "5 minutes ago"
```

---

## 🐛 Debugging Commands

### Application Debugging
```bash
# Enable Flask debug mode (ONLY for development!)
# Edit /etc/f2net_isp/f2net_isp.env
sudo nano /etc/f2net_isp/f2net_isp.env
# Set: FLASK_DEBUG=True
# Set: LOG_LEVEL=DEBUG
sudo systemctl restart f2net-isp

# Run Flask in debug mode manually (development only)
cd /opt/f2net_isp
source venv/bin/activate
export FLASK_DEBUG=1
flask run

# Check Python imports
python -c "import app; print('OK')"
python -c "from app import create_app; app = create_app(); print('App created')"

# Test database connection
python -c "from app import create_app, db; app = create_app(); with app.app_context(): db.engine.connect(); print('DB OK')"

# Test Redis connection
python -c "from redis import Redis; r = Redis(host='localhost', port=6379); r.ping(); print('Redis OK')"

# Check for import errors
python -c "import sys; sys.path.insert(0, '/opt/f2net_isp'); import app"

# Verify environment variables
sudo -u f2net_isp bash -c 'source /etc/f2net_isp/f2net_isp.env && env'
```

### Process Debugging
```bash
# Find Flask/Gunicorn processes
ps aux | grep gunicorn
ps aux | grep f2net

# Find Celery processes
ps aux | grep celery

# Check process tree
pstree -ap | grep f2net

# Get detailed process info
sudo lsof -p <PID>

# Check open files by process
sudo lsof -c gunicorn
sudo lsof -c celery

# Check network connections by process
sudo netstat -anp | grep gunicorn
sudo ss -anp | grep gunicorn

# Check process resource usage
top -p $(pgrep -d',' -f f2net)

# Trace system calls (advanced debugging)
sudo strace -p <PID>

# Trace specific system calls
sudo strace -e trace=network -p <PID>
```

### Network Debugging
```bash
# Check if Flask app is listening
sudo netstat -tlnp | grep 5000
sudo ss -tlnp | grep 5000

# Check all listening ports
sudo netstat -tlnp
sudo ss -tlnp

# Test local connection to Flask
telnet localhost 5000
curl -v http://localhost:5000/health

# Test connection through Nginx
curl -v http://localhost/health
curl -v http://localhost/api/

# Check HTTP response headers
curl -I http://localhost/api/

# Test with custom headers
curl -H "Authorization: Bearer token" http://localhost/api/endpoint

# Detailed connection info
curl -v -X POST http://localhost/api/endpoint -H "Content-Type: application/json" -d '{"test":"data"}'

# Trace route to external services
traceroute google.com

# DNS lookup test
nslookup google.com
dig google.com

# Check firewall rules
sudo iptables -L -n -v
sudo ufw status verbose
```

### Database Debugging
```bash
# Connect to PostgreSQL as f2net_isp database
sudo -u postgres psql -d f2net_isp

# Check active connections
sudo -u postgres psql -d f2net_isp -c "SELECT * FROM pg_stat_activity;"

# Check database size
sudo -u postgres psql -d f2net_isp -c "SELECT pg_size_pretty(pg_database_size('f2net_isp'));"

# Check table sizes
sudo -u postgres psql -d f2net_isp -c "SELECT tablename, pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename)) FROM pg_tables WHERE schemaname = 'public' ORDER BY pg_total_relation_size(schemaname||'.'||tablename) DESC;"

# List all tables
sudo -u postgres psql -d f2net_isp -c "\dt"

# Describe table structure
sudo -u postgres psql -d f2net_isp -c "\d table_name"

# Check for locks
sudo -u postgres psql -d f2net_isp -c "SELECT * FROM pg_locks;"

# Kill long-running query
sudo -u postgres psql -d f2net_isp -c "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE pid = <PID>;"

# Vacuum database
sudo -u postgres psql -d f2net_isp -c "VACUUM ANALYZE;"

# Check PostgreSQL logs
sudo tail -f /var/log/postgresql/postgresql-*.log
sudo journalctl -u postgresql -f
```

### Redis Debugging
```bash
# Connect to Redis CLI
redis-cli

# Inside Redis CLI:
# Ping Redis
PING

# Check Redis info
INFO

# Monitor Redis commands in real-time
MONITOR

# Check connected clients
CLIENT LIST

# Get all keys (be careful in production!)
KEYS *

# Get specific key
GET key_name

# Check key type
TYPE key_name

# Get key TTL
TTL key_name

# Check memory usage
MEMORY STATS

# Exit Redis CLI
EXIT

# From command line:
# Check Redis connection
redis-cli ping

# Get Redis info
redis-cli info

# Monitor Redis
redis-cli monitor

# Check Redis performance
redis-cli --latency
redis-cli --latency-history

# Check Redis slow log
redis-cli slowlog get 10

# Check Redis stats
redis-cli --stat

# Flush all Redis data (DANGEROUS!)
redis-cli FLUSHALL
```

### Performance Debugging
```bash
# Check CPU usage
top
htop

# Check CPU usage by process
ps aux --sort=-%cpu | head -10

# Check memory usage
free -h
vmstat 1

# Check memory usage by process
ps aux --sort=-%mem | head -10

# Check disk I/O
iostat -x 1
iotop

# Check disk usage
df -h
du -sh /opt/f2net_isp/*

# Check network I/O
iftop
nethogs

# Check system load
uptime
cat /proc/loadavg

# Generate Python application profile
python -m cProfile -o profile.out app.py

# View profile results
python -m pstats profile.out
```

### Debugging with Python Debugger
```bash
# Add breakpoint in code
# import pdb; pdb.set_trace()  # Python < 3.7
# breakpoint()  # Python >= 3.7

# Run with debugger
python -m pdb app.py

# Common pdb commands:
# n (next) - Execute next line
# s (step) - Step into function
# c (continue) - Continue execution
# l (list) - Show code
# p variable - Print variable
# pp variable - Pretty print variable
# w (where) - Show stack trace
# q (quit) - Quit debugger
```

### Error Tracking & Reporting
```bash
# Count errors by type
sudo grep "ERROR" /var/log/f2net_isp/app.log | awk -F': ' '{print $2}' | sort | uniq -c | sort -rn

# Generate error report
sudo grep "ERROR\|CRITICAL" /var/log/f2net_isp/app.log > /tmp/error_report_$(date +%Y%m%d).txt

# Find most recent errors
sudo grep "ERROR" /var/log/f2net_isp/app.log | tail -20

# Track error frequency over time
sudo grep "ERROR" /var/log/f2net_isp/app.log | awk '{print $1, $2}' | cut -d: -f1 | uniq -c

# Create daily error summary
sudo grep "$(date +%Y-%m-%d)" /var/log/f2net_isp/app.log | grep "ERROR" | wc -l
```

---

## 🗄️ Database Commands

### PostgreSQL Basic Operations
```bash
# Start PostgreSQL
sudo systemctl start postgresql

# Stop PostgreSQL
sudo systemctl stop postgresql

# Restart PostgreSQL
sudo systemctl restart postgresql

# Check PostgreSQL status
sudo systemctl status postgresql

# Enable PostgreSQL at boot
sudo systemctl enable postgresql

# Access PostgreSQL as postgres user
sudo -u postgres psql

# Access f2net_isp database
sudo -u postgres psql -d f2net_isp

# Access as isp_user
sudo -u postgres psql -U isp_user -d f2net_isp
```

### Database Management
```bash
# Create database
sudo -u postgres psql -c "CREATE DATABASE f2net_isp;"

# Drop database (DANGEROUS!)
sudo -u postgres psql -c "DROP DATABASE f2net_isp;"

# Create user
sudo -u postgres psql -c "CREATE USER isp_user WITH PASSWORD 'isp_password';"

# Grant privileges
sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE f2net_isp TO isp_user;"

# List databases
sudo -u postgres psql -c "\l"

# List users
sudo -u postgres psql -c "\du"

# Change user password
sudo -u postgres psql -c "ALTER USER isp_user WITH PASSWORD 'new_password';"
```

### Database Backup & Restore
```bash
# Create backup
sudo -u postgres pg_dump f2net_isp > /var/backups/f2net_isp/backup_$(date +%Y%m%d_%H%M%S).sql

# Create compressed backup
sudo -u postgres pg_dump f2net_isp | gzip > /var/backups/f2net_isp/backup_$(date +%Y%m%d_%H%M%S).sql.gz

# Backup specific tables
sudo -u postgres pg_dump -t table_name f2net_isp > table_backup.sql

# Backup schema only (no data)
sudo -u postgres pg_dump --schema-only f2net_isp > schema_backup.sql

# Backup data only (no schema)
sudo -u postgres pg_dump --data-only f2net_isp > data_backup.sql

# Restore database
sudo -u postgres psql f2net_isp < /var/backups/f2net_isp/backup.sql

# Restore compressed backup
gunzip -c /var/backups/f2net_isp/backup.sql.gz | sudo -u postgres psql f2net_isp

# Restore to new database
sudo -u postgres psql -c "CREATE DATABASE f2net_isp_restored;"
sudo -u postgres psql f2net_isp_restored < /var/backups/f2net_isp/backup.sql

# List backups
ls -lah /var/backups/f2net_isp/
```

### Database Queries & Inspection
```bash
# Count total records in table
sudo -u postgres psql -d f2net_isp -c "SELECT COUNT(*) FROM table_name;"

# Show recent records
sudo -u postgres psql -d f2net_isp -c "SELECT * FROM table_name ORDER BY created_at DESC LIMIT 10;"

# Check database connections
sudo -u postgres psql -d f2net_isp -c "SELECT pid, usename, application_name, client_addr, state FROM pg_stat_activity;"

# Check database locks
sudo -u postgres psql -d f2net_isp -c "SELECT * FROM pg_locks;"

# Check table indexes
sudo -u postgres psql -d f2net_isp -c "SELECT * FROM pg_indexes WHERE tablename = 'table_name';"

# Analyze query performance
sudo -u postgres psql -d f2net_isp -c "EXPLAIN ANALYZE SELECT * FROM table_name;"

# Show table structure
sudo -u postgres psql -d f2net_isp -c "\d+ table_name"

# Show all tables with row counts
sudo -u postgres psql -d f2net_isp -c "SELECT schemaname,relname,n_live_tup FROM pg_stat_user_tables ORDER BY n_live_tup DESC;"
```

### Database Maintenance
```bash
# Vacuum database
sudo -u postgres psql -d f2net_isp -c "VACUUM;"

# Vacuum with analyze
sudo -u postgres psql -d f2net_isp -c "VACUUM ANALYZE;"

# Reindex database
sudo -u postgres psql -d f2net_isp -c "REINDEX DATABASE f2net_isp;"

# Reindex specific table
sudo -u postgres psql -d f2net_isp -c "REINDEX TABLE table_name;"

# Check database bloat
sudo -u postgres psql -d f2net_isp -c "SELECT schemaname, tablename, pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename)) FROM pg_tables WHERE schemaname = 'public';"

# Clear old logs from pg_log
sudo find /var/lib/postgresql/*/main/pg_log -type f -mtime +30 -delete
```

---

## 🔴 Redis Commands

### Redis Service Management
```bash
# Start Redis
sudo systemctl start redis-server  # Ubuntu/Debian
sudo systemctl start redis          # CentOS/RHEL

# Stop Redis
sudo systemctl stop redis-server

# Restart Redis
sudo systemctl restart redis-server

# Check Redis status
sudo systemctl status redis-server

# Enable Redis at boot
sudo systemctl enable redis-server

# View Redis configuration
cat /etc/redis/redis.conf
```

### Redis Operations
```bash
# Connect to Redis CLI
redis-cli

# Connect to specific host/port
redis-cli -h localhost -p 6379

# Connect with authentication
redis-cli -a password

# Ping Redis
redis-cli ping

# Get Redis info
redis-cli info
redis-cli info server
redis-cli info memory
redis-cli info stats

# Monitor Redis commands (real-time)
redis-cli monitor

# Get Redis version
redis-cli --version
redis-cli info | grep redis_version
```

### Redis Data Operations
```bash
# Set a key
redis-cli SET key_name "value"

# Get a key
redis-cli GET key_name

# Delete a key
redis-cli DEL key_name

# Check if key exists
redis-cli EXISTS key_name

# Get all keys (CAREFUL in production!)
redis-cli KEYS "*"

# Get keys with pattern
redis-cli KEYS "user:*"

# Get key type
redis-cli TYPE key_name

# Set expiration on key (seconds)
redis-cli EXPIRE key_name 3600

# Check time to live
redis-cli TTL key_name

# Remove expiration
redis-cli PERSIST key_name

# Increment counter
redis-cli INCR counter_name

# Decrement counter
redis-cli DECR counter_name
```

### Redis List Operations
```bash
# Push to list
redis-cli LPUSH list_name "value"
redis-cli RPUSH list_name "value"

# Pop from list
redis-cli LPOP list_name
redis-cli RPOP list_name

# Get list length
redis-cli LLEN list_name

# Get list range
redis-cli LRANGE list_name 0 -1  # Get all
redis-cli LRANGE list_name 0 10  # Get first 10
```

### Redis Hash Operations
```bash
# Set hash field
redis-cli HSET hash_name field_name "value"

# Get hash field
redis-cli HGET hash_name field_name

# Get all hash fields
redis-cli HGETALL hash_name

# Delete hash field
redis-cli HDEL hash_name field_name

# Check if hash field exists
redis-cli HEXISTS hash_name field_name
```

### Redis Debugging & Performance
```bash
# Check Redis memory usage
redis-cli INFO memory

# Get memory usage for specific key
redis-cli MEMORY USAGE key_name

# Check slow queries
redis-cli SLOWLOG GET 10

# Reset slow log
redis-cli SLOWLOG RESET

# Check latency
redis-cli --latency

# Check latency history
redis-cli --latency-history

# Real-time stats
redis-cli --stat

# Check connected clients
redis-cli CLIENT LIST

# Get client info
redis-cli CLIENT INFO

# Kill client connection
redis-cli CLIENT KILL ip:port

# Check Redis performance
redis-cli --intrinsic-latency 60
```

### Redis Maintenance
```bash
# Save database to disk
redis-cli SAVE        # Blocking
redis-cli BGSAVE      # Background

# Get last save time
redis-cli LASTSAVE

# Flush current database (DANGEROUS!)
redis-cli FLUSHDB

# Flush all databases (VERY DANGEROUS!)
redis-cli FLUSHALL

# Get database size
redis-cli DBSIZE

# Select different database (0-15 by default)
redis-cli SELECT 1

# Get Redis config
redis-cli CONFIG GET "*"
redis-cli CONFIG GET "maxmemory"

# Set Redis config
redis-cli CONFIG SET "maxmemory" "256mb"

# Rewrite Redis config
redis-cli CONFIG REWRITE
```

---

## 🔐 Security & Firewall

### UFW Firewall (Ubuntu/Debian)
```bash
# Check firewall status
sudo ufw status
sudo ufw status verbose
sudo ufw status numbered

# Enable firewall
sudo ufw enable

# Disable firewall
sudo ufw disable

# Allow specific port
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw allow 1194/udp  # OpenVPN

# Allow service by name
sudo ufw allow ssh
sudo ufw allow http
sudo ufw allow https

# Allow from specific IP
sudo ufw allow from 192.168.1.100

# Allow from IP to specific port
sudo ufw allow from 192.168.1.100 to any port 5000

# Allow from subnet
sudo ufw allow from 192.168.1.0/24

# Deny specific port
sudo ufw deny 23/tcp

# Deny from specific IP
sudo ufw deny from 192.168.1.100

# Delete rule by number
sudo ufw status numbered
sudo ufw delete <number>

# Delete rule by specification
sudo ufw delete allow 80/tcp

# Reset firewall (removes all rules)
sudo ufw reset

# Default policies
sudo ufw default deny incoming
sudo ufw default allow outgoing

# Reload firewall
sudo ufw reload
```

### IPTables (CentOS/RHEL or Advanced)
```bash
# List all rules
sudo iptables -L -n -v
sudo iptables -L -n -v --line-numbers

# List rules by chain
sudo iptables -L INPUT -n -v
sudo iptables -L OUTPUT -n -v
sudo iptables -L FORWARD -n -v

# Allow specific port
sudo iptables -A INPUT -p tcp --dport 80 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 443 -j ACCEPT

# Allow from specific IP
sudo iptables -A INPUT -s 192.168.1.100 -j ACCEPT

# Block specific IP
sudo iptables -A INPUT -s 192.168.1.100 -j DROP

# Delete rule by number
sudo iptables -D INPUT <line-number>

# Flush all rules (DANGEROUS!)
sudo iptables -F

# Save rules (Ubuntu/Debian)
sudo iptables-save > /etc/iptables/rules.v4

# Restore rules
sudo iptables-restore < /etc/iptables/rules.v4

# Save rules (CentOS/RHEL)
sudo service iptables save
```

### Fail2Ban
```bash
# Check Fail2Ban status
sudo systemctl status fail2ban

# Check jail status
sudo fail2ban-client status

# Check specific jail
sudo fail2ban-client status sshd
sudo fail2ban-client status nginx-limit-req

# Ban an IP
sudo fail2ban-client set sshd banip 192.168.1.100

# Unban an IP
sudo fail2ban-client set sshd unbanip 192.168.1.100

# Reload Fail2Ban
sudo systemctl reload fail2ban

# View Fail2Ban logs
sudo tail -f /var/log/fail2ban.log
```

### SSL/TLS Certificates (Let's Encrypt with Certbot)
```bash
# Install Certbot
sudo apt install certbot python3-certbot-nginx  # Ubuntu/Debian

# Obtain certificate
sudo certbot --nginx -d yourdomain.com -d www.yourdomain.com

# Obtain certificate (manual)
sudo certbot certonly --nginx -d yourdomain.com

# Test certificate renewal
sudo certbot renew --dry-run

# Renew certificates
sudo certbot renew

# List certificates
sudo certbot certificates

# Delete certificate
sudo certbot delete --cert-name yourdomain.com

# Check certificate expiration
sudo certbot certificates
openssl x509 -in /etc/letsencrypt/live/yourdomain.com/cert.pem -noout -dates
```

### SSH Security
```bash
# Check SSH service status
sudo systemctl status sshd

# Edit SSH configuration
sudo nano /etc/ssh/sshd_config

# Test SSH configuration
sudo sshd -t

# Restart SSH
sudo systemctl restart sshd

# Check failed SSH attempts
sudo grep "Failed password" /var/log/auth.log

# Check successful SSH logins
sudo grep "Accepted" /var/log/auth.log

# List active SSH sessions
who
w

# Kill SSH session
sudo pkill -u username
```

### File Permissions & Ownership
```bash
# Check file permissions
ls -la /opt/f2net_isp/

# Change ownership
sudo chown f2net_isp:f2net_isp /opt/f2net_isp/file

# Change ownership recursively
sudo chown -R f2net_isp:f2net_isp /opt/f2net_isp/

# Change permissions
sudo chmod 644 /opt/f2net_isp/file    # rw-r--r--
sudo chmod 755 /opt/f2net_isp/script  # rwxr-xr-x
sudo chmod 600 /etc/f2net_isp/f2net_isp.env  # rw-------

# Change permissions recursively
sudo chmod -R 755 /opt/f2net_isp/

# Check sudo permissions
sudo visudo -c -f /etc/sudoers.d/f2net_isp
```

---

## 📊 System Monitoring

### System Resource Monitoring
```bash
# Interactive process viewer
htop
top

# CPU usage
mpstat 1        # Requires sysstat package
uptime

# Memory usage
free -h
vmstat 1

# Disk usage
df -h
df -h /opt/f2net_isp

# Disk I/O
iostat -x 1
iotop           # Requires iotop package

# Network I/O
iftop           # Requires iftop package
nethogs         # Requires nethogs package

# System load
uptime
cat /proc/loadavg

# Check running processes
ps aux
ps aux | grep f2net
```

### Performance Statistics
```bash
# CPU information
lscpu
cat /proc/cpuinfo

# Memory information
cat /proc/meminfo

# Disk I/O statistics
iostat -x

# Network statistics
netstat -s
ss -s

# System uptime
uptime -p
uptime -s

# Last reboot time
last reboot

# Check kernel messages
dmesg | tail
dmesg | grep -i error
```

### Application Performance Monitoring
```bash
# Check Gunicorn workers
ps aux | grep gunicorn | wc -l

# Check Celery workers
ps aux | grep celery | wc -l

# Monitor requests per second (from Nginx access log)
sudo tail -f /var/log/f2net_isp/nginx/access.log | pv -l -i 1 > /dev/null

# Calculate average response time
sudo awk '{sum+=$NF; count++} END {print sum/count}' /var/log/f2net_isp/nginx/access.log

# Check open file descriptors
sudo lsof | wc -l
sudo lsof -u f2net_isp | wc -l

# Check socket connections
sudo ss -s
sudo netstat -an | grep ESTABLISHED | wc -l

# Check memory usage by application
sudo ps aux --sort=-%mem | grep f2net | head -10

# Check CPU usage by application
sudo ps aux --sort=-%cpu | grep f2net | head -10
```

### Network Monitoring
```bash
# Check listening ports
sudo netstat -tlnp
sudo ss -tlnp

# Check established connections
sudo netstat -antp | grep ESTABLISHED
sudo ss -antp | grep ESTABLISHED

# Check connection states
sudo netstat -ant | awk '{print $6}' | sort | uniq -c

# Monitor bandwidth usage
iftop -i eth0           # Requires iftop
nethogs eth0            # Requires nethogs

# Check network interface statistics
ip -s link

# Test network speed
speedtest-cli           # Install with: pip install speedtest-cli

# Check routing table
route -n
ip route

# Check DNS resolution
nslookup google.com
dig google.com

# Test connectivity
ping -c 4 google.com
traceroute google.com
```

---

## 🔧 Troubleshooting

### Common Issues & Solutions

#### Service Won't Start
```bash
# Check service status and errors
sudo systemctl status f2net-isp
sudo journalctl -u f2net-isp -n 50 --no-pager

# Check if port is already in use
sudo netstat -tlnp | grep 5000
sudo ss -tlnp | grep 5000

# Kill process using port
sudo fuser -k 5000/tcp

# Check permissions
ls -la /opt/f2net_isp/
sudo chown -R f2net_isp:f2net_isp /opt/f2net_isp/

# Validate configuration
cd /opt/f2net_isp
source