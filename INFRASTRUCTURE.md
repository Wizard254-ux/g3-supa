# ISP Middleware - Flask Application Architecture

## 📁 Flask App Structure

```
isp_middleware/                 # Flask app root
├── app.py                      # Main Flask application
├── requirements.txt            # Flask dependencies
├── config.py                   # Configuration settings
├── .env                        # Environment variables
├── wsgi.py                     # WSGI entry point
├── radius_server.py            # FreeRADIUS integration
├── mikrotik_api.py            # MikroTik API integration
├── openvpn_manager.py         # OpenVPN management
├── auth/                       # Authentication modules
│   ├── __init__.py
│   ├── radius_auth.py          # RADIUS authentication
│   ├── hotspot_auth.py         # Hotspot authentication
│   ├── pppoe_auth.py          # PPPoE authentication
│   └── user_manager.py         # User management
├── api/                        # API endpoints
│   ├── __init__.py
│   ├── auth_api.py            # Authentication API
│   ├── mikrotik_api.py        # MikroTik management API
│   ├── usage_api.py           # Usage logging API
│   ├── vpn_api.py             # VPN management API
│   └── bandwidth_api.py       # Bandwidth management API
├── models/                     # Database models
│   ├── __init__.py
│   ├── user_session.py        # User sessions
│   ├── usage_log.py           # Usage logging
│   ├── radius_log.py          # RADIUS logs
│   └── network_device.py      # Network devices
├── services/                   # Business logic
│   ├── __init__.py
│   ├── radius_service.py      # RADIUS service layer
│   ├── mikrotik_service.py    # MikroTik service layer
│   ├── bandwidth_service.py   # Bandwidth management
│   ├── usage_service.py       # Usage tracking
│   └── notification_service.py # Notifications
├── utils/                      # Utilities
│   ├── __init__.py
│   ├── crypto.py              # Encryption utilities
│   ├── network.py             # Network utilities
│   ├── logging.py             # Logging configuration
│   └── decorators.py          # Custom decorators
├── scripts/                    # Management scripts
│   ├── setup_radius.sh        # FreeRADIUS setup
│   ├── setup_openvpn.sh       # OpenVPN setup
│   ├── mikrotik_sync.py       # MikroTik synchronization
│   └── user_sync.py           # User synchronization
├── configs/                    # Configuration files
│   ├── freeradius/            # FreeRADIUS configs
│   ├── openvpn/               # OpenVPN configs
│   ├── mikrotik/              # MikroTik scripts
│   └── systemd/               # Systemd services
└── logs/                       # Log files
    ├── radius.log
    ├── mikrotik.log
    ├── openvpn.log
    └── app.log
```

## 🔧 System Integration Overview

### Data Flow:
1. **Customer authenticates** → RADIUS server → Flask middleware
2. **Flask validates** → Django API → Customer database
3. **Authentication approved** → MikroTik API → Network access granted
4. **Usage tracking** → RADIUS accounting → Flask → Django database
5. **Bandwidth management** → MikroTik queue management

### Key Components:

#### 1. RADIUS Server Integration
- FreeRADIUS with Python modules
- Custom authentication scripts
- Accounting data collection
- Session management

#### 2. MikroTik API Integration
- RouterOS API communication
- User queue management
- Bandwidth limitation
- Traffic monitoring
- PPPoE secret management

#### 3. OpenVPN Management
- Client certificate generation
- Connection monitoring
- Network routing
- Site-to-site tunnels

#### 4. Authentication Flow
- Hotspot captive portal
- PPPoE authentication
- User session tracking
- Timeout management

## 🌐 Network Architecture

```
Internet
    │
    ├── Django App (Customer Portal)
    │   └── Customer Management
    │       └── Billing System
    │
    ├── Flask Middleware (RADIUS Server)
    │   ├── FreeRADIUS
    │   ├── OpenVPN Server
    │   ├── API Gateway
    │   └── Usage Tracking
    │
    └── MikroTik Infrastructure
        ├── Core Router
        ├── Distribution Switches
        ├── Access Points (Hotspot)
        ├── PPPoE Servers
        └── Customer Connections
```

## 🔐 Security Features

- **SSL/TLS encryption** for all communications
- **RADIUS shared secrets** for device authentication
- **API key authentication** for service communication
- **OpenVPN certificates** for secure tunneling
- **Rate limiting** to prevent abuse
- **IP whitelisting** for admin access

## 📊 Monitoring & Logging

- **Real-time bandwidth monitoring**
- **User session tracking**
- **RADIUS authentication logs**
- **MikroTik connection logs**
- **OpenVPN tunnel status**
- **API request logging**

## 🚀 Deployment Strategy

### Server Requirements:
- **OS**: Ubuntu 20.04+ / CentOS 8+
- **RAM**: 8GB minimum (16GB recommended)
- **CPU**: 4 cores minimum
- **Storage**: 100GB SSD
- **Network**: Multiple NICs for network segmentation

### Services to Install:
1. **FreeRADIUS** - Authentication server
2. **OpenVPN** - VPN tunneling
3. **Flask** - Python web framework
4. **PostgreSQL** - Database (shared with Django)
5. **Redis** - Caching and session storage
6. **Nginx** - Reverse proxy
7. **Systemd** - Service management