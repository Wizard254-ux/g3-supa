# ISP Middleware API Documentation

## Overview
This document provides comprehensive documentation for the ISP Middleware Flask application APIs. The system consists of three main API blueprints for managing MikroTik devices, OpenVPN services, and bandwidth monitoring.

## Base URL
```
http://your-server.com/api
```

## Authentication
All endpoints require API key authentication unless specified otherwise.
- Header: `X-API-Key: your-api-key`
- Some endpoints also support JWT token authentication

---

# 1. MikroTik API (`/api/mikrotik`)

## Device Management

### GET `/devices`
**List all configured MikroTik devices**
- **Auth**: Required
- **Cache**: 60 seconds
- **Response**:
```json
{
  "success": true,
  "devices": [
    {
      "name": "core_router",
      "host": "192.168.1.1",
      "port": 8728,
      "use_ssl": false,
      "connected": true,
      "system_info": {
        "uptime": "2w3d4h15m",
        "version": "7.11.2",
        "cpu_load": "5"
      }
    }
  ],
  "total_devices": 1,
  "connected_devices": 1
}
```

### GET `/devices/status?identities=device1,device2`
**Check VPN connection status for multiple devices**
- **Auth**: Required
- **Cache**: 30 seconds
- **Query Params**: `identities` (comma-separated device names)
- **Response**:
```json
{
  "success": true,
  "data": [
    {
      "device_name": "abutis_Mikrotik787878",
      "connected": true,
      "vpn_connected": true,
      "vpn_connection_info": {
        "real_address": "197.248.198.73:58742",
        "virtual_address": "10.8.0.13",
        "bytes_received": 84323,
        "bytes_sent": 85632,
        "connected_since": "2025-11-19 06:42:49"
      }
    }
  ],
  "timestamp": "2025-11-19T12:50:14.000Z"
}
```

### GET `/devices/{device_name}/currentstatus`
**Check single device VPN connection status**
- **Auth**: Required
- **Cache**: 30 seconds
- **Response**: Same format as above but for single device

### POST `/devices/{device_name}/status`
**Get detailed MikroTik device status with custom credentials**
- **Auth**: Required
- **Body**:
```json
{
  "username": "admin",
  "password": "mikrotik_password",
  "host": "192.168.1.100",
  "port": 8728
}
```
- **Response**:
```json
{
  "success": true,
  "data": {
    "device_name": "device1",
    "connected": true,
    "system_resources": {
      "uptime": "2w3d4h15m",
      "version": "7.11.2",
      "cpu_load": "5",
      "free_memory": "234567890",
      "total_memory": "536870912"
    },
    "interface_stats": [...],
    "active_users_count": 3,
    "active_users": [...]
  }
}
```

### GET `/devices/{device_name}/config`
**Download OpenVPN configuration file for device**
- **Auth**: Required
- **Response**: File download (.ovpn)

## User Queue Management

### POST `/users/queue/create`
**Create bandwidth queue for user**
- **Auth**: Required
- **Body**:
```json
{
  "username": "user123",
  "package_info": {
    "download_speed": 10,
    "upload_speed": 5
  },
  "device_name": "core_router"
}
```

### POST `/users/queue/remove`
**Remove user bandwidth queue**
- **Body**:
```json
{
  "username": "user123",
  "device_name": "core_router"
}
```

### PUT `/users/queue/update`
**Update user bandwidth limits**
- **Body**:
```json
{
  "username": "user123",
  "package_info": {
    "download_speed": 20,
    "upload_speed": 10
  }
}
```

### GET `/users/{username}/stats`
**Get traffic statistics for user**
- **Query Params**: `device` (optional)

### GET `/users/active`
**Get all active users from queues**
- **Query Params**: `device` (optional)

## Hotspot Management

### POST `/hotspot/authorize`
**Authorize user on MikroTik hotspot**
- **Body**:
```json
{
  "username": "user123",
  "mac_address": "00:11:22:33:44:55",
  "ip_address": "192.168.1.100",
  "package_info": {
    "download_speed": 10,
    "upload_speed": 5,
    "hotspot_profile": "default"
  }
}
```

### POST `/hotspot/deauthorize`
**Deauthorize user from hotspot**
- **Body**:
```json
{
  "username": "user123"
}
```

## PPPoE Management

### POST `/pppoe/secret/create`
**Create PPPoE secret**
- **Body**:
```json
{
  "username": "user123",
  "password": "userpass",
  "package_info": {
    "download_speed": 10,
    "upload_speed": 5,
    "pppoe_profile": "default"
  }
}
```

### POST `/pppoe/secret/remove`
**Remove PPPoE secret**
- **Body**:
```json
{
  "username": "user123"
}
```

## Network Infrastructure Management

### POST `/bridge/create`
**Create bridge interface**
- **Auth**: Required
- **Body**:
```json
{
  "bridge_name": "bridge-local",
  "auto_mac": false,
  "admin_mac": "00:00:00:00:00:00",
  "device_name": "core_router"
}
```

### POST `/bridge/add-port`
**Add interface to bridge**
- **Auth**: Required
- **Body**:
```json
{
  "bridge_name": "bridge-local",
  "interface": "ether2",
  "device_name": "core_router"
}
```

### POST `/pppoe/server/configure`
**Configure PPPoE server on specific interface**
- **Auth**: Required
- **Body**:
```json
{
  "interface": "bridge-local",
  "service_name": "service",
  "local_address": "172.31.0.1",
  "remote_address": "hotspot-pool",
  "use_encryption": true,
  "authentication": "pap,chap,mschap1,mschap2",
  "keepalive_timeout": 60,
  "device_name": "core_router"
}
```

### POST `/hotspot/server/configure`
**Configure hotspot server on specific interface**
- **Auth**: Required
- **Body**:
```json
{
  "interface": "bridge-local",
  "hotspot_name": "hotspot1",
  "address_pool": "hotspot-pool",
  "profile": "hotspot-profile",
  "addresses_per_mac": 1,
  "idle_timeout": "none",
  "keepalive_timeout": "2m",
  "device_name": "core_router"
}
```

### POST `/network/setup`
**Create f2net_bridge and address pool**
- **Auth**: Required
- **Body**:
```json
{
  "username": "admin",
  "password": "mikrotik_password",
  "host": "192.168.1.1",
  "port": 8728,
  "ip_pool_range": "172.31.0.2-172.31.255.254",
  "network_address": "172.31.0.1/16"
}
```
- **Description**: Creates a bridge named `f2net_bridge` and an IP pool named `f2net_pool` with the specified range

### POST `/anti-sharing/enable`
**Enable hotspot anti-sharing protection (TTL-based)**
- **Auth**: Required
- **Body**:
```json
{
  "interface": "bridge-local",
  "device_name": "core_router"
}
```
- **Description**: Prevents users from sharing their hotspot connection with multiple devices using TTL modification to detect and block connection sharing

## System Operations

### GET `/interfaces`
**Get network interface statistics**
- **Query Params**: `device` (optional)

### POST `/backup/create`
**Create configuration backup**
- **Rate Limited**: 5 requests
- **Query Params**: `device` (optional)

### GET `/health`
**MikroTik service health check**
- **Auth**: Not required

---

# 2. VPN API (`/api/vpn`)

## Server Management

### GET `/status`
**Get OpenVPN server status**
- **Auth**: Required
- **Cache**: 30 seconds
- **Response**:
```json
{
  "success": true,
  "server_status": {
    "service_running": true,
    "port_listening": true,
    "connected_clients": 5,
    "client_list": [...],
    "health_score": 100
  }
}
```

### GET `/server/logs`
**Get OpenVPN server logs**
- **Query Params**: `lines` (max 1000, default 100)

### POST `/server/backup`
**Create VPN configuration backup**
- **Rate Limited**: 2 requests

### GET `/server/config`
**Get OpenVPN server configuration**

### GET `/server/ip`
**Get server IP from client template**

### GET `/client/template`
**Get client configuration template**

## Client Management

### GET `/clients`
**Get list of all VPN clients**
- **Cache**: 60 seconds
- **Response**:
```json
{
  "success": true,
  "clients": [
    {
      "name": "client1",
      "full_name": "f2net_client1",
      "is_connected": true,
      "is_valid": true,
      "created_at": "2025-11-19T10:00:00Z",
      "expires_at": "2026-11-19T10:00:00Z",
      "connection_info": {...}
    }
  ],
  "statistics": {
    "total_clients": 10,
    "connected_clients": 5,
    "valid_certificates": 9
  }
}
```

### GET `/clients/connected`
**Get currently connected VPN clients**
- **No Cache**
- **Response**:
```json
{
  "success": true,
  "connected_clients": [
    {
      "common_name": "f2net_client1",
      "real_address": "1.2.3.4:12345",
      "virtual_address": "10.8.0.10",
      "bytes_received": 1024000,
      "bytes_sent": 512000,
      "connected_since": "2025-11-19 10:00:00"
    }
  ],
  "total_connected": 1,
  "bandwidth_summary": {
    "total_mb_received": 1.0,
    "total_mb_sent": 0.5
  }
}
```

### POST `/clients/create`
**Create new VPN client certificate**
- **Rate Limited**: 10 requests
- **Body**:
```json
{
  "client_name": "new_client",
  "email": "client@example.com"
}
```

### GET `/clients/{client_name}/config`
**Download client configuration file**
- **Response**: File download (.ovpn)

### GET `/clients/{client_name}/details`
**Get detailed client information**

### POST `/clients/{client_name}/revoke`
**Revoke client certificate**
- **Rate Limited**: 20 requests

### POST `/clients/{client_name}/disconnect`
**Disconnect specific client**
- **Rate Limited**: 30 requests

## Statistics

### GET `/statistics/usage`
**Get VPN usage statistics**
- **Query Params**: `days` (max 90, default 7)
- **Cache**: 300 seconds

### GET `/health`
**VPN service health check**
- **Auth**: Not required

---

# 3. Bandwidth API (`/api/bandwidth`)

## Real-time Monitoring

### GET `/usage/real-time`
**Get real-time bandwidth usage**
- **Cache**: 10 seconds
- **Query Params**:
  - `username` (optional)
  - `minutes` (max 1440, default 60)
  - `device` (optional)
- **Response**:
```json
{
  "success": true,
  "period_minutes": 60,
  "bandwidth_data": [
    {
      "timestamp": "2025-11-19T12:00:00Z",
      "username": "user123",
      "download_mbps": 8.5,
      "upload_mbps": 2.1,
      "total_mbps": 10.6,
      "latency_ms": 45,
      "packet_loss_percent": 0.1,
      "nas_ip": "192.168.1.1",
      "user_ip": "10.0.1.100"
    }
  ],
  "summary": {
    "peak_download_mbps": 10.2,
    "avg_download_mbps": 7.8,
    "data_points": 60
  }
}
```

### GET `/usage/peak`
**Get peak bandwidth usage statistics**
- **Cache**: 300 seconds
- **Query Params**:
  - `username` (optional)
  - `hours` (max 168, default 24)

## Network Monitoring

### GET `/monitoring/top-users`
**Get top bandwidth users**
- **Cache**: 300 seconds
- **Query Params**:
  - `limit` (max 100, default 20)
  - `sort_by` (total/download/upload)
  - `minutes` (max 180, default 30)

### GET `/monitoring/network-summary`
**Get network-wide bandwidth summary**
- **Cache**: 60 seconds
- **Query Params**: `minutes` (max 180, default 30)

### GET `/monitoring/alerts`
**Get bandwidth threshold alerts**
- **Cache**: 60 seconds
- **Query Params**:
  - `threshold` (Mbps, default 50)
  - `minutes` (max 180, default 30)

### GET `/monitoring/quality`
**Get network quality metrics**
- **Cache**: 30 seconds
- **Query Params**:
  - `minutes` (max 1440, default 60)
  - `username` (optional)

## Bandwidth Management

### POST `/management/throttle`
**Throttle user bandwidth**
- **Body**:
```json
{
  "username": "user123",
  "download_speed": 5,
  "upload_speed": 2,
  "device_name": "core_router"
}
```

### POST `/management/remove-throttle`
**Remove bandwidth throttling**
- **Body**:
```json
{
  "username": "user123",
  "device_name": "core_router"
}
```

### GET `/health`
**Bandwidth service health check**
- **Auth**: Not required

---

# Common Response Formats

## Success Response
```json
{
  "success": true,
  "data": {...},
  "timestamp": "2025-11-19T12:00:00Z"
}
```

## Error Response
```json
{
  "success": false,
  "error": "Error message",
  "timestamp": "2025-11-19T12:00:00Z"
}
```

## Rate Limit Response
```json
{
  "success": false,
  "error": "Rate limit exceeded",
  "retry_after": "60"
}
```

# Error Codes

- **200**: Success
- **201**: Created
- **400**: Bad Request
- **401**: Unauthorized
- **404**: Not Found
- **429**: Rate Limited
- **500**: Internal Server Error

# Rate Limits

- **Default**: 1000 requests per hour
- **Certificate operations**: 10-20 requests per endpoint
- **Backup operations**: 2-5 requests per endpoint
- **Real-time monitoring**: Higher limits for frequent polling

# Caching

- **Device lists**: 60 seconds
- **Status checks**: 30 seconds
- **Statistics**: 300 seconds (5 minutes)
- **Real-time data**: 10 seconds
- **Health checks**: 30 seconds

# Authentication Methods

1. **API Key**: `X-API-Key` header
2. **JWT Token**: `Authorization: Bearer <token>` header
3. **Some endpoints**: No authentication required (health checks)

# Best Practices

1. **Use appropriate cache timeouts** for your use case
2. **Respect rate limits** to avoid throttling
3. **Handle errors gracefully** with proper retry logic
4. **Use bulk operations** when possible (e.g., multiple device status)
5. **Monitor health endpoints** for service availability
6. **Implement proper authentication** and secure API keys