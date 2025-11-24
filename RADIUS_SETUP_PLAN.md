# FreeRADIUS Setup Plan for MikroTik Integration

## Overview
This document outlines the complete setup process for integrating FreeRADIUS with MikroTik devices to provide centralized authentication and bandwidth package management.

---

## Architecture

```
┌─────────────────┐         ┌──────────────────┐         ┌─────────────────┐
│   Your API      │────────▶│  FreeRADIUS      │◀────────│   MikroTik      │
│  (Flask App)    │         │   + MySQL        │         │   Devices       │
└─────────────────┘         └──────────────────┘         └─────────────────┘
      │                              │
      │                              │
      └──────────────┬───────────────┘
                     │
              ┌──────▼───────┐
              │    MySQL     │
              │   Database   │
              │  - Users     │
              │  - Packages  │
              │  - Sessions  │
              └──────────────┘
```
# 🔒 Security Recommendations in prodution:

  Change these in production:

  1. RADIUS_SECRET - Make it STRONG:
   Generate a strong secret                                                                                                                                                        
  openssl rand -base64 32
   Example output: xK8mP3vN2wQ9rL4sT7yU6zB5cD1eF0gH8iJ9kL2mN4o=                                                                                                                    
  2. Update in TWO places:
    - FreeRADIUS: /etc/freeradius/3.0/clients.conf                                                                                                                                  
    - MikroTik: /radius configuration
  3. RADIUS_DB_PASS - Use a complex password:
   Example strong password                                                                                                                                                         
  RADIUS_DB_PASS="aB3$mK9#pQ2@xY7!"  

### Flow:
1. **User Management**: Your API → MySQL (add/remove users, assign packages)
2. **Authentication**: Customer → MikroTik → FreeRADIUS → MySQL
3. **Rate Limiting**: RADIUS returns user's package speed → MikroTik applies it

---

## Phase 1: FreeRADIUS Installation (VPS)

### Script: `scripts/setup_radius.sh`

Run on your VPS:
```bash
# Upload the script
```

### What the Script Does:

#### Step 1: Install Packages
- FreeRADIUS server
- FreeRADIUS MySQL module
- MySQL server
- Utilities for testing

#### Step 2: Database Setup
Creates:
- Database: `radius`
- User: `radius` with secure password
- Grants privileges

#### Step 3: Import Schema
Imports standard FreeRADIUS tables:
- `radcheck` - User credentials
- `radreply` - User-specific replies
- `radgroupcheck` - Group credentials
- `radgroupreply` - Group replies
- `radusergroup` - User-group mapping
- `radacct` - Accounting (session logs)
- `radpostauth` - Authentication logs

#### Step 4: Custom Tables
Creates:
- `packages` table for bandwidth packages:
  ```sql
  - id
  - package_name (e.g., "5mbps", "10mbps")
  - download_speed (e.g., "5M", "10M")
  - upload_speed
  - description
  - price
  ```

Inserts default packages:
- 5 Mbps - 500.00
- 10 Mbps - 800.00
- 20 Mbps - 1200.00
- 50 Mbps - 2000.00

#### Step 5: Configure SQL Module
Updates `/etc/freeradius/3.0/mods-enabled/sql`:
- Driver: MySQL
- Connection: localhost
- Credentials: radius user

#### Step 6: Add MikroTik Client
Adds MikroTik devices to `/etc/freeradius/3.0/clients.conf`:
- Accepts connections from any IP (0.0.0.0/0)
- Shared secret: `testing123` (change this!)

#### Step 7: Start Service
- Tests configuration
- Starts FreeRADIUS
- Enables auto-start on boot

---

## Phase 2: API Development (Local)

### Files to Create:

#### 1. Database Models (`models/radius.py`)
```python
class RadiusPackage:
    - package_name
    - download_speed
    - upload_speed
    - price

class RadiusUser:
    - username
    - package_id
    - status (active/suspended)
```

#### 2. API Endpoints (`api/radius_api.py`)

**User Management:**
- `POST /api/radius/users` - Add user
- `DELETE /api/radius/users/{username}` - Remove user
- `PUT /api/radius/users/{username}/package` - Change package
- `GET /api/radius/users` - List all users
- `GET /api/radius/users/{username}` - Get user details

**Package Management:**
- `GET /api/radius/packages` - List packages
- `POST /api/radius/packages` - Create package
- `PUT /api/radius/packages/{id}` - Update package
- `DELETE /api/radius/packages/{id}` - Delete package

**MikroTik Configuration:**
- `POST /api/mikrotik/radius/configure` - Configure MikroTik to use RADIUS

**Accounting & Sessions:**
- `GET /api/radius/sessions/active` - Active sessions
- `GET /api/radius/users/{username}/usage` - User usage history

---

## Phase 3: MikroTik Configuration

### For PPPoE:
```
/radius
add address=YOUR_VPS_IP secret=testing123 service=ppp

/ppp aaa
set use-radius=yes
```

### For Hotspot:
```
/radius
add address=YOUR_VPS_IP secret=testing123 service=hotspot

/ip hotspot profile
set [find] use-radius=yes
```

---

## Phase 4: Testing

### Test 1: Add User via API
```bash
curl -X POST http://your-vps/api/radius/users \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser",
    "password": "testpass",
    "package": "10mbps"
  }'
```

### Test 2: Authenticate on MikroTik
Connect PPPoE client with:
- Username: testuser
- Password: testpass

Should receive 10 Mbps rate limit.

### Test 3: Check Session
```bash
curl http://your-vps/api/radius/sessions/active
```

Should show active session with rate limit.

---

## Database Schema Details

### radcheck (User Credentials)
```sql
INSERT INTO radcheck (username, attribute, op, value, package_id)
VALUES ('testuser', 'Cleartext-Password', ':=', 'testpass', 2);
```

### radreply (Rate Limit)
When user authenticates, RADIUS returns:
```
Mikrotik-Rate-Limit = "10M/10M"
```

This is handled automatically based on package assignment.

---

## Security Notes

1. **Change Default Secret**: Update `RADIUS_SECRET` in script before running
2. **Firewall**: Only allow RADIUS port (1812, 1813) from MikroTik IPs
3. **Database Password**: Use strong password for `radius` DB user
4. **API Authentication**: All API endpoints require X-API-Key header

---

## Troubleshooting

### FreeRADIUS won't start:
```bash
# Check config
sudo freeradius -CX

# View logs
sudo journalctl -u freeradius -n 50

# Debug mode
sudo freeradius -X
```

### Authentication fails:
```bash
# Test locally
radtest username password localhost 0 testing123

# Check logs
tail -f /var/log/freeradius/radius.log
```

### MikroTik can't connect:
1. Check firewall allows UDP 1812, 1813
2. Verify secret matches on both sides
3. Check RADIUS client IP in `/etc/freeradius/3.0/clients.conf`

---

## Next Steps After Installation

1. ✅ Run `setup_radius.sh` on VPS
2. ✅ Note down database credentials
3. ✅ Update `.env` file with RADIUS credentials
4. ✅ Commit and push API code (after we build it)
5. ✅ Pull on VPS
6. ✅ Configure one MikroTik device to test
7. ✅ Create test user via API
8. ✅ Test authentication
9. ✅ Verify rate limit applied
10. ✅ Deploy to all MikroTik devices

---

## Environment Variables (.env)

Add these after running setup script:
```env
RADIUS_DB_HOST=localhost
RADIUS_DB_PORT=3306
RADIUS_DB_NAME=radius
RADIUS_DB_USER=radius
RADIUS_DB_PASS=RadiusSecurePass2024!
RADIUS_SECRET=testing123
```

  🔍 Status & Service Management

  # Check FreeRADIUS service status                                                                                                                                                 
  sudo systemctl status freeradius

  # Start/Stop/Restart                                                                                                                                                              
  sudo systemctl start freeradius
  sudo systemctl stop freeradius
  sudo systemctl restart freeradius

  # Enable auto-start on boot                                                                                                                                                       
  sudo systemctl enable freeradius

  # Check if FreeRADIUS is running                                                                                                                                                  
  ps aux | grep freeradius

  ---
  📋 Configuration Testing

  # Test FreeRADIUS configuration (dry run)                                                                                                                                         
  sudo freeradius -CX

  # Run in debug mode (see detailed logs)                                                                                                                                           
  sudo freeradius -X
  # Press Ctrl+C to stop                                                                                                                                                            

  # Check which modules are enabled                                                                                                                                                 
  ls -la /etc/freeradius/3.0/mods-enabled/

  ---
  📊 Database Checks

  # Connect to RADIUS database                                                                                                                                                      
  mysql -u radius -p radius
  # Password: RadiusSecurePass2024!                                                                                                                                                 

  # Once in MySQL, run these:                                                                                                                                                       
  SHOW TABLES;
  SELECT * FROM packages;
  SELECT * FROM radcheck;
  SELECT username, package_id, status FROM radcheck;
  DESC packages;
  DESC radcheck;
  EXIT;

  ---
  📝 View Logs

  # Real-time logs                                                                                                                                                                  
  sudo journalctl -u freeradius -f

  # Last 50 lines                                                                                                                                                                   
  sudo journalctl -u freeradius -n 50

  # Logs since today                                                                                                                                                                
  sudo journalctl -u freeradius --since today

  # FreeRADIUS log files                                                                                                                                                            
  sudo tail -f /var/log/freeradius/radius.log

  # Check for errors                                                                                                                                                                
  sudo grep -i error /var/log/freeradius/radius.log

  ---
  🧪 Test RADIUS Authentication

  # Test local authentication (after creating a customer)                                                                                                                           
  radtest username password localhost 0 testing123

  # Example:                                                                                                                                                                        
  radtest john@abutis secret123 localhost 0 testing123

  # Expected output if successful:                                                                                                                                                  
  # Sent Access-Request Id ...                                                                                                                                                      
  # Received Access-Accept Id ...                                                                                                                                                   

  ---
  🔧 Quick Diagnostics

  # Check if MySQL is running                                                                                                                                                       
  sudo systemctl status mysql

  # Check if FreeRADIUS can connect to MySQL                                                                                                                                        
  sudo freeradius -X | grep -i sql

  # Check FreeRADIUS version                                                                                                                                                        
  freeradius -v

  # List RADIUS ports                                                                                                                                                               
  sudo netstat -tlnp | grep radius
  # Should show ports 1812 (auth) and 1813 (accounting)                                                                                                                             

  # Check SQL module configuration                                                                                                                                                  
  sudo cat /etc/freeradius/3.0/mods-enabled/sql | grep -A 5 "mysql"                                                                                                                 

  ---
  🚨 Common Issues & Fixes

  # If FreeRADIUS won't start:                                                                                                                                                      
  sudo freeradius -CX  # Check config errors                                                                                                                                        

  # If SQL connection fails:                                                                                                                                                        
  mysql -u radius -p -e "SELECT 1"  # Test MySQL access                                                                                                                             

  # Clear logs and restart                                                                                                                                                          
  sudo systemctl stop freeradius
  sudo rm /var/log/freeradius/*.log                                                                                                                                                 
  sudo systemctl start freeradius

  # Check file permissions                                                                                                                                                          
  sudo chown -R freerad:freerad /etc/freeradius/3.0/
  sudo chmod 640 /etc/freeradius/3.0/mods-enabled/sql

 📈 Monitor Active Sessions

  # Check active RADIUS sessions                                                                                                                                                    
  mysql -u radius -p radius -e "SELECT * FROM radacct WHERE acctstoptime IS NULL;"                                                                                                  

  # Count active sessions                                                                                                                                                           
  mysql -u radius -p radius -e "SELECT COUNT(*) FROM radacct WHERE acctstoptime IS NULL;"                                                                                           

  ---
  Start with these first:
  # 1. Check if everything is running                                                                                                                                               
  sudo systemctl status freeradius
  sudo systemctl status mysql

  # 2. Test configuration                                                                                                                                                           
  sudo freeradius -CX

  # 3. View real-time logs                                                                                                                                                          
  sudo journalctl -u freeradius -f
