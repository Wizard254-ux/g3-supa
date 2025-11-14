#!/bin/bash

# Base directory
BASE_DIR="isp_middleware"

# Create directory structure
mkdir -p $BASE_DIR/{auth,api,models,services,utils,scripts,configs/{freeradius,openvpn,mikrotik,systemd},logs}

# Create root-level files
touch $BASE_DIR/{app.py,requirements.txt,config.py,.env,wsgi.py,radius_server.py,mikrotik_api.py,openvpn_manager.py}

# Create auth module files
touch $BASE_DIR/auth/{__init__.py,radius_auth.py,hotspot_auth.py,pppoe_auth.py,user_manager.py}

# Create API module files
touch $BASE_DIR/api/{__init__.py,auth_api.py,mikrotik_api.py,usage_api.py,vpn_api.py,bandwidth_api.py}

# Create models
touch $BASE_DIR/models/{__init__.py,user_session.py,usage_log.py,radius_log.py,network_device.py}

# Create services
touch $BASE_DIR/services/{__init__.py,radius_service.py,mikrotik_service.py,bandwidth_service.py,usage_service.py,notification_service.py}

# Create utils
touch $BASE_DIR/utils/{__init__.py,crypto.py,network.py,logging.py,decorators.py}

# Create scripts
touch $BASE_DIR/scripts/{setup_radius.sh,setup_openvpn.sh,mikrotik_sync.py,user_sync.py}

# Create empty config folders
mkdir -p $BASE_DIR/configs/{freeradius,openvpn,mikrotik,systemd}

# Create log files
touch $BASE_DIR/logs/{radius.log,mikrotik.log,openvpn.log,app.log}

echo "✅ Directory structure created under '$BASE_DIR'"
