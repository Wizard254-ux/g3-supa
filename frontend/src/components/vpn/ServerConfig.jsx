import React, { useState, useEffect } from 'react';
import { Settings, Network, Shield, Users, FileText, Wrench, Eye, EyeOff, Copy, Check, Edit3, Save, X, Plus, ExternalLink, AlertCircle, Info, ChevronRight, ToggleLeft, ToggleRight } from 'lucide-react';
import { API_BASE_URL } from '../../App';

const ServerConfig = () => {
  const [config, setConfig] = useState(null);
  const [clientTemplate, setClientTemplate] = useState('');
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState('network');
  const [showSensitive, setShowSensitive] = useState(false);
  const [copied, setCopied] = useState('');
  const [editModes, setEditModes] = useState({});
  const [editData, setEditData] = useState({});
  const [enabledFields, setEnabledFields] = useState({});
  const [originalData, setOriginalData] = useState({});
  const [dirtyTabs, setDirtyTabs] = useState(new Set());
  const [showDiscardPrompt, setShowDiscardPrompt] = useState(false);
  const [pendingTab, setPendingTab] = useState(null);
  const [saving, setSaving] = useState(false);

  const tabs = [
    { id: 'network', label: 'Network', icon: Network },
    { id: 'security', label: 'Security', icon: Shield },
    { id: 'clients', label: 'Client', icon: Users },
    { id: 'logging', label: 'Logging', icon: FileText },
    { id: 'advanced', label: 'Advanced', icon: Wrench },
  ];

  // Comprehensive OpenVPN configuration definitions
  const configDefinitions = {
    network: [
      { key: 'server', type: 'text', required: true, description: 'VPN subnet and netmask', recommended: '10.8.0.0 255.255.255.0', docs: 'https://openvpn.net/community-resources/reference-manual-for-openvpn-2-4/#server' },
      { key: 'port', type: 'number', required: true, description: 'UDP/TCP port for server', recommended: '1194', docs: 'https://openvpn.net/community-resources/reference-manual-for-openvpn-2-4/#port' },
      { key: 'proto', type: 'select', options: ['udp', 'tcp', 'udp4', 'udp6', 'tcp4', 'tcp6'], description: 'Protocol type', recommended: 'udp', docs: 'https://openvpn.net/community-resources/reference-manual-for-openvpn-2-4/#proto' },
      { key: 'dev', type: 'select', options: ['tun', 'tap'], description: 'Virtual network device type', recommended: 'tun', docs: 'https://openvpn.net/community-resources/reference-manual-for-openvpn-2-4/#dev' },
      { key: 'topology', type: 'select', options: ['subnet', 'net30', 'p2p'], description: 'Virtual network topology', recommended: 'subnet', docs: 'https://openvpn.net/community-resources/reference-manual-for-openvpn-2-4/#topology' },
      { key: 'push', type: 'textarea', description: 'Options to push to clients', recommended: 'redirect-gateway def1 bypass-dhcp', docs: 'https://openvpn.net/community-resources/reference-manual-for-openvpn-2-4/#push' },
      { key: 'route', type: 'text', description: 'Add route to routing table', recommended: '192.168.1.0 255.255.255.0', docs: 'https://openvpn.net/community-resources/reference-manual-for-openvpn-2-4/#route' },
      { key: 'ifconfig-pool-persist', type: 'text', description: 'Persist client IP assignments', recommended: 'ipp.txt', docs: 'https://openvpn.net/community-resources/reference-manual-for-openvpn-2-4/#ifconfig-pool-persist' },
      { key: 'client-to-client', type: 'checkbox', description: 'Allow clients to communicate', recommended: false, docs: 'https://openvpn.net/community-resources/reference-manual-for-openvpn-2-4/#client-to-client' },
      { key: 'duplicate-cn', type: 'checkbox', description: 'Allow multiple clients with same certificate', recommended: false, docs: 'https://openvpn.net/community-resources/reference-manual-for-openvpn-2-4/#duplicate-cn' },
      { key: 'max-clients', type: 'number', description: 'Maximum number of concurrent clients', recommended: '100', docs: 'https://openvpn.net/community-resources/reference-manual-for-openvpn-2-4/#max-clients' },
    ],
    security: [
      { key: 'ca', type: 'file', required: true, description: 'Certificate Authority certificate', recommended: 'ca.crt', docs: 'https://openvpn.net/community-resources/reference-manual-for-openvpn-2-4/#ca' },
      { key: 'cert', type: 'file', required: true, description: 'Server certificate', recommended: 'server.crt', docs: 'https://openvpn.net/community-resources/reference-manual-for-openvpn-2-4/#cert' },
      { key: 'key', type: 'file', required: true, description: 'Server private key', recommended: 'server.key', docs: 'https://openvpn.net/community-resources/reference-manual-for-openvpn-2-4/#key' },
      { key: 'dh', type: 'file', description: 'Diffie-Hellman parameters', recommended: 'dh2048.pem', docs: 'https://openvpn.net/community-resources/reference-manual-for-openvpn-2-4/#dh' },
      { key: 'tls-auth', type: 'file', description: 'TLS authentication key', recommended: 'ta.key 0', docs: 'https://openvpn.net/community-resources/reference-manual-for-openvpn-2-4/#tls-auth' },
      { key: 'tls-crypt', type: 'file', description: 'TLS encryption and authentication', recommended: 'tls-crypt.key', docs: 'https://openvpn.net/community-resources/reference-manual-for-openvpn-2-4/#tls-crypt' },
      { key: 'cipher', type: 'select', options: ['AES-256-GCM', 'AES-128-GCM', 'AES-256-CBC', 'AES-128-CBC', 'CHACHA20-POLY1305'], description: 'Data channel encryption cipher', recommended: 'AES-256-GCM', docs: 'https://openvpn.net/community-resources/reference-manual-for-openvpn-2-4/#cipher' },
      { key: 'auth', type: 'select', options: ['SHA256', 'SHA512', 'SHA1', 'SHA384'], description: 'HMAC authentication algorithm', recommended: 'SHA256', docs: 'https://openvpn.net/community-resources/reference-manual-for-openvpn-2-4/#auth' },
      { key: 'tls-version-min', type: 'select', options: ['1.0', '1.1', '1.2', '1.3'], description: 'Minimum TLS version', recommended: '1.2', docs: 'https://openvpn.net/community-resources/reference-manual-for-openvpn-2-4/#tls-version-min' },
      { key: 'tls-cipher', type: 'select', options: ['TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384', 'TLS-ECDHE-ECDSA-WITH-AES-256-GCM-SHA384', 'TLS-ECDHE-RSA-WITH-AES-128-GCM-SHA256'], description: 'TLS control channel cipher', recommended: 'TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384', docs: 'https://openvpn.net/community-resources/reference-manual-for-openvpn-2-4/#tls-cipher' },
      { key: 'crl-verify', type: 'file', description: 'Certificate Revocation List', recommended: 'crl.pem', docs: 'https://openvpn.net/community-resources/reference-manual-for-openvpn-2-4/#crl-verify' },
      { key: 'remote-cert-tls', type: 'select', options: ['server', 'client'], description: 'Verify remote certificate usage', recommended: 'server', docs: 'https://openvpn.net/community-resources/reference-manual-for-openvpn-2-4/#remote-cert-tls' },
    ],
    clients: [
      { key: 'client-config-dir', type: 'text', description: 'Directory for client-specific configs', recommended: 'ccd', docs: 'https://openvpn.net/community-resources/reference-manual-for-openvpn-2-4/#client-config-dir' },
      { key: 'ccd-exclusive', type: 'checkbox', description: 'Only allow clients with config files', recommended: false, docs: 'https://openvpn.net/community-resources/reference-manual-for-openvpn-2-4/#ccd-exclusive' },
      { key: 'username-as-common-name', type: 'checkbox', description: 'Use username instead of certificate CN', recommended: false, docs: 'https://openvpn.net/community-resources/reference-manual-for-openvpn-2-4/#username-as-common-name' },
      { key: 'client-cert-not-required', type: 'checkbox', description: 'Disable client certificate requirement', recommended: false, docs: 'https://openvpn.net/community-resources/reference-manual-for-openvpn-2-4/#client-cert-not-required' },
      { key: 'auth-user-pass-verify', type: 'text', description: 'Script to verify username/password', recommended: '/etc/openvpn/checkpsw.sh via-env', docs: 'https://openvpn.net/community-resources/reference-manual-for-openvpn-2-4/#auth-user-pass-verify' },
      { key: 'script-security', type: 'select', options: ['0', '1', '2', '3'], description: 'Script execution security level', recommended: '2', docs: 'https://openvpn.net/community-resources/reference-manual-for-openvpn-2-4/#script-security' },
      { key: 'tmp-dir', type: 'text', description: 'Temporary directory for scripts', recommended: '/tmp', docs: 'https://openvpn.net/community-resources/reference-manual-for-openvpn-2-4/#tmp-dir' },
    ],
    logging: [
      { key: 'log', type: 'text', description: 'Output logging to file', recommended: '/var/log/openvpn.log', docs: 'https://openvpn.net/community-resources/reference-manual-for-openvpn-2-4/#log' },
      { key: 'log-append', type: 'text', description: 'Append to existing log file', recommended: '/var/log/openvpn.log', docs: 'https://openvpn.net/community-resources/reference-manual-for-openvpn-2-4/#log-append' },
      { key: 'status', type: 'text', description: 'Status file for monitoring', recommended: '/var/log/openvpn-status.log', docs: 'https://openvpn.net/community-resources/reference-manual-for-openvpn-2-4/#status' },
      { key: 'status-version', type: 'select', options: ['1', '2', '3'], description: 'Status file format version', recommended: '2', docs: 'https://openvpn.net/community-resources/reference-manual-for-openvpn-2-4/#status-version' },
      { key: 'verb', type: 'select', options: ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9'], description: 'Verbosity level', recommended: '3', docs: 'https://openvpn.net/community-resources/reference-manual-for-openvpn-2-4/#verb' },
      { key: 'mute', type: 'number', description: 'Silence repeating messages', recommended: '20', docs: 'https://openvpn.net/community-resources/reference-manual-for-openvpn-2-4/#mute' },
      { key: 'explicit-exit-notify', type: 'select', options: ['0', '1', '2'], description: 'Notify clients on server restart', recommended: '1', docs: 'https://openvpn.net/community-resources/reference-manual-for-openvpn-2-4/#explicit-exit-notify' },
      { key: 'syslog', type: 'text', description: 'Output to syslog facility', recommended: 'openvpn', docs: 'https://openvpn.net/community-resources/reference-manual-for-openvpn-2-4/#syslog' },
    ],
    advanced: [
      { key: 'daemon', type: 'checkbox', description: 'Run as daemon process', recommended: true, docs: 'https://openvpn.net/community-resources/reference-manual-for-openvpn-2-4/#daemon' },
      { key: 'user', type: 'text', description: 'Run as specific user', recommended: 'nobody', docs: 'https://openvpn.net/community-resources/reference-manual-for-openvpn-2-4/#user' },
      { key: 'group', type: 'text', description: 'Run as specific group', recommended: 'nogroup', docs: 'https://openvpn.net/community-resources/reference-manual-for-openvpn-2-4/#group' },
      { key: 'persist-key', type: 'checkbox', description: 'Keep keys in memory on restart', recommended: true, docs: 'https://openvpn.net/community-resources/reference-manual-for-openvpn-2-4/#persist-key' },
      { key: 'persist-tun', type: 'checkbox', description: 'Keep TUN/TAP open on restart', recommended: true, docs: 'https://openvpn.net/community-resources/reference-manual-for-openvpn-2-4/#persist-tun' },
      { key: 'keepalive', type: 'text', description: 'Ping and ping-restart intervals', recommended: '10 120', docs: 'https://openvpn.net/community-resources/reference-manual-for-openvpn-2-4/#keepalive' },
      { key: 'comp-lzo', type: 'select', options: ['no', 'yes', 'adaptive'], description: 'LZO compression (deprecated)', recommended: 'no', docs: 'https://openvpn.net/community-resources/reference-manual-for-openvpn-2-4/#comp-lzo' },
      { key: 'compress', type: 'select', options: ['lz4', 'lzo', 'stub'], description: 'Compression algorithm', recommended: 'lz4', docs: 'https://openvpn.net/community-resources/reference-manual-for-openvpn-2-4/#compress' },
      { key: 'fast-io', type: 'checkbox', description: 'Optimize TUN/TAP I/O', recommended: false, docs: 'https://openvpn.net/community-resources/reference-manual-for-openvpn-2-4/#fast-io' },
      { key: 'sndbuf', type: 'number', description: 'Set TCP/UDP send buffer size', recommended: '0', docs: 'https://openvpn.net/community-resources/reference-manual-for-openvpn-2-4/#sndbuf' },
      { key: 'rcvbuf', type: 'number', description: 'Set TCP/UDP receive buffer size', recommended: '0', docs: 'https://openvpn.net/community-resources/reference-manual-for-openvpn-2-4/#rcvbuf' },
    ]
  };

  useEffect(() => {
    fetchConfig();
  }, []);

  const fetchConfig = async () => {
    setLoading(true);
    try {
      const [configRes, templateRes] = await Promise.all([
        fetch(`${API_BASE_URL}/server/config`, {
          headers: { 'x-api-key': 'your-django-api-key-for-authentication' }
        }),
        fetch(`${API_BASE_URL}/client/template`, {
          headers: { 'x-api-key': 'your-django-api-key-for-authentication' }
        })
      ]);

      if (configRes.ok) {
        const configData = await configRes.json();
        setConfig(configData);
        const currentConfig = configData.config || configData;
        setOriginalData(currentConfig);
        setEditData(currentConfig);

        // Set enabled fields based on existing config
        const enabled = {};
        Object.keys(currentConfig).forEach(key => {
          enabled[key] = true;
        });
        setEnabledFields(enabled);
      }
      if (templateRes.ok) setClientTemplate(await templateRes.text());
    } catch (err) {
      console.error('Failed to fetch config:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleTabChange = (tabId) => {
    if (dirtyTabs.size > 0) {
      setPendingTab(tabId);
      setShowDiscardPrompt(true);
      return;
    }
    setActiveTab(tabId);
  };

  const handleEditToggle = (tabId) => {
    setEditModes(prev => ({
      ...prev,
      [tabId]: !prev[tabId]
    }));
  };

  const handleFieldChange = (key, value) => {
    setEditData(prev => ({ ...prev, [key]: value }));
    setDirtyTabs(prev => new Set([...prev, activeTab]));
  };

  const handleFieldToggle = (key, enabled) => {
    setEnabledFields(prev => ({ ...prev, [key]: enabled }));
    if (!enabled) {
      // Remove from editData if disabled
      setEditData(prev => {
        const newData = { ...prev };
        delete newData[key];
        return newData;
      });
    } else {
      // Add default value if enabled
      const fieldDef = configDefinitions[activeTab]?.find(f => f.key === key);
      if (fieldDef) {
        setEditData(prev => ({ ...prev, [key]: fieldDef.recommended }));
      }
    }
    setDirtyTabs(prev => new Set([...prev, activeTab]));
  };

  const handleSave = async (tabId) => {
    setSaving(true);
    try {
      const changes = {};
      const currentTabFields = configDefinitions[tabId] || [];

      // Only include enabled and changed fields
      currentTabFields.forEach(fieldDef => {
        const key = fieldDef.key;
        if (enabledFields[key] && editData[key] !== originalData[key]) {
          changes[key] = editData[key];
        }
      });

      if (Object.keys(changes).length > 0) {
        const response = await fetch(`${API_BASE_URL}/server/config`, {
          method: 'PUT',
          headers: {
            'Content-Type': 'application/json',
            'x-api-key': 'your-django-api-key-for-authentication'
          },
          body: JSON.stringify(changes)
        });

        if (response.ok) {
          await fetchConfig();
          setEditModes(prev => ({ ...prev, [tabId]: false }));
          setDirtyTabs(prev => {
            const newSet = new Set(prev);
            newSet.delete(tabId);
            return newSet;
          });
          setCopied('saved');
          setTimeout(() => setCopied(''), 2000);
        }
      }
    } catch (err) {
      console.error('Failed to save config:', err);
    } finally {
      setSaving(false);
    }
  };

  const handleDiscard = () => {
    setEditData({ ...originalData });
    setDirtyTabs(new Set());
    setEditModes({});
    setShowDiscardPrompt(false);
    if (pendingTab) {
      setActiveTab(pendingTab);
      setPendingTab(null);
    }
  };

  const copyToClipboard = async (text, key) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(key);
      setTimeout(() => setCopied(''), 2000);
    } catch (err) {
      console.error('Failed to copy:', err);
    }
  };

  const maskSensitive = (value) => {
    if (!showSensitive && typeof value === 'string' && value.length > 10) {
      return value.substring(0, 4) + '•'.repeat(value.length - 8) + value.substring(value.length - 4);
    }
    return value;
  };

  const renderField = (fieldDef, value, isEditing) => {
    const { key, type, options, description } = fieldDef;
    const currentValue = editData[key] ?? value ?? '';
    const isEnabled = enabledFields[key];

    if (!isEditing) {
      return (
        <div className="flex items-center justify-between py-3 px-4 bg-gray-50 rounded-sm hover:bg-gray-100 transition-colors">
          <div className="flex-1">
            <div className="flex items-center space-x-2">
              <span className="text-sm font-medium text-gray-800 capitalize">
                {key.replace(/-/g, ' ').replace(/_/g, ' ')}
              </span>
              <a
                href={fieldDef.docs}
                target="_blank"
                rel="noopener noreferrer"
                className="text-blue-600 hover:text-blue-800"
              >
                <ExternalLink className="w-3 h-3" />
              </a>
            </div>
            <p className="text-xs text-gray-500 mt-1">{description}</p>
          </div>
          <div className="flex items-center space-x-2">
            <span className="text-sm font-mono text-gray-700 bg-white px-2 py-1 rounded-sm border">
              {value ? (typeof value === 'boolean' ? (value ? 'Enabled' : 'Disabled') : maskSensitive(String(value))) : 'Not set'}
            </span>
            <button
              onClick={() => copyToClipboard(String(value), key)}
              className="p-1 text-gray-400 hover:text-green-600 transition-colors"
              title="Copy value"
            >
              {copied === key ? (
                <Check className="w-3 h-3 text-green-600" />
              ) : (
                <Copy className="w-3 h-3" />
              )}
            </button>
          </div>
        </div>
      );
    }

    return (
      <div className="flex items-center justify-between py-3 px-4 bg-gray-50 rounded-sm">
        <div className="flex items-center space-x-3">
          <button
            onClick={() => handleFieldToggle(key, !isEnabled)}
            className={`${isEnabled ? 'text-green-600' : 'text-gray-400'} hover:text-green-700 transition-colors`}
          >
            {isEnabled ? <ToggleRight className="w-5 h-5" /> : <ToggleLeft className="w-5 h-5" />}
          </button>
          <div className="flex-1">
            <div className="flex items-center space-x-2">
              <span className={`text-sm font-medium capitalize ${isEnabled ? 'text-gray-800' : 'text-gray-500'}`}>
                {key.replace(/-/g, ' ').replace(/_/g, ' ')}
              </span>
              <a
                href={fieldDef.docs}
                target="_blank"
                rel="noopener noreferrer"
                className="text-blue-600 hover:text-blue-800"
              >
                <ExternalLink className="w-3 h-3" />
              </a>
            </div>
            <p className="text-xs text-gray-500 mt-1">{description}</p>
          </div>
        </div>
        <div className="ml-4">
          {isEnabled && (
            <>
              {type === 'select' ? (
                <select
                  value={currentValue}
                  onChange={(e) => handleFieldChange(key, e.target.value)}
                  className="text-sm border border-gray-300 rounded-sm px-3 py-2 focus:outline-none focus:ring-2 focus:ring-green-500 focus:border-green-500"
                >
                  <option value="">Select...</option>
                  {options?.map(option => (
                    <option key={option} value={option}>{option}</option>
                  ))}
                </select>
              ) : type === 'checkbox' ? (
                <input
                  type="checkbox"
                  checked={currentValue === true || currentValue === 'true'}
                  onChange={(e) => handleFieldChange(key, e.target.checked)}
                  className="w-4 h-4 text-green-600 focus:ring-green-500 border-gray-300 rounded"
                />
              ) : type === 'number' ? (
                <input
                  type="number"
                  value={currentValue}
                  onChange={(e) => handleFieldChange(key, e.target.value)}
                  className="text-sm border border-gray-300 rounded-sm px-3 py-2 w-32 focus:outline-none focus:ring-2 focus:ring-green-500 focus:border-green-500"
                />
              ) : type === 'textarea' ? (
                <textarea
                  value={currentValue}
                  onChange={(e) => handleFieldChange(key, e.target.value)}
                  rows={2}
                  className="text-sm border border-gray-300 rounded-sm px-3 py-2 w-64 focus:outline-none focus:ring-2 focus:ring-green-500 focus:border-green-500"
                />
              ) : (
                <input
                  type="text"
                  value={currentValue}
                  onChange={(e) => handleFieldChange(key, e.target.value)}
                  className="text-sm border border-gray-300 rounded-sm px-3 py-2 w-64 focus:outline-none focus:ring-2 focus:ring-green-500 focus:border-green-500"
                />
              )}
            </>
          )}
        </div>
      </div>
    );
  };

  const renderConfigSection = (tabId) => {
    const fields = configDefinitions[tabId] || [];
    const isEditing = editModes[tabId];

    if (fields.length === 0) {
      return (
        <div className="text-center py-8 text-gray-500">
          <Settings className="w-8 h-8 mx-auto mb-2 opacity-50" />
          <p className="text-sm">No configuration options available</p>
        </div>
      );
    }

    return (
      <div className="space-y-2">
        {fields.map(fieldDef => {
          const value = editData[fieldDef.key];
          // Show field if it has a value OR if we're in edit mode
          if (!isEditing && (value === undefined || value === null)) {
            return null;
          }
          return (
            <div key={fieldDef.key}>
              {renderField(fieldDef, value, isEditing)}
            </div>
          );
        })}
      </div>
    );
  };

  const renderClientTemplate = () => {
    let templateData;
    try {
      templateData = JSON.parse(clientTemplate);
    } catch {
      return (
        <div className="bg-gray-900 text-gray-300 rounded-sm p-3 font-mono text-xs max-h-64 overflow-y-auto">
          <pre className="whitespace-pre-wrap">{clientTemplate}</pre>
        </div>
      );
    }

    const configEntries = Object.entries(templateData.config || {});

    return (
      <div className="space-y-2">
        {configEntries.map(([key, value]) => (
          <div key={key} className="flex items-center justify-between p-3 bg-gray-50 rounded-sm hover:bg-gray-100 transition-colors">
            <div className="flex-1">
              <div className="flex items-center space-x-2">
                <span className="text-sm font-medium text-gray-800">{key}</span>
                <a
                  href={`https://openvpn.net/community-resources/reference-manual-for-openvpn-2-4/#${key}`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-blue-600 hover:text-blue-800"
                >
                  <ExternalLink className="w-3 h-3" />
                </a>
              </div>
              <p className="text-xs text-gray-500 mt-1">{getFieldDescription(key)}</p>
            </div>
            <span className="text-sm font-mono text-gray-700 bg-white px-2 py-1 rounded-sm border">
              {typeof value === 'boolean' ? (value ? 'true' : 'false') : value}
            </span>
          </div>
        ))}
      </div>
    );
  };

  const getFieldDescription = (key) => {
    const descriptions = {
      'auth': 'HMAC authentication algorithm for data channel',
      'auth-nocache': 'Don\'t cache authentication credentials',
      'cipher': 'Encryption cipher for data channel',
      'client': 'Configure client mode',
      'dev': 'TUN/TAP virtual network device',
      'ignore-unknown-option': 'Ignore unknown configuration options',
      'nobind': 'Don\'t bind to local address and port',
      'persist-key': 'Keep keys in memory across restarts',
      'persist-tun': 'Keep TUN device open across restarts',
      'proto': 'Network protocol to use',
      'remote': 'Remote server hostname/IP and port',
      'remote-cert-tls': 'Verify remote certificate key usage',
      'resolv-retry': 'DNS resolution retry behavior',
      'setenv': 'Set environment variable',
      'tls-cipher': 'TLS control channel cipher suite',
      'tls-client': 'Enable TLS client mode',
      'tls-version-min': 'Minimum acceptable TLS version',
      'verb': 'Verbosity level for logging output',
      'verify-x509-name': 'Verify peer certificate subject',
    };
    return descriptions[key] || 'OpenVPN configuration parameter';
  };

  if (loading) {
    return (
      <div className="bg-white rounded-sm border border-gray-200 p-4">
        <div className="animate-pulse space-y-3">
          <div className="h-4 bg-gray-200 rounded w-1/4"></div>
          <div className="flex space-x-1 mb-4">
            {[1, 2, 3, 4, 5].map(i => (
              <div key={i} className="h-8 bg-gray-200 rounded w-20"></div>
            ))}
          </div>
          <div className="space-y-2">
            {[1, 2, 3, 4].map(i => (
              <div key={i} className="h-12 bg-gray-200 rounded"></div>
            ))}
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="bg-white h-full rounded-sm border border-gray-200">
      <div className="px-4 py-3 border-b border-gray-200 flex items-center justify-between">
        <h3 className="text-sm font-semibold text-gray-900 flex items-center">
          <Settings className="w-4 h-4 mr-2 text-green-600" />
          Server Configuration
          {dirtyTabs.size > 0 && (
            <span className="ml-2 w-2 h-2 bg-orange-400 rounded-full animate-pulse"></span>
          )}
        </h3>
        <div className="flex items-center space-x-2">
          <button
            onClick={() => setShowSensitive(!showSensitive)}
            className="flex items-center px-2 py-1 text-xs text-gray-600 hover:text-gray-900 transition-colors"
          >
            {showSensitive ? <EyeOff className="w-3 h-3 mr-1" /> : <Eye className="w-3 h-3 mr-1" />}
            {showSensitive ? 'Hide' : 'Show'} Sensitive
          </button>
          <button
            onClick={fetchConfig}
            className="px-2 py-1 text-xs bg-green-100 text-green-700 rounded-sm hover:bg-green-200 transition-colors"
          >
            Refresh
          </button>
        </div>
      </div>

      {/* Discard Changes Prompt */}
      {showDiscardPrompt && (
        <div className="px-4 py-2 bg-orange-50 border-b border-orange-200">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-2">
              <AlertCircle className="w-4 h-4 text-orange-600" />
              <span className="text-sm text-orange-800">You have unsaved changes. Discard them?</span>
            </div>
            <div className="flex items-center space-x-2">
              <button
                onClick={handleDiscard}
                className="px-2 py-1 text-xs bg-orange-600 text-white rounded-sm hover:bg-orange-700 transition-colors"
              >
                Discard
              </button>
              <button
                onClick={() => setShowDiscardPrompt(false)}
                className="px-2 py-1 text-xs bg-gray-100 text-gray-700 rounded-sm hover:bg-gray-200 transition-colors"
              >
                Cancel
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Tab Navigation */}
      <div className="border-b border-gray-200">
        <nav className="flex space-x-0" aria-label="Tabs">
          {tabs.map((tab) => (
            <button
              key={tab.id}
              onClick={() => handleTabChange(tab.id)}
              className={`relative flex items-center px-3 py-2 text-xs font-medium border-b-2 transition-colors ${
                activeTab === tab.id
                  ? 'border-green-500 text-green-600 bg-green-50'
                  : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
              }`}
            >
              <tab.icon className="w-3 h-3 mr-1.5" />
              {tab.label}
              {dirtyTabs.has(tab.id) && (
                <span className="absolute -top-1 -right-1 w-2 h-2 bg-orange-400 rounded-full"></span>
              )}
            </button>
          ))}
        </nav>
      </div>

      {/* Tab Content */}
      <div className="flex flex-col h-full">
        <div className="flex items-center justify-between px-4 py-3 border-b border-gray-100">
          <h4 className="text-sm font-medium text-gray-800 flex items-center">
            {tabs.find(t => t.id === activeTab)?.icon && (
              <span className="mr-2">
                {React.createElement(tabs.find(t => t.id === activeTab).icon, {
                  className: "w-4 h-4 text-blue-600"
                })}
              </span>
            )}
            {tabs.find(t => t.id === activeTab)?.label} Configuration
          </h4>
          <div className="flex items-center space-x-2">
            {!editModes[activeTab] ? (
              <button
                onClick={() => handleEditToggle(activeTab)}
                className="flex items-center px-3 py-1 text-xs bg-blue-100 text-blue-700 rounded-sm hover:bg-blue-200 transition-colors"
              >
                <Edit3 className="w-3 h-3 mr-1" />
                Edit
              </button>
            ) : (
              <>
                <button
                  onClick={() => handleSave(activeTab)}
                  disabled={saving || !dirtyTabs.has(activeTab)}
                  className="flex items-center px-3 py-1 text-xs bg-green-600 text-white rounded-sm hover:bg-green-700 disabled:opacity-50 transition-colors"
                >
                  <Save className="w-3 h-3 mr-1" />
                  {saving ? 'Saving...' : 'Save'}
                </button>
                <button
                  onClick={() => handleEditToggle(activeTab)}
                  className="flex items-center px-2 py-1 text-xs bg-gray-100 text-gray-700 rounded-sm hover:bg-gray-200 transition-colors"
                >
                  <X className="w-3 h-3 mr-1" />
                  Cancel
                </button>
              </>
            )}
          </div>
        </div>

        <div className="flex-1 overflow-y-auto p-4">
          {activeTab === 'clients' && clientTemplate ? (
            <div className="space-y-6">
              <div>
                {renderConfigSection(activeTab)}
              </div>
              <div className="border-t border-gray-200 pt-6">
                <div className="flex items-center justify-between mb-4">
                  <h4 className="text-sm font-medium text-gray-700">Client Configuration Template</h4>
                  <button
                    onClick={() => copyToClipboard(clientTemplate, 'template')}
                    className="flex items-center px-2 py-1 text-xs text-gray-600 hover:text-green-600 transition-colors"
                  >
                    {copied === 'template' ? (
                      <>
                        <Check className="w-3 h-3 mr-1" />
                        Copied
                      </>
                    ) : (
                      <>
                        <Copy className="w-3 h-3 mr-1" />
                        Copy Template
                      </>
                    )}
                  </button>
                </div>
                {renderClientTemplate()}
              </div>
            </div>
          ) : (
            renderConfigSection(activeTab)
          )}
        </div>
      </div>
    </div>
  );
};

export default ServerConfig;