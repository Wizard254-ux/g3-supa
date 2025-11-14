import { useState, useEffect } from 'react';
import { FileText, RefreshCw, Download, Activity, Users, Shield, Network, AlertTriangle, Info, CheckCircle, XCircle } from 'lucide-react';
import { API_BASE_URL } from '../../App';

const ServerLogs = () => {
  const [logs, setLogs] = useState([]);
  const [rawLogs, setRawLogs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [autoRefresh, setAutoRefresh] = useState(false);
  const [viewMode, setViewMode] = useState('enhanced'); // 'enhanced' or 'raw'
  const [logStats, setLogStats] = useState({});

  useEffect(() => {
    fetchLogs();
  }, []);

  useEffect(() => {
    let interval;
    if (autoRefresh) {
      interval = setInterval(fetchLogs, 5000);
    }
    return () => clearInterval(interval);
  }, [autoRefresh]);

  const fetchLogs = async () => {
    try {
      const response = await fetch(`${API_BASE_URL}/server/logs`, {
        headers: { 'x-api-key': 'your-django-api-key-for-authentication' }
      });

      if (response.ok) {
        const data = await response.json();
        const logEntries = Array.isArray(data) ? data : data.logs || [];
        setRawLogs(logEntries);
        const parsedLogs = parseLogEntries(logEntries);
        setLogs(parsedLogs);
        setLogStats(generateLogStats(parsedLogs));
      }
    } catch (err) {
      console.error('Failed to fetch logs:', err);
    } finally {
      setLoading(false);
    }
  };

  const parseLogEntries = (logEntries) => {
    return logEntries.map((logEntry, index) => {
      const logText = typeof logEntry === 'string' ? logEntry : logEntry.message || '';

      // Parse timestamp and message
      const timestampMatch = logText.match(/^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})/);
      const timestamp = timestampMatch ? timestampMatch[1] : 'Unknown';

      // Extract process and message
      const processMatch = logText.match(/ovpn-server\[(\d+)\]:\s*(.+)$/);
      const systemdMatch = logText.match(/systemd\[\d+\]:\s*(.+)$/);

      let category, level, message, details = {};

      if (processMatch) {
        const pid = processMatch[1];
        message = processMatch[2];
        details.pid = pid;

        // Categorize OpenVPN messages
        if (message.includes('Initialization Sequence Completed')) {
          category = 'startup';
          level = 'success';
          details.event = 'Server fully initialized and ready';
        } else if (message.includes('OpenVPN') && message.includes('built on')) {
          category = 'startup';
          level = 'info';
          details.event = 'OpenVPN version information';
          details.version = message.match(/OpenVPN\s+([\d.]+)/)?.[1];
        } else if (message.includes('TUN/TAP device') && message.includes('opened')) {
          category = 'network';
          level = 'success';
          details.event = 'Virtual network interface created';
          details.device = message.match(/device\s+(\w+)/)?.[1];
        } else if (message.includes('net_addr_v4_add')) {
          category = 'network';
          level = 'success';
          details.event = 'IP address assigned to interface';
          details.ip = message.match(/(\d+\.\d+\.\d+\.\d+\/\d+)/)?.[1];
        } else if (message.includes('UDPv4 link local')) {
          category = 'network';
          level = 'info';
          details.event = 'Server listening on UDP port';
          details.port = message.match(/:(\d+)/)?.[1];
        } else if (message.includes('Cipher') && message.includes('initialized')) {
          category = 'security';
          level = 'success';
          details.event = 'Encryption cipher configured';
          details.cipher = message.match(/Cipher\s+'([^']+)'/)?.[1];
        } else if (message.includes('CRL: loaded')) {
          category = 'security';
          level = 'success';
          details.event = 'Certificate Revocation List loaded';
        } else if (message.includes('IFCONFIG POOL')) {
          category = 'network';
          level = 'info';
          details.event = 'IP pool configuration';
          details.range = message.match(/base=(\d+\.\d+\.\d+\.\d+)\s+size=(\d+)/);
        } else if (message.includes('SIGTERM')) {
          category = 'system';
          level = 'warning';
          details.event = 'Server shutdown signal received';
        } else if (message.includes('error') || message.includes('Error')) {
          category = 'error';
          level = 'error';
          details.event = 'Error occurred';
        } else if (message.includes('warning') || message.includes('Warning')) {
          category = 'warning';
          level = 'warning';
          details.event = 'Warning message';
        } else {
          category = 'general';
          level = 'info';
          details.event = 'General system message';
        }
      } else if (systemdMatch) {
        message = systemdMatch[1];
        category = 'system';

        if (message.includes('Started OpenVPN')) {
          level = 'success';
          details.event = 'VPN service started successfully';
        } else if (message.includes('Starting OpenVPN')) {
          level = 'info';
          details.event = 'VPN service starting';
        } else if (message.includes('Stopped OpenVPN')) {
          level = 'warning';
          details.event = 'VPN service stopped';
        } else if (message.includes('Stopping OpenVPN')) {
          level = 'warning';
          details.event = 'VPN service stopping';
        } else {
          level = 'info';
          details.event = 'System message';
        }
      } else {
        category = 'unknown';
        level = 'info';
        message = logText;
        details.event = 'Unknown log format';
      }

      return {
        id: index,
        timestamp,
        category,
        level,
        message,
        details,
        raw: logText
      };
    });
  };

  const generateLogStats = (parsedLogs) => {
    const stats = {
      total: parsedLogs.length,
      categories: {},
      levels: {},
      recent: {
        startups: 0,
        shutdowns: 0,
        errors: 0,
        connections: 0
      }
    };

    parsedLogs.forEach(log => {
      // Count categories
      stats.categories[log.category] = (stats.categories[log.category] || 0) + 1;

      // Count levels
      stats.levels[log.level] = (stats.levels[log.level] || 0) + 1;

      // Count recent events
      if (log.details.event?.includes('initialized')) stats.recent.startups++;
      if (log.details.event?.includes('stopped') || log.details.event?.includes('shutdown')) stats.recent.shutdowns++;
      if (log.level === 'error') stats.recent.errors++;
    });

    return stats;
  };

  const getCategoryIcon = (category) => {
    switch (category) {
      case 'startup': return <Activity className="w-4 h-4" />;
      case 'network': return <Network className="w-4 h-4" />;
      case 'security': return <Shield className="w-4 h-4" />;
      case 'system': return <CheckCircle className="w-4 h-4" />;
      case 'error': return <XCircle className="w-4 h-4" />;
      case 'warning': return <AlertTriangle className="w-4 h-4" />;
      default: return <Info className="w-4 h-4" />;
    }
  };

  const getCategoryColor = (category, level) => {
    switch (level) {
      case 'success': return 'text-green-400';
      case 'error': return 'text-red-400';
      case 'warning': return 'text-yellow-400';
      case 'info':
        switch (category) {
          case 'network': return 'text-blue-400';
          case 'security': return 'text-purple-400';
          case 'system': return 'text-cyan-400';
          default: return 'text-gray-400';
        }
      default: return 'text-gray-400';
    }
  };

  const downloadLogs = async () => {
    try {
      const response = await fetch(`${API_BASE_URL}/server/logs`, {
        headers: { 'x-api-key': 'your-django-api-key-for-authentication' }
      });

      if (response.ok) {
        const logs = await response.text();
        const blob = new Blob([logs], { type: 'text/plain' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `vpn-logs-${new Date().toISOString().split('T')[0]}.txt`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
      }
    } catch (err) {
      console.error('Failed to download logs:', err);
    }
  };

  if (loading) {
    return (
      <div className="bg-white rounded-sm border border-gray-200 p-4">
        <div className="animate-pulse space-y-3">
          <div className="h-4 bg-gray-200 rounded w-1/4"></div>
          <div className="space-y-2">
            {[1, 2, 3, 4, 5].map(i => (
              <div key={i} className="h-6 bg-gray-200 rounded"></div>
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
          <FileText className="w-4 h-4 mr-2 text-green-600" />
          Server Logs ({logStats.total})
        </h3>
        <div className="flex items-center space-x-2">
          <select
            value={viewMode}
            onChange={(e) => setViewMode(e.target.value)}
            className="px-2 py-1 text-xs border border-gray-300 rounded-sm focus:outline-none focus:ring-1 focus:ring-green-500"
          >
            <option value="enhanced">Enhanced View</option>
            <option value="raw">Raw Logs</option>
          </select>
          <button
            onClick={() => setAutoRefresh(!autoRefresh)}
            className={`px-2 py-1 text-xs rounded-sm transition-colors ${
              autoRefresh 
                ? 'bg-green-100 text-green-700' 
                : 'bg-gray-100 text-gray-600 hover:bg-gray-200'
            }`}
          >
            Auto Refresh
          </button>
          <button
            onClick={fetchLogs}
            className="p-1 text-gray-600 hover:text-green-600 transition-colors"
            title="Refresh Logs"
          >
            <RefreshCw className="w-4 h-4" />
          </button>
          <button
            onClick={downloadLogs}
            className="p-1 text-gray-600 hover:text-green-600 transition-colors"
            title="Download Logs"
          >
            <Download className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Log Statistics */}
      <div className="px-4 py-2 bg-gray-50 border-b border-gray-200">
        <div className="grid grid-cols-5 gap-4 text-center">
          <div>
            <div className="text-xs text-gray-500">Success</div>
            <div className="text-sm font-medium text-green-600">{logStats.levels?.success || 0}</div>
          </div>
          <div>
            <div className="text-xs text-gray-500">Warnings</div>
            <div className="text-sm font-medium text-yellow-600">{logStats.levels?.warning || 0}</div>
          </div>
          <div>
            <div className="text-xs text-gray-500">Errors</div>
            <div className="text-sm font-medium text-red-600">{logStats.levels?.error || 0}</div>
          </div>
          <div>
            <div className="text-xs text-gray-500">Network</div>
            <div className="text-sm font-medium text-blue-600">{logStats.categories?.network || 0}</div>
          </div>
          <div>
            <div className="text-xs text-gray-500">Security</div>
            <div className="text-sm font-medium text-purple-600">{logStats.categories?.security || 0}</div>
          </div>
        </div>
      </div>

      <div className="p-1">
        <div className="bg-black text-green-400 rounded-sm p-3 font-mono text-xs h-80 overflow-y-auto">
          {!logs.length ? (
            <div className="text-gray-500 text-center py-8">
              <FileText className="w-8 h-8 mx-auto mb-2 opacity-50" />
              <p>No logs available</p>
            </div>
          ) : viewMode === 'enhanced' ? (
            logs.slice(-100).map((log) => (
              <div key={log.id} className="mb-2 pb-2 border-b border-gray-800 last:border-b-0">
                <div className="flex items-start space-x-2">
                  <span className="text-gray-500 text-xs mt-0.5">{log.timestamp}</span>
                  <div className={`${getCategoryColor(log.category, log.level)} mt-0.5`}>
                    {getCategoryIcon(log.category)}
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className={`text-sm ${getCategoryColor(log.category, log.level)} font-medium`}>
                      {log.details.event}
                    </div>
                    {log.details.version && (
                      <div className="text-cyan-400 text-xs">Version: {log.details.version}</div>
                    )}
                    {log.details.device && (
                      <div className="text-blue-400 text-xs">Device: {log.details.device}</div>
                    )}
                    {log.details.ip && (
                      <div className="text-green-400 text-xs">IP: {log.details.ip}</div>
                    )}
                    {log.details.port && (
                      <div className="text-yellow-400 text-xs">Port: {log.details.port}</div>
                    )}
                    {log.details.cipher && (
                      <div className="text-purple-400 text-xs">Cipher: {log.details.cipher}</div>
                    )}
                    {log.details.pid && (
                      <div className="text-gray-500 text-xs">PID: {log.details.pid}</div>
                    )}
                    <div className="text-gray-400 text-xs mt-1 truncate" title={log.message}>
                      {log.message}
                    </div>
                  </div>
                </div>
              </div>
            ))
          ) : (
            rawLogs.slice(-50).map((log, index) => (
              <div key={index} className="mb-1 text-green-400">
                {typeof log === 'string' ? log : log.message || JSON.stringify(log)}
              </div>
            ))
          )}
        </div>

        <div className="mt-3 text-xs text-gray-500 flex justify-between items-center">
          <span>
            Showing last {viewMode === 'enhanced' ? '100' : '50'} entries •
            <span className="ml-1">
              {viewMode === 'enhanced' ? 'Enhanced analysis mode' : 'Raw log mode'}
            </span>
          </span>
          <div className="flex items-center space-x-4">
            {autoRefresh && (
              <span className="flex items-center">
                <div className="w-2 h-2 bg-green-400 rounded-full mr-1 animate-pulse"></div>
                Live
              </span>
            )}
            <div className="flex items-center space-x-2">
              <div className="flex items-center">
                <div className="w-2 h-2 bg-green-400 rounded-full mr-1"></div>
                <span>Success</span>
              </div>
              <div className="flex items-center">
                <div className="w-2 h-2 bg-yellow-400 rounded-full mr-1"></div>
                <span>Warning</span>
              </div>
              <div className="flex items-center">
                <div className="w-2 h-2 bg-red-400 rounded-full mr-1"></div>
                <span>Error</span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default ServerLogs;