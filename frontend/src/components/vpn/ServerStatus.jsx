import { useState, useEffect } from 'react';
import { Activity, Server, Wifi, AlertCircle } from 'lucide-react';
import { API_BASE_URL } from '../../App';

const ServerStatus = () => {
  const [status, setStatus] = useState(null);
  const [health, setHealth] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    fetchServerData();
  }, []);

  const fetchServerData = async () => {
    setLoading(true);
    try {
      const [statusRes, healthRes] = await Promise.all([
        fetch(`${API_BASE_URL}/status`, {
          headers: { 'x-api-key': 'your-django-api-key-for-authentication' }
        }),
        fetch(`${API_BASE_URL}/health`, {
          headers: { 'x-api-key': 'your-django-api-key-for-authentication' }
        })
      ]);

      if (statusRes.ok) setStatus(await statusRes.json());
      if (healthRes.ok) setHealth(await healthRes.json());
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  if (loading) {
    return (
      <div className="bg-white rounded-sm border border-gray-200 p-4">
        <div className="animate-pulse space-y-3">
          <div className="h-4 bg-gray-200 rounded w-1/4"></div>
          <div className="h-8 bg-gray-200 rounded"></div>
        </div>
      </div>
    );
  }

  return (
    <div className="bg-white rounded-sm border border-gray-200">
      <div className="px-4 py-3 border-b border-gray-200">
        <h3 className="text-sm font-semibold text-gray-900 flex items-center">
          <Server className="w-4 h-4 mr-2 text-green-600" />
          Server Status
        </h3>
      </div>

      <div className="p-4">
        {error ? (
          <div className="flex items-center text-red-600 text-sm">
            <AlertCircle className="w-4 h-4 mr-2" />
            Failed to fetch server status
          </div>
        ) : (
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div className="text-center">
              <div className="text-xs text-gray-500 mb-1">Status</div>
              <div className="flex items-center justify-center">
                <div className={`w-2 h-2 rounded-full mr-2 ${
                  health?.status === 'healthy' ? 'bg-green-500' : 'bg-red-500'
                }`}></div>
                <span className="text-sm font-medium">
                  {health?.status || 'Unknown'}
                </span>
              </div>
            </div>

            <div className="text-center">
              <div className="text-xs text-gray-500 mb-1">Uptime</div>
              <div className="text-sm font-medium">
                {status?.uptime || 'N/A'}
              </div>
            </div>

            <div className="text-center">
              <div className="text-xs text-gray-500 mb-1">Active Clients</div>
              <div className="text-sm font-medium text-green-600">
                {status?.active_clients || '0'}
              </div>
            </div>

            <div className="text-center">
              <div className="text-xs text-gray-500 mb-1">Load</div>
              <div className="text-sm font-medium">
                {status?.server_load || 'N/A'}
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default ServerStatus;