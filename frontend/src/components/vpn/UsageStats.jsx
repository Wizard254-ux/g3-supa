import { useState, useEffect } from 'react';
import { BarChart3, Download, Upload, Clock, HardDrive } from 'lucide-react';
import { API_BASE_URL } from '../../App';

const UsageStats = () => {
  const [usage, setUsage] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchUsage();
  }, []);

  const fetchUsage = async () => {
    setLoading(true);
    try {
      const response = await fetch(`${API_BASE_URL}/statistics/usage`, {
        headers: { 'x-api-key': 'your-django-api-key-for-authentication' }
      });

      if (response.ok) {
        setUsage(await response.json());
      }
    } catch (err) {
      console.error('Failed to fetch usage stats:', err);
    } finally {
      setLoading(false);
    }
  };

  const formatBytes = (bytes) => {
    if (!bytes) return '0 B';
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(1024));
    return `${(bytes / Math.pow(1024, i)).toFixed(1)} ${sizes[i]}`;
  };

  if (loading) {
    return (
      <div className="bg-white rounded-sm border border-gray-200 p-4">
        <div className="animate-pulse space-y-3">
          <div className="h-4 bg-gray-200 rounded w-1/4"></div>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            {[1, 2, 3, 4].map(i => (
              <div key={i} className="h-16 bg-gray-200 rounded"></div>
            ))}
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="bg-white h-full  rounded-sm border border-gray-200">
      <div className="px-4 py-3 border-b border-gray-200">
        <h3 className="text-sm font-semibold text-gray-900 flex items-center">
          <BarChart3 className="w-4 h-4 mr-2 text-green-600" />
          Usage Statistics
        </h3>
      </div>

      <div className="p-4 ">
        <div className="grid grid-cols-1 gap-1">
          <div className="text-center p-3 bg-gray-50 rounded-sm">
            <Download className="w-5 h-5 mx-auto mb-2 text-green-600" />
            <div className="text-xs text-gray-500 mb-1">Total Download</div>
            <div className="text-sm font-semibold text-gray-900">
              {formatBytes(usage?.total_download)}
            </div>
          </div>

          <div className="text-center p-3 bg-gray-50 rounded-sm">
            <Upload className="w-5 h-5 mx-auto mb-2 text-blue-600" />
            <div className="text-xs text-gray-500 mb-1">Total Upload</div>
            <div className="text-sm font-semibold text-gray-900">
              {formatBytes(usage?.total_upload)}
            </div>
          </div>

          <div className="text-center p-3 bg-gray-50 rounded-sm">
            <Clock className="w-5 h-5 mx-auto mb-2 text-purple-600" />
            <div className="text-xs text-gray-500 mb-1">Session Time</div>
            <div className="text-sm font-semibold text-gray-900">
              {usage?.total_session_time || 'N/A'}
            </div>
          </div>

          <div className="text-center p-3 bg-gray-50 rounded-sm">
            <HardDrive className="w-5 h-5 mx-auto mb-2 text-orange-600" />
            <div className="text-xs text-gray-500 mb-1">Peak Connections</div>
            <div className="text-sm font-semibold text-gray-900">
              {usage?.peak_connections || '0'}
            </div>
          </div>
        </div>

        {usage?.recent_activity && (
          <div className="mt-6">
            <h4 className="text-xs font-medium text-gray-700 mb-3">Recent Activity</h4>
            <div className="space-y-2">
              {usage.recent_activity.slice(0, 5).map((activity, index) => (
                <div key={index} className="flex justify-between items-center py-2 px-3 bg-gray-50 rounded-sm">
                  <div className="text-xs text-gray-600">
                    {activity.client_name}
                  </div>
                  <div className="text-xs text-gray-500">
                    {formatBytes(activity.bytes_transferred)}
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default UsageStats;