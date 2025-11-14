import { useState, useEffect } from 'react';
import { Users, Download, Trash2, Wifi, WifiOff } from 'lucide-react';
import { API_BASE_URL } from '../../App';

const ClientsSection = ({ onClientAction }) => {
  const [clients, setClients] = useState([]);
  const [connectedClients, setConnectedClients] = useState([]);
  const [loading, setLoading] = useState(true);
  const [actionLoading, setActionLoading] = useState(null);

  useEffect(() => {
    fetchClients();
  }, []);

  const fetchClients = async () => {
    setLoading(true);
    try {
      const [clientsRes, connectedRes] = await Promise.all([
        fetch(`${API_BASE_URL}/clients`, {
          headers: { 'x-api-key': 'your-django-api-key-for-authentication' }
        }),
        fetch(`${API_BASE_URL}/clients/connected`, {
          headers: { 'x-api-key': 'your-django-api-key-for-authentication' }
        })
      ]);

      if (clientsRes.ok) setClients((await clientsRes.json())?.clients ?? []);
      if (connectedRes.ok) setConnectedClients((await connectedRes.json())?.connected_clients ?? []);
    } catch (err) {
      console.error('Failed to fetch clients:', err);
    } finally {
      setLoading(false);
    }
  };

  const downloadConfig = async (clientName) => {
    setActionLoading(clientName);
    try {
      const response = await fetch(`${API_BASE_URL}/clients/${clientName}/config`, {
        headers: { 'x-api-key': 'your-django-api-key-for-authentication' }
      });

      if (response.ok) {
        const config = await response.text();
        const blob = new Blob([config], { type: 'text/plain' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `${clientName}.ovpn`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
      }
    } catch (err) {
      console.error('Failed to download config:', err);
    } finally {
      setActionLoading(null);
    }
  };

  const revokeClient = async (clientName) => {
    if (!confirm(`Are you sure you want to revoke client "${clientName}"?`)) return;

    setActionLoading(clientName);
    try {
      const response = await fetch(`${API_BASE_URL}/clients/${clientName}/revoke`, {
        method: 'POST',
        headers: { 'x-api-key': 'your-django-api-key-for-authentication' }
      });

      if (response.ok) {
        await fetchClients();
        onClientAction?.();
      }
    } catch (err) {
      console.error('Failed to revoke client:', err);
    } finally {
      setActionLoading(null);
    }
  };

  const isClientConnected = (clientName) => {
    return connectedClients?.some(client => client.name === clientName);
  };

  if (loading) {
    return (
      <div className="bg-white rounded-sm border border-gray-200 p-4">
        <div className="animate-pulse space-y-3">
          <div className="h-4 bg-gray-200 rounded w-1/4"></div>
          <div className="space-y-2">
            {[1, 2, 3].map(i => (
              <div key={i} className="h-12 bg-gray-200 rounded"></div>
            ))}
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="bg-white rounded-sm border border-gray-200">
      <div className="px-4 py-3 border-b border-gray-200">
        <h3 className="text-sm font-semibold text-gray-900 flex items-center">
          <Users className="w-4 h-4 mr-2 text-green-600" />
          VPN Clients ({clients?.length || 0})
        </h3>
      </div>

      <div className="p-4">
        {!clients?.length ? (
          <div className="text-center py-8 text-gray-500">
            <Users className="w-8 h-8 mx-auto mb-2 opacity-50" />
            <p className="text-sm">No VPN clients configured</p>
          </div>
        ) : (
          <div className={"max-h-96 overflow-y-auto" + (clients.length > 5 ? " scrollbar-thin scrollbar-thumb-gray-300 scrollbar-track-gray-100" : "")}>
          <div className="space-y-2">
            {clients.map((client) => {
              const isConnected = isClientConnected(client.name);
              const isLoading = actionLoading === client.name;

              return (
                <div key={client.name} className="flex items-center justify-between p-3 border border-gray-100 rounded-sm hover:bg-gray-50">
                  <div className="flex items-center space-x-3">
                    {isConnected ? (
                      <Wifi className="w-4 h-4 text-green-500" />
                    ) : (
                      <WifiOff className="w-4 h-4 text-gray-400" />
                    )}
                    <div>
                      <div className="text-sm font-medium text-gray-900">
                        {client.name}
                      </div>
                      <div className="text-xs text-gray-500">
                        {isConnected ? 'Connected' : 'Offline'} • Created {client.created_at}
                      </div>
                    </div>
                  </div>

                  <div className="flex items-center space-x-2">
                    <button
                      onClick={() => downloadConfig(client.name)}
                      disabled={isLoading}
                      className="p-1.5 text-gray-600 hover:text-green-600 hover:bg-green-50 rounded-sm transition-colors"
                      title="Download Config"
                    >
                      <Download className="w-4 h-4" />
                    </button>
                    <button
                      onClick={() => revokeClient(client.name)}
                      disabled={isLoading}
                      className="p-1.5 text-gray-600 hover:text-red-600 hover:bg-red-50 rounded-sm transition-colors"
                      title="Revoke Client"
                    >
                      <Trash2 className="w-4 h-4" />
                    </button>
                  </div>
                </div>
              );
            })}
          </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default ClientsSection;