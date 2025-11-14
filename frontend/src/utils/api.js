// API Configuration
export const API_BASE_URL = 'http://localhost:5001/api/vpn';
export const API_KEY = import.meta.env.VITE_API_KEY || 'your-django-api-key-for-authentication';

// API Headers
export const getApiHeaders = () => ({
  'Content-Type': 'application/json',
  'x-api-key': API_KEY,
});

// API Endpoints
export const endpoints = {
  // Server endpoints
  status: '/status',
  health: '/health',
  serverConfig: '/server/config',
  serverLogs: '/server/logs',

  // Client endpoints
  clients: '/clients',
  connectedClients: '/clients/connected',
  createClient: '/clients/create',
  clientConfig: (name) => `/clients/${name}/config`,
  revokeClient: (name) => `/clients/${name}/revoke`,
  clientTemplate: '/client/template',

  // Statistics
  usage: '/statistics/usage',
};

// Generic API call function
export const apiCall = async (endpoint, options = {}) => {
  const url = `${API_BASE_URL}${endpoint}`;
  const config = {
    headers: getApiHeaders(),
    ...options,
  };

  try {
    const response = await fetch(url, config);

    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }

    const contentType = response.headers.get('content-type');
    if (contentType && contentType.includes('application/json')) {
      return await response.json();
    } else {
      return await response.text();
    }
  } catch (error) {
    console.error(`API call failed for ${endpoint}:`, error);
    throw error;
  }
};

// Specific API functions
export const vpnApi = {
  // Server status and health
  getStatus: () => apiCall(endpoints.status),
  getHealth: () => apiCall(endpoints.health),
  getServerConfig: () => apiCall(endpoints.serverConfig),
  getServerLogs: () => apiCall(endpoints.serverLogs),

  // Client management
  getClients: () => apiCall(endpoints.clients),
  getConnectedClients: () => apiCall(endpoints.connectedClients),
  createClient: (name) => apiCall(endpoints.createClient, {
    method: 'POST',
    body: JSON.stringify({ name }),
  }),
  getClientConfig: (name) => apiCall(endpoints.clientConfig(name)),
  revokeClient: (name) => apiCall(endpoints.revokeClient(name), {
    method: 'POST',
  }),
  getClientTemplate: () => apiCall(endpoints.clientTemplate),

  // Statistics
  getUsageStats: () => apiCall(endpoints.usage),
};