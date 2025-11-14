# VPN Dashboard Setup Instructions

## File Structure

Create the following file structure in your Vite React project:

```
src/
├── App.jsx
├── components/
│   ├── Layout.jsx
│   ├── VPNDashboard.jsx
│   └── vpn/
│       ├── ServerStatus.jsx
│       ├── ClientsSection.jsx
│       ├── CreateClient.jsx
│       ├── UsageStats.jsx
│       ├── ServerLogs.jsx
│       └── ServerConfig.jsx
└── utils/
    └── api.js
```

## Required Dependencies

Install the required dependencies:

```bash
npm install react-router-dom lucide-react
```

## Environment Configuration

Create a `.env` file in your project root:

```env
VITE_API_URL=http://localhost:5000
VITE_API_KEY=your-django-api-key-for-authentication
```

## Vite Proxy Configuration (Optional)

To avoid CORS issues, you can configure a proxy in `vite.config.js`:

```javascript
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      '/api': {
        target: 'http://localhost:5000',
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/api/, ''),
      },
    },
  },
})
```

If using proxy, update `API_BASE_URL` in components to `/api`.

## Flask Backend Requirements

Your Flask backend should handle these endpoints:

### Required Headers
All requests include: `x-api-key: your-django-api-key-for-authentication`

### Endpoints to Implement

#### Server Management
- `GET /status` - Server status
- `GET /health` - Health check
- `GET /server/config` - Server configuration
- `GET /server/logs` - Server logs

#### Client Management
- `GET /clients` - List all clients
- `GET /clients/connected` - List connected clients
- `POST /clients/create` - Create new client (body: `{"name": "client_name"}`)
- `GET /clients/{name}/config` - Get client config file
- `POST /clients/{name}/revoke` - Revoke client certificate
- `GET /client/template` - Get client template

#### Statistics
- `GET /statistics/usage` - Usage statistics

## CORS Configuration

Add CORS headers to your Flask app:

```python
from flask_cors import CORS

app = Flask(__name__)
CORS(app, origins=['http://localhost:5173'])  # Vite dev server
```

## Theme Colors

The dashboard uses this color scheme:
- **Primary Green**: `green-600` (#059669)
- **Background**: `gray-50` (#f9fafb)
- **Cards**: `white` with `gray-200` borders
- **Sidebar**: `gray-900` (#111827)
- **Accent**: `green-400` (#4ade80)

## API Response Format Examples

### Server Status Response
```json
{
  "uptime": "2d 14h 32m",
  "active_clients": 5,
  "server_load": "12%"
}
```

### Health Check Response
```json
{
  "status": "healthy"
}
```

### Clients List Response
```json
[
  {
    "name": "client1",
    "created_at": "2025-01-15",
    "status": "active"
  }
]
```

### Usage Stats Response
```json
{
  "total_download": 1073741824,
  "total_upload": 536870912,
  "total_session_time": "24h 30m",
  "peak_connections": 12,
  "recent_activity": [
    {
      "client_name": "client1",
      "bytes_transferred": 1048576
    }
  ]
}
```

## Features Included

✅ **Real-time Dashboard** - Auto-refreshing components  
✅ **Client Management** - Create, view, download configs, revoke  
✅ **Usage Statistics** - Bandwidth and connection stats  
✅ **Live Server Logs** - Real-time log viewing with auto-refresh  
✅ **Server Configuration** - View and export server settings  
✅ **Responsive Design** - Works on desktop and mobile  
✅ **Dark Theme Elements** - Terminal-style log viewer  
✅ **Export Functions** - Download configs and logs  

## Development

1. Copy all component files to their respective locations
2. Update the API_BASE_URL in components if needed
3. Ensure your Flask backend implements the required endpoints
4. Start your Vite dev server: `npm run dev`
5. Start your Flask backend on port 5000

## Security Notes

- Store API keys in environment variables
- Implement proper authentication in your Flask backend
- Use HTTPS in production
- Validate all client inputs on the backend
- Consider rate limiting for API endpoints

## Customization

- Modify colors in Tailwind classes to match your brand
- Adjust the auto-refresh intervals in components
- Add more statistics or configuration options as needed
- Customize the sidebar navigation items