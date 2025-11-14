import { Outlet, NavLink } from 'react-router-dom';
import { Shield, Activity, Users, Server, FileText, Settings } from 'lucide-react';

const Layout = () => {
  const navItems = [
    { path: '/vpn', icon: Shield, label: 'VPN Overview' },
    { path: '/vpn#status', icon: Activity, label: 'Server Status' },
    { path: '/vpn#clients', icon: Users, label: 'Clients' },
    { path: '/vpn#usage', icon: Server, label: 'Usage Stats' },
    { path: '/vpn#logs', icon: FileText, label: 'Server Logs' },
    { path: '/vpn#config', icon: Settings, label: 'Configuration' },
  ];

  return (
    <div className="flex h-screen bg-gray-50">
      {/* Sidebar */}
      <div className="w-64 bg-gray-900 text-white flex flex-col">
        <div className="p-4 border-b border-gray-700">
          <h1 className="text-xl font-bold text-green-400">VPN Manager</h1>
        </div>

        <nav className="flex-1 p-4 space-y-2">
          {navItems.map((item) => (
            <NavLink
              key={item.path}
              to={item.path}
              className={({ isActive }) =>
                `flex items-center space-x-3 px-3 py-2 rounded-sm transition-colors ${
                  isActive
                    ? 'bg-green-600 text-white'
                    : 'text-gray-300 hover:bg-gray-800 hover:text-white'
                }`
              }
            >
              <item.icon size={18} />
              <span className="text-sm">{item.label}</span>
            </NavLink>
          ))}
        </nav>

        <div className="p-4 border-t border-gray-700">
          <div className="flex items-center space-x-2">
            <div className="w-2 h-2 bg-green-400 rounded-full"></div>
            <span className="text-xs text-gray-400">System Online</span>
          </div>
        </div>
      </div>

      {/* Main Content */}
      <div className="flex-1 flex flex-col overflow-hidden">
        <header className="bg-white border-b border-gray-200 px-6 py-4">
          <h2 className="text-lg font-semibold text-gray-900">VPN Dashboard</h2>
        </header>

        <main className="flex-1 overflow-y-auto p-6">
          <Outlet />
        </main>
      </div>
    </div>
  );
};

export default Layout;