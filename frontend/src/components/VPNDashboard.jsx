import {useState, useEffect} from 'react';
import ServerStatus from './vpn/ServerStatus';
import ClientsSection from './vpn/ClientsSection';
import UsageStats from './vpn/UsageStats';
import ServerLogs from './vpn/ServerLogs';
import ServerConfig from './vpn/ServerConfig';
import CreateClient from './vpn/CreateClient';

const VPNDashboard = () => {
    const [refreshTrigger, setRefreshTrigger] = useState(0);

    const handleRefresh = () => {
        setRefreshTrigger(prev => prev + 1);
    };

    return (
        <div className="space-y-6">
            {/* Header Actions */}
            <div className="flex justify-between items-center">
                <h1 className="text-2xl font-bold text-gray-900">VPN Management</h1>
                <button
                    onClick={handleRefresh}
                    className="px-4 py-2 bg-green-600 text-white rounded-sm hover:bg-green-700 transition-colors text-sm font-medium"
                >
                    Refresh All
                </button>
            </div>

            {/* Server Status & Quick Actions */}
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
                <div className="lg:col-span-2">
                    <ServerStatus key={refreshTrigger}/>
                </div>
                <div>
                    <CreateClient onClientCreated={handleRefresh}/>
                </div>
            </div>

            <div className="grid md:grid-cols-12 gap-1">
                {/* Clients Management */}
                <div id="clients" className={"md:col-span-9"}>
                    <ClientsSection key={refreshTrigger} onClientAction={handleRefresh}/>
                </div>

                {/* Usage Statistics */}
                <div className={"md:col-span-3"} id="usage">
                    <UsageStats key={refreshTrigger}/>
                </div>
            </div>

            {/* Server Logs & Configuration */}
            <div className="grid h-100 grid-cols-1 m gap-2">
                <div className={"md:col-sdpan-8"} id="config">
                    <ServerConfig key={refreshTrigger}/>
                </div>
                <div className={"md:col-spdan-4"} id="logs">
                    <ServerLogs key={refreshTrigger}/>
                </div>

            </div>
        </div>
    );
};

export default VPNDashboard;