import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import Layout from './components/Layout';
import VPNDashboard from './components/VPNDashboard';

// Base API URL - configure this for your Flask server
export const API_BASE_URL = 'http://localhost:5001/api/vpn'; // or use proxy

function App() {
  return (
    <Router>
      <Routes>
        <Route path="/" element={<Layout />}>
          <Route index element={<VPNDashboard />} />
          <Route path="vpn" element={<VPNDashboard />} />
        </Route>
      </Routes>
    </Router>
  );
}

export default App;