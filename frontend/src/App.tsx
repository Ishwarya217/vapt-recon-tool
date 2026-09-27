import React, { useEffect, useState } from 'react';
import { BrowserRouter, Routes, Route, NavLink, useLocation } from 'react-router-dom';
import { Shield, LayoutDashboard, Search, Activity, Cpu, FileText, Settings, ChevronRight } from 'lucide-react';
import { getHealth } from './api';

// Pages
import Dashboard from './pages/Dashboard';
import NewScan from './pages/NewScan';
import ScansList from './pages/ScansList';
import ScanDetail from './pages/ScanDetail';
import SystemHealth from './pages/SystemHealth';

function Sidebar({ scannerMode }: { scannerMode: string }) {
  const loc = useLocation();

  return (
    <aside className="sidebar">
      <div className="sidebar-logo">
        <div className="logo-icon">🛡️</div>
        <div>
          <div className="logo-text">VAPT Platform</div>
          <div className="logo-sub">Recon & TLS Engine</div>
        </div>
      </div>

      <nav className="sidebar-nav">
        <div className="nav-section">
          <div className="nav-section-label">Overview</div>
          <NavLink to="/" end className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}>
            <LayoutDashboard size={16} /> Dashboard
          </NavLink>
        </div>

        <div className="nav-section">
          <div className="nav-section-label">Scanning</div>
          <NavLink to="/scans/new" className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}>
            <Search size={16} /> New Scan
          </NavLink>
          <NavLink to="/scans" end className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}>
            <Activity size={16} /> All Scans
          </NavLink>
        </div>

        <div className="nav-section">
          <div className="nav-section-label">System</div>
          <NavLink to="/health" className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}>
            <Cpu size={16} /> System Health
          </NavLink>
        </div>
      </nav>

      <div className={`scanner-mode-badge ${scannerMode === 'mock' ? 'mode-mock' : 'mode-real'}`}>
        {scannerMode === 'mock' ? '⚠ MOCK SCANNER' : '✓ REAL SCANNER'}
      </div>
    </aside>
  );
}

export default function App() {
  const [scannerMode, setScannerMode] = useState('real');

  useEffect(() => {
    getHealth().then(h => setScannerMode(h.scanner_mode)).catch(() => {});
  }, []);

  return (
    <BrowserRouter>
      <div className="app-shell">
        <Sidebar scannerMode={scannerMode} />
        <main className="main-content">
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/scans/new" element={<NewScan />} />
            <Route path="/scans" element={<ScansList />} />
            <Route path="/scans/:id" element={<ScanDetail />} />
            <Route path="/health" element={<SystemHealth />} />
          </Routes>
        </main>
      </div>
    </BrowserRouter>
  );
}
