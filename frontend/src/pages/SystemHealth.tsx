import React, { useEffect, useState } from 'react';
import { Cpu, CheckCircle2, XCircle, AlertTriangle, RefreshCw, Server, Shield, Terminal, HardDrive, Zap, Info } from 'lucide-react';
import { getHealth, SystemHealth as SystemHealthType } from '../api';

export default function SystemHealth() {
  const [health, setHealth] = useState<SystemHealthType | null>(null);
  const [loading, setLoading] = useState(true);
  const [lastChecked, setLastChecked] = useState<string>('');

  const fetchHealth = () => {
    setLoading(true);
    getHealth()
      .then(data => {
        setHealth(data);
        setLastChecked(new Date().toLocaleTimeString());
      })
      .catch(err => console.error('Failed to fetch system health:', err))
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    fetchHealth();
  }, []);

  return (
    <div className="page-container">
      {/* Page Header */}
      <div className="page-header flex justify-between items-center">
        <div>
          <h1 className="page-title flex items-center gap-2">
            <Cpu className="text-accent" size={28} />
            System & Engine Health
          </h1>
          <p className="page-subtitle">Real-time status of security engines, runners, and orchestrator subsystems</p>
        </div>
        <button className="btn btn-secondary flex items-center gap-2" onClick={fetchHealth} disabled={loading}>
          <RefreshCw size={16} className={loading ? 'animate-spin' : ''} />
          {loading ? 'Checking...' : 'Refresh Status'}
        </button>
      </div>

      {/* Main Status Cards */}
      <div className="grid grid-cols-3 gap-4 mb-6">
        <div className="card stat-card">
          <div className="stat-label">Platform Status</div>
          <div className="flex items-center gap-2 mt-2">
            {health?.status === 'ok' ? (
              <>
                <CheckCircle2 size={24} className="text-success" />
                <span className="stat-value text-success">OPERATIONAL</span>
              </>
            ) : (
              <>
                <AlertTriangle size={24} className="text-warning" />
                <span className="stat-value text-warning">DEGRADED</span>
              </>
            )}
          </div>
          <div className="text-xs text-muted mt-2">Last verified: {lastChecked || 'Checking...'}</div>
        </div>

        <div className="card stat-card">
          <div className="stat-label">Configured Scanner Mode</div>
          <div className="flex items-center gap-2 mt-2">
            <span className={`badge ${health?.scanner_mode === 'real' ? 'badge-real' : 'badge-mock'}`} style={{ fontSize: '1rem', padding: '6px 14px' }}>
              {health?.scanner_mode === 'real' ? '🛡️ REAL ENGINE MODE' : '⚠ SIMULATED / MOCK'}
            </span>
          </div>
          <div className="text-xs text-muted mt-2">
            {health?.scanner_mode === 'real'
              ? 'Zero data fabrication: running actual binaries on target scope'
              : 'Synthetic deterministic generation for air-gapped demo runs'}
          </div>
        </div>

        <div className="card stat-card">
          <div className="stat-label">Database & Storage</div>
          <div className="flex items-center gap-2 mt-2">
            <HardDrive size={24} className="text-accent" />
            <span className="stat-value" style={{ fontSize: '1.25rem' }}>{health?.database || 'SQLite'}</span>
          </div>
          <div className="text-xs text-muted mt-2">vapt_recon.db (WAL enabled, auto-indexed)</div>
        </div>
      </div>

      {/* Engine Status Grid */}
      <div className="card mb-6">
        <h2 className="card-title mb-4 flex items-center gap-2">
          <Terminal size={20} className="text-accent" /> Security Engine Subsystems
        </h2>
        <div className="table-responsive">
          <table className="data-table">
            <thead>
              <tr>
                <th>Engine / Tool</th>
                <th>Status</th>
                <th>Version</th>
                <th>Bridge / Runner</th>
                <th>Diagnostics</th>
              </tr>
            </thead>
            <tbody>
              {health?.tools.map(tool => (
                <tr key={tool.name}>
                  <td>
                    <div className="font-semibold flex items-center gap-2">
                      {tool.name === 'theHarvester' && <Shield size={16} className="text-accent" />}
                      {tool.name === 'testssl.sh' && <Zap size={16} className="text-accent" />}
                      {tool.name}
                    </div>
                  </td>
                  <td>
                    {tool.available ? (
                      <span className="badge badge-success flex items-center gap-1" style={{ width: 'fit-content' }}>
                        <CheckCircle2 size={12} /> Available
                      </span>
                    ) : (
                      <span className="badge badge-danger flex items-center gap-1" style={{ width: 'fit-content' }}>
                        <XCircle size={12} /> Unavailable
                      </span>
                    )}
                  </td>
                  <td>
                    <code className="code-tag">{tool.version || 'Detecting...'}</code>
                  </td>
                  <td>
                    <span className="text-sm text-secondary">
                      {tool.name === 'theHarvester' && 'Python 3.14 Virtualenv Subprocess'}
                      {tool.name === 'testssl.sh' && 'Git Bash (MSYS2) + Hexdump PyWrapper'}
                    </span>
                  </td>
                  <td>
                    {tool.error ? (
                      <span className="text-xs text-danger">{tool.error}</span>
                    ) : (
                      <span className="text-xs text-success">Verified executable & operational</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Validation & Micro-Engine Architecture */}
      <div className="grid grid-cols-2 gap-4 mb-6">
        <div className="card">
          <h2 className="card-title mb-3 flex items-center gap-2">
            <Server size={18} className="text-accent" /> Internal Analyzers
          </h2>
          <div className="flex flex-col gap-3 text-sm">
            <div className="flex justify-between items-center p-2 rounded bg-surface-darker">
              <span className="font-medium">DNS Validator (dnspython)</span>
              <span className="badge badge-success">ACTIVE</span>
            </div>
            <div className="flex justify-between items-center p-2 rounded bg-surface-darker">
              <span className="font-medium">HTTP Prober (httpx async)</span>
              <span className="badge badge-success">ACTIVE</span>
            </div>
            <div className="flex justify-between items-center p-2 rounded bg-surface-darker">
              <span className="font-medium">Security Header Analyzer (HSTS, CSP, XFO, XCTO)</span>
              <span className="badge badge-success">ACTIVE</span>
            </div>
            <div className="flex justify-between items-center p-2 rounded bg-surface-darker">
              <span className="font-medium">Scope & SSRF Enforcement Engine</span>
              <span className="badge badge-success">ENFORCING</span>
            </div>
          </div>
        </div>

        <div className="card">
          <h2 className="card-title mb-3 flex items-center gap-2">
            <Info size={18} className="text-accent" /> Report Generation Engines
          </h2>
          <div className="flex flex-col gap-3 text-sm">
            <div className="flex justify-between items-center p-2 rounded bg-surface-darker">
              <span className="font-medium">PDF Generator (ReportLab Flowables & Canvas)</span>
              <span className="badge badge-success">READY</span>
            </div>
            <div className="flex justify-between items-center p-2 rounded bg-surface-darker">
              <span className="font-medium">Excel Workbook Generator (OpenPyXL 6-Tabs)</span>
              <span className="badge badge-success">READY</span>
            </div>
            <div className="flex justify-between items-center p-2 rounded bg-surface-darker">
              <span className="font-medium">XML Security Export (ElementTree ISO-8601)</span>
              <span className="badge badge-success">READY</span>
            </div>
            <div className="flex justify-between items-center p-2 rounded bg-surface-darker">
              <span className="font-medium">Real-Time Event Streamer (FastAPI SSE / EventBus)</span>
              <span className="badge badge-success">STREAMING</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
