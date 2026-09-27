import React, { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { Shield, Activity, AlertTriangle, CheckCircle, TrendingUp, Search } from 'lucide-react';
import { getDashboard, getScans, DashboardStats, Scan } from '../api';
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, PieChart, Pie, Cell, Legend } from 'recharts';

const SEVERITY_COLORS: Record<string, string> = {
  Critical: '#dc2626',
  High: '#ea580c',
  Medium: '#ca8a04',
  Low: '#2563eb',
};

export default function Dashboard() {
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [scans, setScans] = useState<Scan[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    Promise.all([getDashboard(), getScans()])
      .then(([s, sc]) => { setStats(s); setScans(sc.slice(0, 5)); })
      .catch(console.error)
      .finally(() => setLoading(false));
  }, []);

  const severityData = stats ? [
    { name: 'Critical', value: stats.critical_findings, fill: '#dc2626' },
    { name: 'High', value: stats.high_findings, fill: '#ea580c' },
    { name: 'Medium', value: stats.medium_findings, fill: '#ca8a04' },
    { name: 'Low', value: stats.low_findings, fill: '#2563eb' },
  ].filter(d => d.value > 0) : [];

  const scanStatusData = scans.length > 0 ? [
    { name: 'Completed', value: scans.filter(s => s.status === 'COMPLETED').length },
    { name: 'Running', value: scans.filter(s => ['THEHARVESTER_RUNNING','TESTSSL_RUNNING','DNS_VALIDATION','HTTP_PROBING'].includes(s.status)).length },
    { name: 'Queued', value: scans.filter(s => s.status === 'QUEUED').length },
    { name: 'Failed', value: scans.filter(s => s.status === 'FAILED').length },
  ] : [];

  if (loading) return (
    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100%', color: 'var(--text-muted)' }}>
      <div className="spinner" style={{ marginRight: 12 }} /> Loading dashboard...
    </div>
  );

  return (
    <div className="fade-in">
      <div className="page-header">
        <div>
          <div className="page-title">Dashboard</div>
          <div className="page-subtitle">Security reconnaissance overview</div>
        </div>
        <Link to="/scans/new" className="btn btn-primary">
          <Search size={14} /> New Scan
        </Link>
      </div>

      <div className="page-body">
        {/* KPI Cards */}
        <div className="kpi-grid">
          <div className="kpi-card" style={{ '--accent-color': 'var(--accent-blue)' } as any}>
            <div className="kpi-label">Total Scans</div>
            <div className="kpi-value">{stats?.total_scans ?? 0}</div>
            <div className="kpi-sub">{stats?.completed_scans ?? 0} completed</div>
            <div className="kpi-icon"><Activity size={32} /></div>
          </div>
          <div className="kpi-card" style={{ '--accent-color': 'var(--accent-green)' } as any}>
            <div className="kpi-label">Active Assets</div>
            <div className="kpi-value">{stats?.active_assets ?? 0}</div>
            <div className="kpi-sub">HTTPS reachable hosts</div>
            <div className="kpi-icon"><CheckCircle size={32} /></div>
          </div>
          <div className="kpi-card" style={{ '--accent-color': 'var(--sev-critical)' } as any}>
            <div className="kpi-label">Total Findings</div>
            <div className="kpi-value">{stats?.total_findings ?? 0}</div>
            <div className="kpi-sub">{stats?.critical_findings ?? 0} critical</div>
            <div className="kpi-icon"><AlertTriangle size={32} /></div>
          </div>
          <div className="kpi-card" style={{ '--accent-color': 'var(--accent-purple)' } as any}>
            <div className="kpi-label">Scanner Mode</div>
            <div className="kpi-value" style={{ fontSize: 20, paddingTop: 8 }}>{stats?.scanner_mode?.toUpperCase() ?? '—'}</div>
            <div className="kpi-sub">Active engine mode</div>
            <div className="kpi-icon"><Shield size={32} /></div>
          </div>
        </div>

        {/* Charts Row */}
        <div className="grid-2" style={{ marginBottom: 24 }}>
          <div className="card">
            <div className="card-header">
              <div className="card-title">Findings by Severity</div>
            </div>
            {severityData.length > 0 ? (
              <div className="chart-wrap">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={severityData} barCategoryGap="30%">
                    <XAxis dataKey="name" tick={{ fill: '#94a3b8', fontSize: 12 }} axisLine={false} tickLine={false} />
                    <YAxis tick={{ fill: '#94a3b8', fontSize: 11 }} axisLine={false} tickLine={false} />
                    <Tooltip contentStyle={{ background: '#1e293b', border: '1px solid #334155', borderRadius: 8, fontSize: 12 }} />
                    <Bar dataKey="value" radius={[4, 4, 0, 0]}>
                      {severityData.map((d, i) => <Cell key={i} fill={d.fill} />)}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              </div>
            ) : (
              <div className="empty-state" style={{ padding: 40 }}>
                <div style={{ fontSize: 32, marginBottom: 8 }}>📊</div>
                <div className="empty-state-text">No findings data yet</div>
              </div>
            )}
          </div>

          <div className="card">
            <div className="card-header">
              <div className="card-title">Severity Distribution</div>
            </div>
            {severityData.length > 0 ? (
              <div className="chart-wrap">
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie data={severityData} cx="50%" cy="50%" innerRadius={55} outerRadius={85} dataKey="value" paddingAngle={3}>
                      {severityData.map((d, i) => <Cell key={i} fill={d.fill} />)}
                    </Pie>
                    <Tooltip contentStyle={{ background: '#1e293b', border: '1px solid #334155', borderRadius: 8, fontSize: 12 }} />
                    <Legend formatter={(v) => <span style={{ color: '#94a3b8', fontSize: 12 }}>{v}</span>} />
                  </PieChart>
                </ResponsiveContainer>
              </div>
            ) : (
              <div className="empty-state" style={{ padding: 40 }}>
                <div style={{ fontSize: 32, marginBottom: 8 }}>🥧</div>
                <div className="empty-state-text">No findings data yet</div>
              </div>
            )}
          </div>
        </div>

        {/* Recent Scans */}
        <div className="card">
          <div className="card-header">
            <div className="card-title">Recent Scans</div>
            <Link to="/scans" className="btn btn-ghost btn-sm">View All</Link>
          </div>
          {scans.length > 0 ? (
            <div className="table-container">
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Target</th>
                    <th>Status</th>
                    <th>Mode</th>
                    <th>Started</th>
                    <th>Assets</th>
                    <th></th>
                  </tr>
                </thead>
                <tbody>
                  {scans.map(scan => (
                    <tr key={scan.id}>
                      <td><span className="mono">{scan.target_domain}</span></td>
                      <td><ScanStatusBadge status={scan.status} /></td>
                      <td><span style={{ fontSize: 11, color: scan.mode === 'mock' ? 'var(--accent-yellow)' : 'var(--accent-green)', fontWeight: 600 }}>{scan.mode.toUpperCase()}</span></td>
                      <td style={{ color: 'var(--text-muted)', fontSize: 12 }}>{scan.started_at ? new Date(scan.started_at).toLocaleString() : '—'}</td>
                      <td style={{ color: 'var(--text-secondary)' }}>{scan.stats?.active_assets ?? '—'}</td>
                      <td><Link to={`/scans/${scan.id}`} className="btn btn-ghost btn-sm">View →</Link></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="empty-state">
              <div className="empty-state-icon">🔍</div>
              <div className="empty-state-text">No scans yet. <Link to="/scans/new" style={{ color: 'var(--accent-blue)' }}>Start your first scan</Link></div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function ScanStatusBadge({ status }: { status: string }) {
  const colors: Record<string, string> = {
    COMPLETED: 'var(--accent-green)',
    FAILED: 'var(--accent-red)',
    QUEUED: 'var(--text-muted)',
    THEHARVESTER_RUNNING: 'var(--accent-blue)',
    TESTSSL_RUNNING: 'var(--accent-purple)',
    DNS_VALIDATION: 'var(--accent-cyan)',
    HTTP_PROBING: 'var(--accent-cyan)',
  };
  const c = colors[status] || 'var(--text-secondary)';
  const isRunning = !['COMPLETED', 'FAILED', 'QUEUED'].includes(status);
  return (
    <span style={{ color: c, fontSize: 12, fontWeight: 600, display: 'flex', alignItems: 'center', gap: 4 }}>
      {isRunning && <span className="dot-live" style={{ background: c }} />}
      {status.replace(/_/g, ' ')}
    </span>
  );
}
