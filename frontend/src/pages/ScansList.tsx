import React, { useEffect, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { Search, Trash2, RefreshCw } from 'lucide-react';
import { getScans, deleteScan, Scan } from '../api';

const STATUS_ORDER = ['THEHARVESTER_RUNNING', 'DNS_VALIDATION', 'HTTP_PROBING', 'TESTSSL_RUNNING', 'HEADER_ANALYSIS', 'RESULT_PROCESSING', 'QUEUED', 'COMPLETED', 'FAILED'];

export default function ScansList() {
  const [scans, setScans] = useState<Scan[]>([]);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState('');
  const navigate = useNavigate();

  const load = () => {
    setLoading(true);
    getScans().then(setScans).catch(console.error).finally(() => setLoading(false));
  };

  useEffect(() => {
    load();
    const iv = setInterval(load, 10000);
    return () => clearInterval(iv);
  }, []);

  const filtered = scans.filter(s =>
    s.target_domain.includes(filter.toLowerCase()) ||
    s.status.includes(filter.toUpperCase()) ||
    s.mode.includes(filter.toLowerCase())
  );

  const handleDelete = async (e: React.MouseEvent, id: string) => {
    e.preventDefault();
    e.stopPropagation();
    if (!confirm('Delete this scan and all its data?')) return;
    await deleteScan(id);
    load();
  };

  return (
    <div className="fade-in">
      <div className="page-header">
        <div>
          <div className="page-title">All Scans</div>
          <div className="page-subtitle">{scans.length} total scans</div>
        </div>
        <div style={{ display: 'flex', gap: 8 }}>
          <button className="btn btn-ghost" onClick={load}><RefreshCw size={14} /></button>
          <Link to="/scans/new" className="btn btn-primary"><Search size={14} /> New Scan</Link>
        </div>
      </div>

      <div className="page-body">
        <div style={{ marginBottom: 16 }}>
          <input
            className="form-input"
            placeholder="Filter by domain, status, or mode..."
            value={filter}
            onChange={e => setFilter(e.target.value)}
            style={{ maxWidth: 400 }}
          />
        </div>

        {loading && scans.length === 0 ? (
          <div style={{ textAlign: 'center', padding: '60px 20px', color: 'var(--text-muted)' }}>
            <div className="spinner" style={{ marginBottom: 12 }} />
            <div>Loading scans...</div>
          </div>
        ) : filtered.length === 0 ? (
          <div className="card">
            <div className="empty-state">
              <div className="empty-state-icon">📂</div>
              <div className="empty-state-text">
                {scans.length === 0 ? <>No scans yet. <Link to="/scans/new" style={{ color: 'var(--accent-blue)' }}>Start your first scan →</Link></> : 'No scans match filter'}
              </div>
            </div>
          </div>
        ) : (
          <div className="card" style={{ padding: 0 }}>
            <div className="table-container">
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Target</th>
                    <th>Status</th>
                    <th>Mode</th>
                    <th>Discoveries</th>
                    <th>Active Assets</th>
                    <th>Findings</th>
                    <th>Created</th>
                    <th>Duration</th>
                    <th></th>
                  </tr>
                </thead>
                <tbody>
                  {filtered.map(scan => {
                    const duration = scan.started_at && scan.completed_at
                      ? Math.round((new Date(scan.completed_at).getTime() - new Date(scan.started_at).getTime()) / 1000)
                      : null;
                    return (
                      <tr key={scan.id} style={{ cursor: 'pointer' }} onClick={() => navigate(`/scans/${scan.id}`)}>
                        <td>
                          <div style={{ fontWeight: 600, fontSize: 13 }}>{scan.target_domain}</div>
                          <div style={{ fontSize: 11, color: 'var(--text-muted)', fontFamily: 'monospace' }}>{scan.id.substring(0, 8)}...</div>
                        </td>
                        <td><StatusBadge status={scan.status} /></td>
                        <td>
                          <span style={{ fontSize: 11, fontWeight: 700, color: scan.mode === 'mock' ? 'var(--accent-yellow)' : 'var(--accent-green)', padding: '2px 8px', borderRadius: 10, background: scan.mode === 'mock' ? 'rgba(245,158,11,0.1)' : 'rgba(16,185,129,0.1)' }}>
                            {scan.mode.toUpperCase()}
                          </span>
                        </td>
                        <td style={{ color: 'var(--text-secondary)' }}>{scan.stats?.total_discoveries ?? '—'}</td>
                        <td style={{ color: 'var(--accent-green)' }}>{scan.stats?.active_assets ?? '—'}</td>
                        <td>
                          {scan.stats?.total_findings ? (
                            <span style={{ color: scan.stats.critical_findings > 0 ? 'var(--sev-critical)' : 'var(--text-secondary)', fontWeight: scan.stats.critical_findings > 0 ? 700 : 400 }}>
                              {scan.stats.total_findings}
                              {scan.stats.critical_findings > 0 && ` (${scan.stats.critical_findings} crit)`}
                            </span>
                          ) : '—'}
                        </td>
                        <td style={{ color: 'var(--text-muted)', fontSize: 12 }}>{new Date(scan.created_at).toLocaleString()}</td>
                        <td style={{ color: 'var(--text-muted)', fontSize: 12 }}>{duration ? `${duration}s` : '—'}</td>
                        <td onClick={e => e.stopPropagation()}>
                          <div style={{ display: 'flex', gap: 6 }}>
                            <Link to={`/scans/${scan.id}`} className="btn btn-ghost btn-sm">View</Link>
                            <button className="btn btn-danger btn-sm" onClick={e => handleDelete(e, scan.id)}><Trash2 size={12} /></button>
                          </div>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

function StatusBadge({ status }: { status: string }) {
  const isActive = !['COMPLETED', 'FAILED', 'QUEUED'].includes(status);
  const color = status === 'COMPLETED' ? 'var(--accent-green)' : status === 'FAILED' ? 'var(--accent-red)' : status === 'QUEUED' ? 'var(--text-muted)' : 'var(--accent-blue)';
  return (
    <span style={{ color, fontSize: 11, fontWeight: 600, display: 'flex', alignItems: 'center', gap: 4 }}>
      {isActive && <span className="dot-live" style={{ background: color, width: 6, height: 6 }} />}
      {status.replace(/_/g, ' ')}
    </span>
  );
}
