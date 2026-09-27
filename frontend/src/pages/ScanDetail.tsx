import React, { useEffect, useRef, useState } from 'react';
import { useParams } from 'react-router-dom';
import { Download, RefreshCw, Shield, Globe, Lock, AlertTriangle, Server } from 'lucide-react';
import { getScan, getDiscoveries, getAssets, getFindings, downloadReport, Scan, Discovery, Asset, Finding } from '../api';

const SCAN_PHASES = [
  'QUEUED', 'TARGET_VALIDATION', 'THEHARVESTER_RUNNING', 'DISCOVERY_PARSING',
  'SUBDOMAIN_VALIDATION', 'DNS_VALIDATION', 'HTTP_PROBING', 'ACTIVE_ASSETS_IDENTIFIED',
  'TESTSSL_RUNNING', 'HEADER_ANALYSIS', 'RESULT_PROCESSING', 'REPORT_GENERATION',
  'COMPLETED',
];

export default function ScanDetail() {
  const { id } = useParams<{ id: string }>();
  const [scan, setScan] = useState<Scan | null>(null);
  const [discoveries, setDiscoveries] = useState<Discovery[]>([]);
  const [assets, setAssets] = useState<Asset[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [activeTab, setActiveTab] = useState<'console' | 'discoveries' | 'assets' | 'findings' | 'tls'>('console');
  const [events, setEvents] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [downloading, setDownloading] = useState<string | null>(null);
  const consoleRef = useRef<HTMLDivElement>(null);
  const evtRef = useRef<EventSource | null>(null);

  const load = async () => {
    if (!id) return;
    const [s, d, a, f] = await Promise.all([
      getScan(id).catch(() => null),
      getDiscoveries(id).catch(() => []),
      getAssets(id).catch(() => []),
      getFindings(id).catch(() => []),
    ]);
    if (s) setScan(s);
    setDiscoveries(d);
    setAssets(a);
    setFindings(f);
    setLoading(false);
  };

  useEffect(() => {
    load();
    // SSE
    const es = new EventSource(`/api/v1/scans/${id}/events`);
    evtRef.current = es;
    es.onmessage = (e) => {
      try {
        const data = JSON.parse(e.data);
        setEvents(prev => [...prev.slice(-200), data]);
        if (consoleRef.current) consoleRef.current.scrollTop = consoleRef.current.scrollHeight;
        if (['completed', 'failed'].includes(data.event_type)) {
          load();
          es.close();
        } else if (data.event_type === 'phase_change') {
          load();
        }
      } catch {}
    };
    return () => { es.close(); };
  }, [id]);

  useEffect(() => {
    if (consoleRef.current) consoleRef.current.scrollTop = consoleRef.current.scrollHeight;
  }, [events]);

  const handleDownload = async (format: 'pdf' | 'excel' | 'json' | 'xml') => {
    if (!id) return;
    setDownloading(format);
    try {
      const blob = await downloadReport(id, format);
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      const ext = format === 'excel' ? 'xlsx' : format;
      a.download = `vapt_${scan?.target_domain}_${scan?.id?.slice(0, 8)}.${ext}`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (e: any) {
      alert('Failed to generate report: ' + (e?.response?.data?.detail || e.message));
    }
    setDownloading(null);
  };

  if (loading) return (
    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: 400, color: 'var(--text-muted)' }}>
      <div className="spinner" style={{ marginRight: 12 }} /> Loading scan...
    </div>
  );
  if (!scan) return <div className="page-body"><div className="alert alert-error">Scan not found</div></div>;

  const phaseIdx = SCAN_PHASES.indexOf(scan.status);
  const progress = scan.status === 'COMPLETED' ? 100 : scan.status === 'FAILED' ? 0 : Math.round(((phaseIdx + 1) / SCAN_PHASES.length) * 100);
  const isRunning = !['COMPLETED', 'FAILED'].includes(scan.status);
  const activeAssets = assets.filter(a => a.status === 'ACTIVE');
  const httpsAssets = assets.filter(a => a.https_status_code != null);

  return (
    <div className="fade-in">
      {/* Header */}
      <div className="page-header">
        <div>
          <div className="page-title" style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            {isRunning && <span className="dot-live" />}
            {scan.target_domain}
          </div>
          <div className="page-subtitle">
            {scan.mode === 'mock' ? '⚠ MOCK SCAN' : '🔴 REAL SCAN'} • {scan.status.replace(/_/g, ' ')} • ID: {scan.id.substring(0, 12)}...
          </div>
        </div>
        <div style={{ display: 'flex', gap: 8 }}>
          {['COMPLETED'].includes(scan.status) && <>
            <button className="btn btn-ghost btn-sm" onClick={() => handleDownload('pdf')} disabled={downloading === 'pdf'}>
              <Download size={13} /> {downloading === 'pdf' ? 'Generating...' : 'PDF'}
            </button>
            <button className="btn btn-ghost btn-sm" onClick={() => handleDownload('excel')} disabled={downloading === 'excel'}>
              <Download size={13} /> {downloading === 'excel' ? 'Generating...' : 'Excel'}
            </button>
            <button className="btn btn-ghost btn-sm" onClick={() => handleDownload('json')} disabled={downloading === 'json'}>
              <Download size={13} /> {downloading === 'json' ? 'Generating...' : 'JSON'}
            </button>
            <button className="btn btn-ghost btn-sm" onClick={() => handleDownload('xml')} disabled={downloading === 'xml'}>
              <Download size={13} /> {downloading === 'xml' ? 'Generating...' : 'XML'}
            </button>
          </>}
          <button className="btn btn-ghost btn-sm" onClick={load}><RefreshCw size={14} /></button>
        </div>
      </div>


      <div className="page-body">
        {/* KPIs */}
        <div className="kpi-grid" style={{ marginBottom: 20 }}>
          <div className="kpi-card" style={{ '--accent-color': 'var(--accent-blue)' } as any}>
            <div className="kpi-label">Discoveries</div>
            <div className="kpi-value">{scan.stats?.total_discoveries ?? discoveries.length}</div>
            <div className="kpi-sub">Candidate hostnames</div>
          </div>
          <div className="kpi-card" style={{ '--accent-color': 'var(--accent-green)' } as any}>
            <div className="kpi-label">Active Assets</div>
            <div className="kpi-value">{scan.stats?.active_assets ?? activeAssets.length}</div>
            <div className="kpi-sub">HTTP/HTTPS reachable</div>
          </div>
          <div className="kpi-card" style={{ '--accent-color': 'var(--accent-purple)' } as any}>
            <div className="kpi-label">TLS Assessed</div>
            <div className="kpi-value">{scan.stats?.tls_assessed ?? 0}</div>
            <div className="kpi-sub">SSL/TLS certificates</div>
          </div>
          <div className="kpi-card" style={{ '--accent-color': scan.stats?.critical_findings ? 'var(--sev-critical)' : 'var(--accent-yellow)' } as any}>
            <div className="kpi-label">Findings</div>
            <div className="kpi-value">{scan.stats?.total_findings ?? findings.length}</div>
            <div className="kpi-sub">{scan.stats?.critical_findings ?? 0} critical, {scan.stats?.high_findings ?? 0} high</div>
          </div>
        </div>

        {/* Progress */}
        {isRunning && (
          <div className="card" style={{ marginBottom: 16 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 10 }}>
              <div style={{ fontSize: 13, fontWeight: 600 }}>{scan.status.replace(/_/g, ' ')}</div>
              <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>{progress}%</div>
            </div>
            <div className="progress-bar" style={{ height: 6 }}>
              <div className="progress-fill" style={{ width: `${progress}%` }} />
            </div>
          </div>
        )}

        {/* Tabs */}
        <div className="tabs">
          <button className={`tab ${activeTab === 'console' ? 'active' : ''}`} onClick={() => setActiveTab('console')}>
            Live Console {isRunning && <span className="dot-live" />}
          </button>
          <button className={`tab ${activeTab === 'discoveries' ? 'active' : ''}`} onClick={() => setActiveTab('discoveries')}>
            Discoveries ({discoveries.length})
          </button>
          <button className={`tab ${activeTab === 'assets' ? 'active' : ''}`} onClick={() => setActiveTab('assets')}>
            Assets ({assets.length})
          </button>
          <button className={`tab ${activeTab === 'findings' ? 'active' : ''}`} onClick={() => setActiveTab('findings')}>
            Findings ({findings.length})
          </button>
          <button className={`tab ${activeTab === 'tls' ? 'active' : ''}`} onClick={() => setActiveTab('tls')}>
            TLS / Certs ({httpsAssets.length})
          </button>
        </div>

        {/* Tab Content */}
        {activeTab === 'console' && (
          <div className="grid-2">
            <div className="card">
              <div className="card-title" style={{ marginBottom: 12 }}>Live Activity Console</div>
              <div className="console-box" ref={consoleRef}>
                {events.length === 0 && <div style={{ color: 'var(--text-muted)' }}>Waiting for events...</div>}
                {events.map((ev, i) => (
                  <div key={i} className={`console-line event-${ev.event_type}`}>
                    <span className="console-timestamp">[{ev.timestamp && !isNaN(new Date(ev.timestamp).getTime()) ? new Date(ev.timestamp).toLocaleTimeString() : new Date().toLocaleTimeString()}]</span>
                    {ev.phase && <span style={{ color: 'var(--text-muted)', marginRight: 6 }}>[{ev.phase}]</span>}
                    {ev.message}
                  </div>
                ))}
              </div>
            </div>
            <div className="card">
              <div className="card-title" style={{ marginBottom: 12 }}>Scan Phases</div>
              <div className="phase-list">
                {SCAN_PHASES.filter(p => p !== 'ACTIVE_ASSETS_IDENTIFIED').map((phase, i) => {
                  const isDone = phaseIdx > SCAN_PHASES.indexOf(phase) || scan.status === 'COMPLETED';
                  const isActive = scan.status === phase;
                  return (
                    <div key={phase} className="phase-item">
                      <div className={`phase-dot ${isDone ? 'done' : isActive ? 'active' : 'pending'}`}>
                        {isDone ? '✓' : isActive ? '●' : ''}
                      </div>
                      <div className="phase-info">
                        <div className="phase-name" style={{ color: isDone ? 'var(--text-secondary)' : isActive ? 'var(--text-primary)' : 'var(--text-muted)' }}>
                          {phase.replace(/_/g, ' ')}
                        </div>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          </div>
        )}

        {activeTab === 'discoveries' && (
          <div className="card" style={{ padding: 0 }}>
            <div style={{ padding: '14px 20px', borderBottom: '1px solid var(--border)', fontSize: 13, color: 'var(--text-secondary)' }}>
              {discoveries.length} hostnames discovered from {[...new Set(discoveries.map(d => d.source_engine).filter(Boolean))].join(', ') || 'theHarvester'}
            </div>
            <div className="table-container">
              <table className="data-table">
                <thead>
                  <tr><th>#</th><th>Hostname</th><th>Source Engine</th><th>Record Type</th><th>IP Address</th></tr>
                </thead>
                <tbody>
                  {discoveries.map((d, i) => (
                    <tr key={d.id}>
                      <td style={{ color: 'var(--text-muted)' }}>{i + 1}</td>
                      <td className="mono">{d.hostname}</td>
                      <td><span style={{ fontSize: 11, padding: '2px 6px', background: 'rgba(59,130,246,0.1)', color: 'var(--accent-blue)', borderRadius: 10 }}>{d.source_engine || d.source}</span></td>
                      <td style={{ color: 'var(--text-muted)', fontSize: 12 }}>{d.record_type}</td>
                      <td className="mono">{d.ip_address || '—'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {activeTab === 'assets' && (
          <div className="card" style={{ padding: 0 }}>
            <div className="table-container">
              <table className="data-table">
                <thead>
                  <tr>
                    <th>#</th><th>Hostname</th><th>Source</th><th>Status</th>
                    <th>IP</th><th>HTTP</th><th>HTTPS</th><th>Response (ms)</th>
                    <th>HSTS</th><th>CSP</th><th>XFO</th><th>Hdr Score</th><th>TLS</th>
                  </tr>
                </thead>
                <tbody>
                  {assets.map((a, i) => (
                    <tr key={a.id}>
                      <td style={{ color: 'var(--text-muted)' }}>{i + 1}</td>
                      <td className="mono" style={{ maxWidth: 200 }}>{a.hostname}</td>
                      <td style={{ fontSize: 11, color: 'var(--text-muted)' }}>{a.source || '—'}</td>
                      <td><span className={`status-badge status-${a.status}`}>{a.status}</span></td>
                      <td className="mono">{(a.ip_addresses || []).slice(0, 1).join(', ') || '—'}</td>
                      <td><StatusCode code={a.http_status_code} /></td>
                      <td><StatusCode code={a.https_status_code} /></td>
                      <td style={{ color: 'var(--text-secondary)', fontSize: 12 }}>
                        {a.https_response_time_ms ? `${Math.round(a.https_response_time_ms)}` : a.http_response_time_ms ? `${Math.round(a.http_response_time_ms)}` : '—'}
                      </td>
                      <td><Bool v={a.has_hsts} /></td>
                      <td><Bool v={a.has_csp} /></td>
                      <td><Bool v={a.has_xfo} /></td>
                      <td>
                        {a.security_headers_score != null ? (
                          <span style={{ color: a.security_headers_score >= 50 ? 'var(--accent-green)' : 'var(--accent-red)', fontWeight: 600 }}>
                            {a.security_headers_score}/100
                          </span>
                        ) : '—'}
                      </td>
                      <td>
                        {a.tls_assessed
                          ? <span style={{ color: a.tls_grade === 'OK' ? 'var(--accent-green)' : 'var(--accent-yellow)', fontSize: 12, fontWeight: 600 }}>{a.tls_grade || '✓'}</span>
                          : <span style={{ color: 'var(--text-muted)', fontSize: 12 }}>—</span>}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {activeTab === 'findings' && (
          <div>
            {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].map(sev => {
              const sevFindings = findings.filter(f => f.severity === sev);
              if (!sevFindings.length) return null;
              return (
                <div key={sev} style={{ marginBottom: 16 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 10 }}>
                    <span className={`sev-badge sev-${sev}`}>{sev}</span>
                    <span style={{ color: 'var(--text-muted)', fontSize: 13 }}>{sevFindings.length} finding(s)</span>
                  </div>
                  {sevFindings.map(f => (
                    <div key={f.id} className="card" style={{ marginBottom: 8, borderLeft: `3px solid var(--sev-${sev.toLowerCase()}, var(--text-muted))` }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 8 }}>
                        <div style={{ fontWeight: 600, fontSize: 14 }}>{f.title}</div>
                        <div style={{ display: 'flex', gap: 6 }}>
                          {f.cve && <span style={{ fontSize: 11, padding: '2px 6px', background: 'rgba(220,38,38,0.1)', color: 'var(--accent-red)', borderRadius: 6 }}>{f.cve}</span>}
                          {f.cwe && <span style={{ fontSize: 11, padding: '2px 6px', background: 'rgba(245,158,11,0.1)', color: 'var(--accent-yellow)', borderRadius: 6 }}>{f.cwe}</span>}
                        </div>
                      </div>
                      {f.asset_hostname && <div style={{ fontSize: 12, color: 'var(--accent-cyan)', fontFamily: 'monospace', marginBottom: 6 }}>🌐 {f.asset_hostname}</div>}
                      {f.description && <div style={{ fontSize: 13, color: 'var(--text-secondary)', marginBottom: 8 }}>{f.description}</div>}
                      {f.evidence && (
                        <div style={{ fontSize: 12, background: 'var(--bg-primary)', padding: '6px 10px', borderRadius: 6, fontFamily: 'monospace', color: 'var(--text-muted)', marginBottom: 8 }}>
                          Evidence: {f.evidence}
                        </div>
                      )}
                      {f.recommendation && (
                        <div style={{ fontSize: 12, color: 'var(--accent-green)' }}>
                          💡 {f.recommendation}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              );
            })}
            {findings.length === 0 && (
              <div className="empty-state">
                <div className="empty-state-icon">✅</div>
                <div className="empty-state-text">No findings yet. {isRunning ? 'Scan in progress...' : 'No findings detected.'}</div>
              </div>
            )}
          </div>
        )}

        {activeTab === 'tls' && (
          <div>
            {assets.filter(a => a.tls_results?.length || a.cert_results?.length).map(asset => (
              <div key={asset.id} className="card" style={{ marginBottom: 16 }}>
                <div style={{ fontWeight: 700, fontSize: 15, marginBottom: 14, display: 'flex', alignItems: 'center', gap: 8 }}>
                  <Lock size={16} color="var(--accent-blue)" />
                  {asset.hostname}
                </div>

                {/* TLS Protocols */}
                {asset.tls_results?.[0] && (
                  <div style={{ marginBottom: 16 }}>
                    <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-muted)', marginBottom: 8, textTransform: 'uppercase' }}>Protocol Support</div>
                    <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                      {[
                        { label: 'SSL 2', key: 'ssl2_enabled', bad: true },
                        { label: 'SSL 3', key: 'ssl3_enabled', bad: true },
                        { label: 'TLS 1.0', key: 'tls1_0_enabled', bad: true },
                        { label: 'TLS 1.1', key: 'tls1_1_enabled', bad: true },
                        { label: 'TLS 1.2', key: 'tls1_2_enabled', bad: false },
                        { label: 'TLS 1.3', key: 'tls1_3_enabled', bad: false },
                      ].map(({ label, key, bad }) => {
                        const enabled = (asset.tls_results![0] as any)[key];
                        const color = enabled ? (bad ? 'var(--accent-red)' : 'var(--accent-green)') : 'var(--text-muted)';
                        return (
                          <span key={key} style={{ padding: '4px 10px', borderRadius: 20, fontSize: 12, fontWeight: 600, border: `1px solid ${color}`, color, background: `${enabled ? (bad ? 'rgba(220,38,38,0.1)' : 'rgba(16,185,129,0.1)') : 'transparent'}` }}>
                            {label}: {enabled ? '✓' : '✗'}
                          </span>
                        );
                      })}
                    </div>
                  </div>
                )}

                {/* Certificate */}
                {asset.cert_results?.[0] && (() => {
                  const cert = asset.cert_results![0] as any;
                  return (
                    <div style={{ marginBottom: 16 }}>
                      <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-muted)', marginBottom: 8, textTransform: 'uppercase' }}>Certificate</div>
                      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '6px 20px', fontSize: 13 }}>
                        <div><span style={{ color: 'var(--text-muted)' }}>Common Name:</span> {cert.common_name || '—'}</div>
                        <div><span style={{ color: 'var(--text-muted)' }}>Issuer:</span> {cert.issuer || '—'}</div>
                        <div><span style={{ color: 'var(--text-muted)' }}>Valid Until:</span> <span style={{ color: cert.days_remaining < 30 ? 'var(--accent-red)' : cert.days_remaining < 90 ? 'var(--accent-yellow)' : 'var(--accent-green)' }}>{cert.valid_until || '—'}</span></div>
                        <div><span style={{ color: 'var(--text-muted)' }}>Days Remaining:</span> <strong>{cert.days_remaining ?? '—'}</strong></div>
                        <div><span style={{ color: 'var(--text-muted)' }}>Status:</span> <span className={`sev-badge sev-${cert.status === 'VALID' ? 'INFO' : cert.status === 'EXPIRING_SOON' ? 'MEDIUM' : 'CRITICAL'}`}>{cert.status}</span></div>
                        <div><span style={{ color: 'var(--text-muted)' }}>Key Size:</span> {cert.key_size || '—'}</div>
                      </div>
                      {cert.sans?.length > 0 && (
                        <div style={{ marginTop: 8, fontSize: 12, color: 'var(--text-muted)' }}>
                          SANs: {cert.sans.slice(0, 6).join(', ')}{cert.sans.length > 6 ? ` +${cert.sans.length - 6} more` : ''}
                        </div>
                      )}
                    </div>
                  );
                })()}

                {/* Ciphers */}
                {asset.cipher_results && asset.cipher_results.length > 0 && (
                  <div>
                    <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-muted)', marginBottom: 8, textTransform: 'uppercase' }}>
                      Cipher Suites ({asset.cipher_results.length})
                    </div>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                      {(asset.cipher_results as any[]).map((c, i) => (
                        <div key={i} style={{ display: 'flex', gap: 10, alignItems: 'center', fontSize: 12 }}>
                          <span style={{ color: 'var(--text-muted)', width: 60, flexShrink: 0 }}>{c.protocol}</span>
                          <span style={{ fontFamily: 'monospace', flex: 1 }}>{c.cipher}</span>
                          <span className={`sev-badge sev-${c.strength === 'STRONG' ? 'INFO' : c.strength === 'WEAK' ? 'HIGH' : 'CRITICAL'}`} style={{ fontSize: 10 }}>
                            {c.strength}
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            ))}
            {assets.filter(a => a.tls_results?.length || a.cert_results?.length).length === 0 && (
              <div className="empty-state">
                <div className="empty-state-icon">🔒</div>
                <div className="empty-state-text">{isRunning ? 'TLS assessment in progress...' : 'No TLS data available yet.'}</div>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

function StatusCode({ code }: { code?: number | null }) {
  if (!code) return <span style={{ color: 'var(--text-muted)' }}>—</span>;
  const c = code >= 200 && code < 300 ? 'var(--accent-green)' : code >= 300 && code < 400 ? 'var(--accent-cyan)' : code >= 400 ? 'var(--accent-yellow)' : 'var(--text-muted)';
  return <span style={{ color: c, fontWeight: 600, fontSize: 12 }}>{code}</span>;
}

function Bool({ v }: { v?: boolean | null }) {
  if (v == null) return <span style={{ color: 'var(--text-muted)' }}>—</span>;
  return <span style={{ color: v ? 'var(--accent-green)' : 'var(--accent-red)' }}>{v ? '✓' : '✗'}</span>;
}
