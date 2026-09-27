import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Search, AlertTriangle, Info } from 'lucide-react';
import { createScan } from '../api';

const DEFAULT_SOURCES = ['hackertarget', 'rapiddns', 'crtsh', 'certspotter', 'otx'];
const ALL_SOURCES = ['hackertarget', 'rapiddns', 'crtsh', 'certspotter', 'otx', 'urlscan', 'duckduckgo', 'baidu', 'virustotal', 'yahoo'];

export default function NewScan() {
  const navigate = useNavigate();
  const [domain, setDomain] = useState('');
  const [mode, setMode] = useState<'real' | 'mock'>('real');
  const [sources, setSources] = useState<string[]>([...DEFAULT_SOURCES]);
  const [scope, setScope] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState('');

  const toggleSource = (s: string) => {
    setSources(prev => prev.includes(s) ? prev.filter(x => x !== s) : [...prev, s]);
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!domain.trim()) { setError('Target domain is required'); return; }
    const domainClean = domain.trim().toLowerCase().replace(/^https?:\/\//, '').split('/')[0];
    setSubmitting(true);
    setError('');
    try {
      const scan = await createScan({ target_domain: domainClean, mode, sources, scope: scope || undefined });
      navigate(`/scans/${scan.id}`);
    } catch (e: any) {
      setError(e?.response?.data?.detail || 'Failed to create scan. Is the backend running?');
      setSubmitting(false);
    }
  };

  return (
    <div className="fade-in">
      <div className="page-header">
        <div>
          <div className="page-title">New Scan</div>
          <div className="page-subtitle">Configure and launch a reconnaissance scan</div>
        </div>
      </div>

      <div className="page-body" style={{ maxWidth: 760 }}>
        {error && <div className="alert alert-error"><AlertTriangle size={14} style={{ marginRight: 6 }} />{error}</div>}

        <form onSubmit={handleSubmit}>
          {/* Target */}
          <div className="card" style={{ marginBottom: 16 }}>
            <div className="card-title" style={{ marginBottom: 16 }}>Target Configuration</div>

            <div className="form-group">
              <label className="form-label">Target Domain *</label>
              <input
                className="form-input"
                placeholder="e.g. example.com or owasp.org"
                value={domain}
                onChange={e => setDomain(e.target.value)}
                required
              />
              <div className="form-hint">Enter the root domain only (no https:// or paths). Only authorized targets.</div>
            </div>

            <div className="form-group">
              <label className="form-label">Scope (optional)</label>
              <input
                className="form-input"
                placeholder="e.g. *.example.com"
                value={scope}
                onChange={e => setScope(e.target.value)}
              />
              <div className="form-hint">Limit discovery to this scope pattern. Leave blank to use target domain.</div>
            </div>
          </div>

          {/* Scanner Mode */}
          <div className="card" style={{ marginBottom: 16 }}>
            <div className="card-title" style={{ marginBottom: 16 }}>Scanner Mode</div>
            <div className="toggle-group" style={{ display: 'inline-flex' }}>
              <button type="button" className={`toggle-btn ${mode === 'real' ? 'active' : ''}`} onClick={() => setMode('real')}>
                🔴 Real Scanner
              </button>
              <button type="button" className={`toggle-btn ${mode === 'mock' ? 'active' : ''}`} onClick={() => setMode('mock')}>
                🟡 Mock Scanner
              </button>
            </div>
            <div className="form-hint" style={{ marginTop: 10 }}>
              {mode === 'real'
                ? '⚠ Real mode executes theHarvester + testssl.sh against the target. Only use on authorized domains.'
                : '✓ Mock mode generates synthetic data for UI testing. No actual network probes are performed.'}
            </div>
          </div>

          {/* Discovery Sources */}
          <div className="card" style={{ marginBottom: 24 }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 14 }}>
              <div className="card-title">Discovery Sources</div>
              <div style={{ display: 'flex', gap: 8 }}>
                <button type="button" className="btn btn-ghost btn-sm" onClick={() => setSources([...ALL_SOURCES])}>Select All</button>
                <button type="button" className="btn btn-ghost btn-sm" onClick={() => setSources([])}>Clear</button>
              </div>
            </div>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
              {ALL_SOURCES.map(s => (
                <button
                  key={s}
                  type="button"
                  onClick={() => toggleSource(s)}
                  style={{
                    padding: '5px 12px',
                    borderRadius: 20,
                    fontSize: 12,
                    fontWeight: 500,
                    cursor: 'pointer',
                    border: `1px solid ${sources.includes(s) ? 'var(--accent-blue)' : 'var(--border)'}`,
                    background: sources.includes(s) ? 'rgba(59,130,246,0.15)' : 'transparent',
                    color: sources.includes(s) ? 'var(--accent-blue)' : 'var(--text-secondary)',
                    transition: 'all 0.15s',
                  }}
                >
                  {sources.includes(s) ? '✓ ' : ''}{s}
                </button>
              ))}
            </div>
            <div className="form-hint" style={{ marginTop: 10 }}>
              <Info size={12} style={{ marginRight: 4 }} />
              Selected: {sources.length} source(s). API keys (Shodan, Censys) can be configured in .env
            </div>
          </div>

          <button type="submit" className="btn btn-primary btn-lg" disabled={submitting || !domain}>
            {submitting ? <><span className="spinner" /> Starting Scan...</> : <><Search size={16} /> Launch Scan</>}
          </button>
        </form>
      </div>
    </div>
  );
}
