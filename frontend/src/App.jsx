import { useState, useEffect, useCallback, useRef } from 'react'
import {
  Chart as ChartJS,
  CategoryScale, LinearScale, PointElement, LineElement,
  BarElement, ArcElement, Tooltip, Legend, Filler,
} from 'chart.js'
import { Line, Doughnut, Bar } from 'react-chartjs-2'

ChartJS.register(CategoryScale, LinearScale, PointElement, LineElement, BarElement, ArcElement, Tooltip, Legend, Filler)

const API = 'http://localhost:5001/api'

const fetchJSON = async (url, opts) => {
  try { const r = await fetch(url, opts); return await r.json() } catch { return null }
}

/* ─── Loading Screen ─────────────────────────────────────────────────────────── */
function LoadingScreen({ stage }) {
  const stages = [
    { icon: '📡', label: 'Starting ingest pipeline…', done: stage > 0 },
    { icon: '⚙️', label: 'Loading normalization engine…', done: stage > 1 },
    { icon: '🧠', label: 'Starting detection engine…', done: stage > 2 },
    { icon: '🤖', label: 'Connecting SOAR automation…', done: stage > 3 },
    { icon: '🔗', label: 'Syncing blockchain ledger…', done: stage > 4 },
    { icon: '📊', label: 'Launching dashboard…', done: stage > 5 },
  ]
  return (
    <div className="loading-screen">
      <div className="loading-logo">🛡️</div>
      <div className="loading-title">Watchtower</div>
      <div className="loading-subtitle">Initializing Security Operations Center…</div>
      <div className="loading-stages">
        {stages.map((s, i) => (
          <div key={i} className={`loading-stage ${s.done ? 'done' : i === stage ? 'active' : ''}`}>
            <span className="loading-stage-icon">{s.done ? '✅' : s.icon}</span>
            <span>{s.label}</span>
          </div>
        ))}
      </div>
    </div>
  )
}

/* ─── System Health Panel ────────────────────────────────────────────────────── */
function HealthPanel({ health }) {
  if (!health) return null
  return (
    <div className="panel health-panel">
      <div className="panel-header">
        <span className="panel-title"><span className="panel-title-icon">💓</span> System Health</span>
        <span className="panel-badge green">All Systems Operational</span>
      </div>
      <div className="health-grid">
        {health.components?.map((c, i) => (
          <div key={i} className="health-item">
            <span className={`health-dot ${c.status === 'running' ? 'running' : 'stopped'}`}></span>
            <span className="health-icon">{c.icon}</span>
            <div className="health-info">
              <div className="health-name">{c.name}</div>
              <div className="health-detail">{c.detail} • {c.latency_ms}ms</div>
            </div>
          </div>
        ))}
        <div className="health-item health-meta">
          <span className="health-icon">📊</span>
          <div className="health-info">
            <div className="health-detail">CPU: {health.cpu_percent}% • RAM: {health.memory_usage_mb}MB • {health.logs_per_second} logs/s</div>
          </div>
        </div>
      </div>
    </div>
  )
}

/* ─── Pipeline ───────────────────────────────────────────────────────────────── */
function PipelineBar({ stats }) {
  const nodes = [
    { icon: '📡', label: 'Ingest Queue', sub: `${stats?.total_logs || 0} ingested` },
    { icon: '⚙️', label: 'Normalization', sub: 'Processing' },
    { icon: '🧠', label: 'Detection Engine', sub: stats?.model_version || 'v1.0' },
    { icon: '🚨', label: 'Alerts', sub: `${stats?.total_alerts || 0} detected` },
    { icon: '🤖', label: 'SOAR', sub: `${stats?.soar_actions_count || 0} actions` },
    { icon: '🔗', label: 'Audit Ledger', sub: `${stats?.blockchain_blocks || 0} blocks` },
    { icon: '📊', label: 'Dashboard', sub: 'Live' },
  ]
  return (
    <div className="pipeline">
      {nodes.map((n, i) => (
        <span key={i} style={{ display: 'flex', alignItems: 'center' }}>
          <span className="pipeline-node active">
            <span className="pipeline-node-icon">{n.icon}</span>
            <span>
              <div style={{ fontWeight: 700, fontSize: '0.88rem' }}>{n.label}</div>
              <div style={{ fontSize: '0.72rem', color: 'var(--text-dim)', fontWeight: 400 }}>{n.sub}</div>
            </span>
          </span>
          {i < nodes.length - 1 && <span className="pipeline-arrow">→</span>}
        </span>
      ))}
    </div>
  )
}

/* ─── Stat Card ──────────────────────────────────────────────────────────────── */
function StatCard({ icon, value, label, color }) {
  return (
    <div className={`stat-card ${color}`}>
      <div className="stat-icon">{icon}</div>
      <div className="stat-value">{value?.toLocaleString?.() ?? value}</div>
      <div className="stat-label">{label}</div>
    </div>
  )
}

/* ─── Logs + Alerts Timeline Chart ───────────────────────────────────────────── */
function TimelineChart({ data }) {
  if (!data || !data.length) return <div className="empty-state">Collecting data…</div>
  const chartData = {
    labels: data.map(d => d.time),
    datasets: [
      {
        label: 'Logs',
        data: data.map(d => d.logs),
        fill: true,
        borderColor: '#38bdf8',
        backgroundColor: 'rgba(56,189,248,0.06)',
        pointRadius: 1.5,
        pointHoverRadius: 5,
        tension: 0.4,
        borderWidth: 2,
      },
      {
        label: 'Alerts',
        data: data.map(d => d.alerts),
        fill: true,
        borderColor: '#f87171',
        backgroundColor: 'rgba(248,113,113,0.08)',
        pointRadius: 1.5,
        pointHoverRadius: 5,
        tension: 0.4,
        borderWidth: 2,
      },
    ],
  }
  const opts = {
    responsive: true, maintainAspectRatio: false,
    plugins: {
      legend: { position: 'top', labels: { color: '#94a3b8', font: { size: 11, weight: '600' }, padding: 16, usePointStyle: true, pointStyle: 'dash', pointStyleWidth: 20 } },
      tooltip: { backgroundColor: '#0c1220', borderColor: '#38bdf8', borderWidth: 1, titleColor: '#e2e8f0', bodyColor: '#94a3b8' },
    },
    scales: {
      x: { ticks: { color: '#475569', font: { size: 8, family: "'JetBrains Mono'" }, maxRotation: 45 }, grid: { color: 'rgba(56,189,248,0.04)' } },
      y: { ticks: { color: '#475569', font: { size: 9 } }, grid: { color: 'rgba(56,189,248,0.06)' }, beginAtZero: true },
    },
  }
  return <Line data={chartData} options={opts} />
}

/* ─── Alert Distribution Chart ───────────────────────────────────────────────── */
function AlertDistChart({ data }) {
  if (!data) return <div className="empty-state">No alerts yet…</div>
  const chartData = {
    labels: ['Critical', 'High', 'Medium', 'Low'],
    datasets: [{
      data: [data.critical || 0, data.high || 0, data.medium || 0, data.low || 0],
      backgroundColor: ['rgba(239,68,68,0.8)', 'rgba(248,113,113,0.7)', 'rgba(251,191,36,0.7)', 'rgba(52,211,153,0.7)'],
      borderColor: ['#ef4444', '#f87171', '#fbbf24', '#34d399'],
      borderWidth: 2,
      hoverOffset: 8,
    }],
  }
  const opts = {
    responsive: true, maintainAspectRatio: false,
    plugins: { legend: { position: 'bottom', labels: { color: '#94a3b8', font: { size: 10 }, padding: 14, usePointStyle: true, pointStyleWidth: 8 } } },
    cutout: '65%',
  }
  return <Doughnut data={chartData} options={opts} />
}

/* ─── Event Distribution Bar Chart ───────────────────────────────────────────── */
function EventDistChart({ data }) {
  if (!data || Object.keys(data).length === 0) return <div className="empty-state">No events yet…</div>
  const sorted = Object.entries(data).sort((a, b) => b[1] - a[1]).slice(0, 8)
  const chartData = {
    labels: sorted.map(([k]) => k.replace(/_/g, ' ')),
    datasets: [{
      data: sorted.map(([, v]) => v),
      backgroundColor: [
        'rgba(56,189,248,0.6)', 'rgba(248,113,113,0.6)', 'rgba(251,191,36,0.6)',
        'rgba(52,211,153,0.6)', 'rgba(167,139,250,0.6)', 'rgba(244,114,182,0.6)',
        'rgba(96,165,250,0.6)', 'rgba(74,222,128,0.6)',
      ],
      borderRadius: 4,
      borderSkipped: false,
    }],
  }
  const opts = {
    responsive: true, maintainAspectRatio: false, indexAxis: 'y',
    plugins: { legend: { display: false } },
    scales: {
      x: { ticks: { color: '#475569', font: { size: 9 } }, grid: { color: 'rgba(56,189,248,0.06)' } },
      y: { ticks: { color: '#94a3b8', font: { size: 9, family: "'JetBrains Mono'" } }, grid: { display: false } },
    },
  }
  return <Bar data={chartData} options={opts} />
}

/* ─── Live Logs Table ────────────────────────────────────────────────────────── */
function LogsPanel({ logs, search, setSearch, severity, setSeverity, source, setSource, sources }) {
  return (
    <div className="panel">
      <div className="panel-header">
        <span className="panel-title"><span className="panel-title-icon">📋</span> Live Logs Feed</span>
        <span className="panel-badge cyan">{logs.length} entries</span>
      </div>
      <div className="logs-controls">
        <input className="search-input" placeholder="🔍 Search logs…" value={search} onChange={e => setSearch(e.target.value)} />
        <select className="filter-select" value={severity} onChange={e => setSeverity(e.target.value)}>
          <option value="">All Severities</option>
          <option value="critical">🔴 Critical</option>
          <option value="high">🟠 High</option>
          <option value="medium">🟡 Medium</option>
          <option value="low">🟢 Low</option>
        </select>
        <select className="filter-select" value={source} onChange={e => setSource(e.target.value)}>
          <option value="">All Sources</option>
          {sources.map(s => <option key={s} value={s}>{s}</option>)}
        </select>
      </div>
      <div className="logs-table-wrap">
        <table className="logs-table">
          <thead>
            <tr>
              <th>Time</th>
              <th>Source</th>
              <th>Event</th>
              <th>IP Address</th>
              <th>Location</th>
              <th>User</th>
              <th>Severity</th>
            </tr>
          </thead>
          <tbody>
            {logs.length === 0 ? (
              <tr><td colSpan="7" style={{ textAlign: 'center', color: 'var(--text-dim)' }}>Waiting for logs…</td></tr>
            ) : logs.map((log, i) => (
              <tr key={log.id || i} className={log.severity === 'critical' ? 'critical-severity' : log.severity === 'high' ? 'high-severity' : ''}>
                <td>{log.timestamp ? new Date(log.timestamp).toLocaleTimeString() : '—'}</td>
                <td><span className="source-tag">{log.source}</span></td>
                <td>{log.event?.replace(/_/g, ' ')}</td>
                <td className="mono">{log.ip}</td>
                <td>{log.geo?.flag} {log.geo?.country}</td>
                <td>{log.user}</td>
                <td><span className={`severity ${log.severity}`}><span className="severity-dot"></span>{log.severity}</span></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}

/* ─── Alerts Panel ───────────────────────────────────────────────────────────── */
function AlertsPanel({ alerts }) {
  return (
    <div className="panel">
      <div className="panel-header">
        <span className="panel-title"><span className="panel-title-icon">🚨</span> Threat Alerts</span>
        <span className="panel-badge red">{alerts.length} active</span>
      </div>
      <div className="alerts-list">
        {alerts.length === 0 ? (
          <div className="empty-state">No alerts detected</div>
        ) : alerts.slice(0, 30).map((a, i) => (
          <div className={`alert-card ${a.severity === 'critical' ? 'critical' : ''}`} key={a.id || i}>
            <div className="alert-card-header">
              <span className="alert-event">
                {a.severity === 'critical' && <span className="blink-dot"></span>}
                ⚠ {a.event?.replace(/_/g, ' ')}
              </span>
              <span className="alert-score">
                Score: {a.anomaly_score} <span className="confidence-tag">conf: {a.confidence}</span>
              </span>
            </div>
            <div className="alert-explanation">{a.explanation}</div>
            <div className="alert-meta">
              {a.geo?.flag} {a.ip} • {a.source} • {a.user} • {a.model_version}
            </div>
            {a.features && (
              <div className="alert-features">
                <span className="feature-tag">Failed:{a.features.failed_attempts_count}</span>
                <span className="feature-tag">Rep:{a.features.ip_reputation}</span>
                <span className="feature-tag">Freq:{a.features.request_frequency}</span>
              </div>
            )}
            {a.soar_response && (
              <div className="alert-actions">
                {a.soar_response.actions_taken?.map((act, j) => (
                  <span className="alert-action-tag" key={j}>✓ {act}</span>
                ))}
                <span className="soar-time-tag">⏱ {a.soar_response.execution_time_ms}ms</span>
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  )
}

/* ─── SOAR Panel ─────────────────────────────────────────────────────────────── */
function SOARPanel({ actions }) {
  return (
    <div className="panel">
      <div className="panel-header">
        <span className="panel-title"><span className="panel-title-icon">🤖</span> SOAR Automation</span>
        <span className="panel-badge green">{actions.length} responses</span>
      </div>
      <div className="panel-body">
        <div className="soar-list">
          {actions.length === 0 ? (
            <div className="empty-state">No automated responses yet</div>
          ) : actions.slice(0, 20).map((s, i) => (
            <div className="soar-item" key={s.id || i}>
              <span className="soar-status-icon">✅</span>
              <div className="soar-details">
                <div className="soar-playbook">
                  <span className={`priority-tag ${s.priority}`}>{s.priority}</span>
                  {s.playbook} — {s.event?.replace(/_/g, ' ')}
                </div>
                <div className="soar-actions-list">{s.actions_taken?.join(' → ')}</div>
                <div className="soar-timing">
                  ⏱ {s.execution_time_ms}ms total
                  {s.execution_steps?.map((step, j) => (
                    <span key={j} className="step-timing"> • {step.action}: {step.duration_ms}ms</span>
                  ))}
                </div>
              </div>
              <span style={{ fontSize: '0.65rem', color: 'var(--text-dim)', fontFamily: 'var(--font-mono)' }}>{s.ip}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}

/* ─── Blockchain Panel ───────────────────────────────────────────────────────── */
function BlockchainPanel({ blocks, onValidate, validationResult }) {
  return (
    <div className="panel">
      <div className="panel-header">
        <span className="panel-title"><span className="panel-title-icon">🔗</span> Audit Ledger <span className="model-tag">SHA-256 hash chain</span></span>
        <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
          <button className="btn btn-validate" onClick={onValidate}>🔍 Validate Chain</button>
          <span className="panel-badge cyan">{blocks.length} blocks</span>
        </div>
      </div>
      {validationResult && (
        <div className={`chain-validation ${validationResult.valid ? 'valid' : 'invalid'}`}>
          {validationResult.valid
            ? `✅ Chain integrity verified — ${validationResult.blocks_checked} blocks validated`
            : `❌ Chain integrity FAILED — ${validationResult.errors?.length} errors found`}
        </div>
      )}
      <div className="panel-body">
        <div className="blockchain-chain">
          {blocks.length === 0 ? (
            <div className="empty-state">No blocks yet</div>
          ) : blocks.slice(0, 15).map((b, i) => (
            <div key={b.block_id || i} className="block-card">
              <div className="block-card-header">
                <span className="block-id">Block #{b.block_id}</span>
                <span className="block-nonce">Nonce: {b.nonce}</span>
              </div>
              <div className="block-hash-row">
                <span className="block-label">Hash</span>
                <span className="block-hash" title={b.hash}>{b.hash?.slice(0, 24)}…</span>
              </div>
              <div className="block-hash-row">
                <span className="block-label">Prev</span>
                <span className="block-hash prev" title={b.prev_hash}>{b.prev_hash?.slice(0, 24)}…</span>
              </div>
              <div className="block-time">{b.timestamp ? new Date(b.timestamp).toLocaleTimeString() : ''}</div>
              {i < blocks.slice(0, 15).length - 1 && <div className="chain-arrow">⬇</div>}
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}

/* ─── Main App ───────────────────────────────────────────────────────────────── */
export default function App() {
  const [loading, setLoading] = useState(true)
  const [loadingStage, setLoadingStage] = useState(0)
  const [stats, setStats] = useState(null)
  const [logs, setLogs] = useState([])
  const [alerts, setAlerts] = useState([])
  const [soarActions, setSoarActions] = useState([])
  const [blockchain, setBlockchain] = useState([])
  const [health, setHealth] = useState(null)
  const [search, setSearch] = useState('')
  const [severity, setSeverity] = useState('')
  const [source, setSource] = useState('')
  const [toast, setToast] = useState(null)
  const [validationResult, setValidationResult] = useState(null)
  const [attackMenuOpen, setAttackMenuOpen] = useState(false)
  const toastTimeout = useRef(null)

  const showToast = useCallback((message, type = 'success') => {
    setToast({ message, type })
    if (toastTimeout.current) clearTimeout(toastTimeout.current)
    toastTimeout.current = setTimeout(() => setToast(null), 4000)
  }, [])

  // Loading animation
  useEffect(() => {
    if (!loading) return
    const stages = [0, 1, 2, 3, 4, 5, 6]
    let i = 0
    const interval = setInterval(() => {
      i++
      if (i < stages.length) {
        setLoadingStage(i)
      } else {
        setLoading(false)
        clearInterval(interval)
      }
    }, 400)
    return () => clearInterval(interval)
  }, [loading])

  // Fetch all data
  const fetchAll = useCallback(async () => {
    const params = new URLSearchParams()
    if (severity) params.set('severity', severity)
    if (source) params.set('source', source)
    if (search) params.set('search', search)
    params.set('limit', '80')

    const [s, l, a, sa, bc, h] = await Promise.all([
      fetchJSON(`${API}/stats`),
      fetchJSON(`${API}/logs?${params}`),
      fetchJSON(`${API}/alerts?limit=40`),
      fetchJSON(`${API}/soar-actions?limit=25`),
      fetchJSON(`${API}/blockchain?limit=20`),
      fetchJSON(`${API}/system-health`),
    ])
    if (s) setStats(s)
    if (l) setLogs(l)
    if (a) setAlerts(a)
    if (sa) setSoarActions(sa)
    if (bc) setBlockchain(bc)
    if (h) setHealth(h)
  }, [search, severity, source])

  useEffect(() => {
    fetchAll()
    const interval = setInterval(fetchAll, 2000)
    return () => clearInterval(interval)
  }, [fetchAll])

  const simulateAttack = async (type) => {
    setAttackMenuOpen(false)
    const res = await fetchJSON(`${API}/simulate-attack`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ attack_type: type }),
    })
    if (res) showToast(`🚨 ${res.message}`, 'danger')
    fetchAll()
  }

  const retrainModel = async () => {
    const res = await fetchJSON(`${API}/retrain`, { method: 'POST' })
    if (res) showToast(`🧠 ${res.message} — ${res.new_version} (${res.improvement} improvement)`, 'info')
    fetchAll()
  }

  const validateChain = async () => {
    const res = await fetchJSON(`${API}/blockchain/validate`, { method: 'POST' })
    if (res) {
      setValidationResult(res)
      showToast(res.valid ? `✅ Chain valid — ${res.blocks_checked} blocks verified` : '❌ Chain integrity compromised!', res.valid ? 'success' : 'danger')
    }
  }

  const resetAll = async () => {
    if (!confirm('⚠️ Clear ALL logs, alerts, blockchain blocks, and SOAR actions? This cannot be undone.')) return
    const res = await fetchJSON(`${API}/reset`, { method: 'POST' })
    if (res) {
      setValidationResult(null)
      showToast('🗑️ All data cleared — system reset to zero', 'success')
    }
    fetchAll()
  }

  if (loading) return <LoadingScreen stage={loadingStage} />

  return (
    <div className="app">
      {/* Header */}
      <header className="header">
        <div className="header-brand">
          <div className="header-logo">🛡️</div>
          <div>
            <div className="header-title">Watchtower</div>
            <div className="header-subtitle">Security Operations Center</div>
          </div>
        </div>
        <div className="header-controls">
          <span className="model-tag">{stats?.model_version || 'rules-v1.0'}</span>
          <span className="header-status"><span className="status-dot"></span>LIVE</span>
          <div className="attack-dropdown">
            <button className="btn btn-attack" onClick={() => setAttackMenuOpen(!attackMenuOpen)}>⚡ Simulate Attack ▾</button>
            {attackMenuOpen && (
              <div className="attack-menu">
                <button onClick={() => simulateAttack('brute_force')}>🔐 Brute Force</button>
                <button onClick={() => simulateAttack('ddos')}>🌊 DDoS Attack</button>
                <button onClick={() => simulateAttack('insider_threat')}>🕵️ Insider Threat</button>
                <button onClick={() => simulateAttack('malware_outbreak')}>🦠 Malware Outbreak</button>
                <button onClick={() => simulateAttack('mixed')}>💥 Multi-Vector</button>
              </div>
            )}
          </div>
          <button className="btn btn-retrain" onClick={retrainModel}>🧠 Retrain Model</button>
          <button className="btn btn-reset" onClick={resetAll}>🗑️ Reset All</button>
        </div>
      </header>

      {/* Pipeline */}
      <PipelineBar stats={stats} />

      {/* System Health */}
      <HealthPanel health={health} />

      {/* Stats Cards */}
      <div className="stats-grid">
        <StatCard icon="📊" value={stats?.total_logs || 0} label="Total Logs Ingested" color="cyan" />
        <StatCard icon="🚨" value={stats?.total_alerts || 0} label="Alerts Detected" color="red" />
        <StatCard icon="‼️" value={stats?.critical_alerts || 0} label="Critical Alerts" color="critical" />
        <StatCard icon="🔴" value={stats?.high_severity_alerts || 0} label="High Severity" color="amber" />
        <StatCard icon="🤖" value={stats?.soar_actions_count || 0} label="SOAR Actions" color="green" />
        <StatCard icon="🔗" value={stats?.blockchain_blocks || 0} label="Blockchain Blocks" color="purple" />
      </div>

      {/* Charts Row 1: Timeline + Alert Distribution */}
      <div className="grid-2 section-row">
        <div className="panel">
          <div className="panel-header">
            <span className="panel-title"><span className="panel-title-icon">📈</span> Logs & Alerts Timeline</span>
          </div>
          <div className="panel-body"><div className="chart-container"><TimelineChart data={stats?.logs_over_time} /></div></div>
        </div>
        <div className="panel">
          <div className="panel-header">
            <span className="panel-title"><span className="panel-title-icon">🎯</span> Alert Severity Distribution</span>
          </div>
          <div className="panel-body"><div className="chart-container"><AlertDistChart data={stats?.alert_distribution} /></div></div>
        </div>
      </div>

      {/* Charts Row 2: Event Distribution */}
      <div className="section-row">
        <div className="panel">
          <div className="panel-header">
            <span className="panel-title"><span className="panel-title-icon">📊</span> Event Type Distribution</span>
          </div>
          <div className="panel-body"><div className="chart-container"><EventDistChart data={stats?.event_distribution} /></div></div>
        </div>
      </div>

      {/* Logs + Alerts */}
      <div className="grid-3 section-row">
        <LogsPanel logs={logs} search={search} setSearch={setSearch} severity={severity} setSeverity={setSeverity} source={source} setSource={setSource} sources={stats?.sources || []} />
        <AlertsPanel alerts={alerts} />
      </div>

      {/* SOAR + Blockchain */}
      <div className="grid-2 section-row">
        <SOARPanel actions={soarActions} />
        <BlockchainPanel blocks={blockchain} onValidate={validateChain} validationResult={validationResult} />
      </div>

      {/* Footer */}
      <footer className="footer">
        <div className="footer-content">
          <span className="footer-shield">🛡️</span>
          <span>Built by <span className="footer-name">Shlok Dahale</span></span>
          <span className="footer-divider">•</span>
          <span className="footer-tag">Watchtower — MIT licensed</span>
        </div>
      </footer>

      {/* Toast */}
      {toast && <div className={`toast ${toast.type}`}>{toast.message}</div>}
    </div>
  )
}
