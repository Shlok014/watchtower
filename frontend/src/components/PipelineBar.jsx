/* Node state comes from /api/v1/system-health, which derives each component's
   status from measured state. Every node used to be hardcoded
   className="pipeline-node active", so the diagram showed a healthy pipeline
   with the generator thread dead and nothing being processed. */
export function PipelineBar({ stats, health }) {
  const byName = Object.fromEntries((health?.components || []).map(c => [c.name, c]))
  const stateOf = (name) => byName[name]?.status || 'unknown'
  const nodes = [
    { icon: '📡', label: 'Ingest', sub: `${stats?.total_logs ?? 0} ingested`, state: stateOf('Ingest Queue') },
    { icon: '⚙️', label: 'Normalize', sub: `${stats?.logs_retained ?? 0} retained`, state: stateOf('Normalization') },
    // Ledger before detection: that is the order the pipeline runs in. Events
    // are chained as they arrive, before anything decides what they mean.
    { icon: '🔗', label: 'Audit Ledger', sub: `${stats?.total_blocks ?? 0} blocks`, state: stateOf('Audit Ledger') },
    { icon: '🧠', label: 'Detection', sub: stats?.ruleset_version || '—', state: stateOf('Detection Engine') },
    { icon: '🚨', label: 'Alerts', sub: `${stats?.total_alerts ?? 0} raised`, state: stateOf('Alert System') },
    { icon: '🤖', label: 'SOAR', sub: `${stats?.events_dropped_lifetime ?? 0} dropped`, state: stateOf('SOAR Engine') },
  ]
  return (
    <div className="pipeline">
      {nodes.map((n, i) => (
        <span key={i} style={{ display: 'flex', alignItems: 'center' }}>
          <span className={`pipeline-node ${n.state}`} title={`status: ${n.state}`}>
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
