import { HeartPulse } from 'lucide-react'
import { Panel, EmptyState } from './Panel'

function sourceState(source) {
  if (source.alive) return '✓ live'
  if (source.completed) return '✓ complete'
  return '✕ stopped'
}

export function HealthPanel({ health, dimmed }) {
  const summary = health?.summary
  const badgeColor = summary?.state === 'ok' ? 'green' : ['degraded', 'idle'].includes(summary?.state) ? 'amber' : 'red'
  return (
    <Panel
      icon={HeartPulse}
      title="System Health"
      dimmed={dimmed}
      badge={summary?.label || 'Unknown'}
      badgeColor={badgeColor}
    >
      {!health ? (
        <EmptyState>No health data received yet</EmptyState>
      ) : (
        <div className="health-grid">
          {health.components?.map((c, i) => (
            <div key={i} className="health-item">
              <span className={`health-dot ${c.status}`}></span>
              <span className="health-icon">{c.icon}</span>
              <div className="health-info">
                <div className="health-name">{c.name}</div>
                <div className="health-detail">
                  {c.detail}
                  {/* Percentiles are suppressed by the backend below 20 samples
                      rather than dressed up, so a missing p95 is expected and
                      the UI must not print "undefined". */}
                  {c.p50_ms != null && <> • p50 {c.p50_ms}ms{c.p95_ms != null && ` / p95 ${c.p95_ms}ms`}</>}
                  {c.samples === 0 && <> • no samples yet</>}
                </div>
              </div>
            </div>
          ))}
          <div className="health-item health-meta">
            <span className="health-icon">📊</span>
            <div className="health-info">
              <div className="health-detail">
                CPU {health.cpu_percent ?? '—'}% • RSS {health.memory_usage_mb ?? '—'}MB
                (peak {health.peak_rss_mb ?? '—'}MB) • {health.events_per_second ?? 0} events/s
              </div>
            </div>
          </div>
          {health.sources?.length > 0 && (
            <div className="health-item health-meta">
              <span className="health-icon">📥</span>
              <div className="health-info">
                <div className="health-detail">
                  {health.sources.map(s => `${s.name} ${sourceState(s)}`).join(' • ')}
                </div>
              </div>
            </div>
          )}
        </div>
      )}
    </Panel>
  )
}
