import { BellRing } from 'lucide-react'
import { Panel, EmptyState } from './Panel'

const STATUS_LABEL = {
  open: 'open — no action has run',
  contained: 'contained — required steps ran, address blocked',
  mitigated: 'mitigated',
  action_failed: 'action failed — a required step did not succeed',
}

export function AlertsPanel({ alerts, dimmed }) {
  return (
    <Panel icon={BellRing} title="Threat Alerts" dimmed={dimmed}
           badge={`${alerts.length} shown`} badgeColor="red">
      <div className="alerts-list">
        {alerts.length === 0 ? (
          <EmptyState>No alerts raised — nothing has crossed the threshold</EmptyState>
        ) : alerts.slice(0, 30).map((a, i) => (
          <div className={`alert-card ${a.severity === 'critical' ? 'critical' : ''}`} key={a.id || i}>
            <div className="alert-card-header">
              <span className="alert-event">
                {a.severity === 'critical' && <span className="blink-dot"></span>}
                ⚠ {a.event?.replace(/_/g, ' ')}
              </span>
              <span className="alert-score">
                Score: {a.anomaly_score}
                {/* The threshold this alert was actually judged against, stored
                    with it. This printed a hardcoded 0.45 because the API never
                    sent one — so it would have gone on saying 0.45 after anyone
                    changed WATCHTOWER_ALERT_THRESHOLD. */}
                <span className="confidence-tag">
                  {a.features?.threshold != null
                    ? `/ ${a.features.threshold} threshold`
                    : '/ threshold not recorded'}
                </span>
              </span>
            </div>
            <div className="alert-explanation">{a.explanation}</div>
            <div className="alert-meta">{a.ip} • {a.source} • {a.user} • {a.ruleset_version}</div>
            {a.features && (
              <div className="alert-features">
                <span className="feature-tag">Failed:{a.features.failed_attempts_count}</span>
                <span className="feature-tag">Rep:{a.features.ip_reputation}</span>
                <span className="feature-tag">Freq:{a.features.request_frequency}</span>
              </div>
            )}
            {a.soar_response && (
              <div className="alert-actions">
                {a.soar_response.execution_steps?.map((s, j) => (
                  <span className={`alert-action-tag step-${s.status}`} key={j}
                        title={`${s.status}${s.required ? ' · required' : ' · optional'} — ${s.detail}`}>
                    {s.status === 'executed' ? '✓' : s.status === 'failed' ? '✕' : '–'} {s.action}
                  </span>
                ))}
                <span className={`soar-time-tag status-${a.status}`}
                      title="Status earned by the steps that actually ran.">
                  {STATUS_LABEL[a.status] || a.status}
                </span>
              </div>
            )}
          </div>
        ))}
      </div>
    </Panel>
  )
}
