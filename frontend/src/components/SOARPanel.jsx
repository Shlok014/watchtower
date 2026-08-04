import { Panel, EmptyState } from './Panel'

const ICON = { contained: '✓', action_failed: '✕', mitigated: '✓', open: '→' }

export function SOARPanel({ actions, dimmed }) {
  return (
    <Panel icon="🤖" title="SOAR Playbooks" dimmed={dimmed}
           tag="enforced at the ingestion layer — no firewall"
           badge={`${actions.length} runs`} badgeColor="amber">
      <div className="panel-body">
        <div className="soar-list">
          {actions.length === 0 ? (
            <EmptyState>No playbook has run yet</EmptyState>
          ) : actions.slice(0, 20).map((s, i) => {
            const ran = s.execution_steps?.filter(x => x.executed).length || 0
            const total = s.execution_steps?.length || 0
            return (
              <div className="soar-item" key={s.id || i}>
                <span className={`soar-status-icon status-${s.status}`} title={s.status}>
                  {ICON[s.status] || '→'}
                </span>
                <div className="soar-details">
                  <div className="soar-playbook">
                    <span className={`priority-tag ${s.priority}`}>{s.priority}</span>
                    {s.playbook} — {s.event?.replace(/_/g, ' ')}
                  </div>
                  <div className="soar-actions-list">
                    {s.execution_steps?.map((x, j) => (
                      <span key={j} className={`step-${x.status}`} title={x.detail}>
                        {x.action}
                        <span className="step-status">{x.status}</span>
                        {j < s.execution_steps.length - 1 && ' → '}
                      </span>
                    ))}
                  </div>
                  {/* The number that used to be here was a random.randint
                      duration on a step nothing executed. This one counts the
                      steps that actually had a side effect. */}
                  <div className="soar-timing">
                    {s.status} · {ran} of {total} steps executed in {s.selection_time_us}µs
                  </div>
                </div>
                <span className="mono" style={{ fontSize: '0.65rem', color: 'var(--text-dim)' }}>{s.ip}</span>
              </div>
            )
          })}
        </div>
      </div>
    </Panel>
  )
}
