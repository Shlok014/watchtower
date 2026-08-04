/* One panel shell, so every panel gets the same header, badge and empty-state
   treatment. Before this each of the ten components rebuilt the markup, and
   three of them had drifted. */
export function Panel({ icon, title, tag, badge, badgeColor = 'cyan', actions, children, dimmed }) {
  return (
    <div className={`panel${dimmed ? ' panel-stale' : ''}`}>
      <div className="panel-header">
        <span className="panel-title">
          <span className="panel-title-icon">{icon}</span> {title}
          {tag && <span className="model-tag">{tag}</span>}
        </span>
        <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
          {actions}
          {badge != null && <span className={`panel-badge ${badgeColor}`}>{badge}</span>}
        </div>
      </div>
      {children}
    </div>
  )
}

export function EmptyState({ children }) {
  return <div className="empty-state">{children}</div>
}
