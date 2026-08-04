export function StatCard({ icon, value, label, color, title }) {
  return (
    <div className={`stat-card ${color}`} title={title}>
      <div className="stat-icon">{icon}</div>
      <div className="stat-value">{value?.toLocaleString?.() ?? value ?? '—'}</div>
      <div className="stat-label">{label}</div>
    </div>
  )
}
