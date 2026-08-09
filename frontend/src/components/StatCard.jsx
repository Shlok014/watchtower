export function StatCard({ icon, value, label, color, title }) {
  const Icon = icon
  return (
    <div className={`stat-card ${color}`} title={title}>
      <div className="stat-icon"><Icon size={18} strokeWidth={1.7} /></div>
      <div className="stat-value">{value?.toLocaleString?.() ?? value ?? '—'}</div>
      <div className="stat-label">{label}</div>
    </div>
  )
}
