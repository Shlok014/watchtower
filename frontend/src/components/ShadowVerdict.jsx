const REASONS = {
  profile_missing: 'profile missing',
  profile_invalid: 'profile invalid',
  profile_not_loaded: 'profile not loaded',
  predates_shadow_schema: 'predates shadow scoring',
  invalid_features: 'invalid features',
  blocked_event: 'blocked at ingest',
}

export function ShadowVerdict({ verdict }) {
  if (!verdict) return <span className="shadow-verdict muted">Shadow: not recorded</span>
  if (verdict.status === 'scored') {
    const state = verdict.shadow_anomaly ? 'flagged' : 'within baseline'
    const digest = verdict.profile_digest || ''
    return (
      <span className={`shadow-verdict ${verdict.shadow_anomaly ? 'flagged' : 'muted'}`}
            title={`Shadow-only robust deviation; uncalibrated, never creates an alert. Profile SHA-256: ${digest}`}>
        {`Shadow: ${state} · deviation ${verdict.anomaly_score} · profile ${digest.slice(0, 8) || 'unknown'}`}
      </span>
    )
  }
  const reason = REASONS[verdict.reason] || verdict.reason || 'unknown reason'
  return <span className="shadow-verdict muted">{`Shadow: ${verdict.status} · ${reason}`}</span>
}
