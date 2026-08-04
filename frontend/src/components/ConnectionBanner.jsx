import { LIVE, OFFLINE, STALE } from '../hooks/usePolling'

/**
 * Says, at the top of the page, whether what you are looking at is current.
 *
 * The dashboard used to keep rendering its last good data indefinitely with a
 * green `LIVE` in the header, whatever had happened to the backend. Everything
 * on screen was as convincing five minutes after the process died as it was
 * while it was running.
 */
export function ConnectionBanner({ status, ageSeconds, error, onRetry }) {
  if (status === LIVE) return null

  const offline = status === OFFLINE
  return (
    <div className={`conn-banner ${offline ? 'offline' : 'stale'}`} role="status">
      <span className="conn-banner-icon">{offline ? '⛔' : '⚠️'}</span>
      <span>
        <strong>{offline ? 'Backend unreachable' : 'Data is stale'}</strong>
        {' — '}
        {ageSeconds === null
          ? 'never connected'
          : `last successful update ${ageSeconds}s ago`}
        {error?.message ? ` · ${error.message}` : ''}
        {'. '}
        <span className="conn-banner-note">
          Everything below is the last data received, not the current state.
        </span>
      </span>
      <button className="btn btn-validate" onClick={onRetry}>
        Retry
      </button>
    </div>
  )
}

/** The header pill. Three states, all derived from the last successful poll. */
export function ConnectionPill({ status, ageSeconds }) {
  const label = { [LIVE]: 'LIVE', [STALE]: 'STALE', [OFFLINE]: 'OFFLINE' }[status]
  const title =
    status === LIVE
      ? 'Last update under 6 seconds ago'
      : ageSeconds === null
        ? 'No successful update yet'
        : `Last successful update ${ageSeconds}s ago`
  return (
    <span className={`header-status conn-${status}`} title={title}>
      <span className="status-dot"></span>
      {label}
    </span>
  )
}
