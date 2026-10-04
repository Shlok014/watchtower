/** Make the server's write policy visible without exposing an owner token in the browser. */
export function AccessBanner({ canWrite }) {
  if (canWrite !== false) return null
  return (
    <div className="access-banner" role="status">
      <strong>Read-only dashboard</strong>
      <span>Investigation and ledger verification remain available. Simulation, retraining, reset and unblock require owner access.</span>
    </div>
  )
}
