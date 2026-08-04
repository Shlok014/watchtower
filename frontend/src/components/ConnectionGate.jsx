import { API } from '../api/client'

/**
 * The first screen, and the loudest thing that had to go.
 *
 * What was here was a six-stage boot animation — "Initializing Kafka stream…",
 * "Syncing blockchain ledger…" — that ticked each line to a green checkmark on a
 * 400ms timer without ever contacting the backend. It reported six subsystems
 * healthy before a single request had been made, and played the identical
 * sequence with the server switched off.
 *
 * This reflects exactly one thing: whether a real request to a real endpoint
 * came back.
 */
export function ConnectionGate({ error, attempts, onRetry }) {
  return (
    <div className="loading-screen">
      <div className="loading-logo">🛡️</div>
      <div className="loading-title">Watchtower</div>
      {error ? (
        <>
          <div className="loading-subtitle">Cannot reach the backend</div>
          <div className="loading-stages">
            <div className="loading-stage stopped">
              <span className="loading-stage-icon">✖</span>
              <span>{error.message}</span>
            </div>
            {error.detail && (
              <div className="loading-stage stopped">
                <span className="loading-stage-icon">↳</span>
                <span className="mono">{error.detail}</span>
              </div>
            )}
            <div className="loading-stage">
              <span className="loading-stage-icon">↳</span>
              <span>
                Expected at <code>{API}</code> — start it with{' '}
                <code>python -m watchtower run</code>
              </span>
            </div>
            {attempts > 1 && (
              <div className="loading-stage">
                <span className="loading-stage-icon">⟳</span>
                <span>{attempts} attempts, retrying every 2s</span>
              </div>
            )}
          </div>
          <button className="btn btn-validate" onClick={onRetry}>
            Retry now
          </button>
        </>
      ) : (
        <>
          <div className="loading-subtitle">Connecting to {API}…</div>
          <div className="loading-stages">
            <div className="loading-stage active">
              <span className="loading-stage-icon">⋯</span>
              <span>Awaiting the first response</span>
            </div>
          </div>
        </>
      )}
    </div>
  )
}
