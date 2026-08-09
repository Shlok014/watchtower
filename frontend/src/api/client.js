/**
 * The API client.
 *
 * The version this replaces was three lines:
 *
 *     const fetchJSON = async (url, opts) => {
 *       try { const r = await fetch(url, opts); return await r.json() } catch { return null }
 *     }
 *
 * It never checked `res.ok`, so a 500 with a JSON body rendered as data, and a
 * 404's HTML body threw inside `.json()` and came back as `null` — which every
 * caller treated as "no data yet". Both failures looked exactly like a quiet
 * system, which is the one thing a security dashboard must never do.
 */

/**
 * Base URL. Hardcoded before this, so a build could only ever talk to
 * localhost — including the production build in `dist/`.
 */
export const API = import.meta.env.VITE_API_URL ?? 'http://localhost:5001/api/v1'

/** Requests that take longer than this are treated as a dead backend. */
const TIMEOUT_MS = 8000

export class ApiError extends Error {
  /**
   * @param {string} message  human-readable, safe to show in the UI
   * @param {object} [opts]
   * @param {number} [opts.status]   HTTP status, absent for transport failures
   * @param {string} [opts.detail]   the backend's own explanation, if it gave one
   * @param {boolean} [opts.offline] transport-level failure: nothing answered
   */
  constructor(message, { status, detail, offline = false } = {}) {
    super(message)
    this.name = 'ApiError'
    this.status = status
    this.detail = detail
    this.offline = offline
  }
}

/**
 * @typedef {Object} Stats
 * @property {number} total_logs
 * @property {number} total_alerts
 * @property {number} total_blocks
 * @property {number} logs_retained
 * @property {number} active_blocks
 * @property {number} events_dropped_lifetime
 * @property {string} ruleset_version
 * @property {string} retention_note
 * @property {Array<{time: string, logs: number, alerts: number}>} logs_over_time
 * @property {string[]} sources
 */

/**
 * @typedef {Object} Health
 * @property {{state: 'ok'|'degraded'|'down', label: string}} summary
 * @property {Array<{name: string, icon: string, status: string, detail: string,
 *                   p50_ms: number|null, p95_ms: number|null}>} components
 * @property {Array<{name: string, alive: boolean, completed: boolean, origin: string, stats?: object}>} sources
 * @property {number} events_per_second
 * @property {number|null} memory_usage_mb
 */

async function request(path, opts = {}) {
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS)
  let res
  try {
    res = await fetch(`${API}${path}`, { ...opts, signal: controller.signal })
  } catch (err) {
    // No response at all: refused, DNS, CORS, or our own timeout. Distinguished
    // from an HTTP error because the UI says different things about them —
    // "the backend is not running" versus "the backend said no".
    throw new ApiError(
      err.name === 'AbortError'
        ? `No response from ${API} within ${TIMEOUT_MS / 1000}s`
        : `Cannot reach ${API}`,
      { offline: true, detail: err.message }
    )
  } finally {
    clearTimeout(timer)
  }

  const body = await readBody(res)
  if (!res.ok) {
    // The backend returns JSON for its own errors, including 404s, precisely so
    // this branch has something to show. Fall back to the status line when it
    // is some other server answering.
    const detail = typeof body === 'object' && body ? body.detail || body.error : null
    throw new ApiError(`HTTP ${res.status} ${res.statusText}`.trim(), {
      status: res.status,
      detail,
    })
  }
  if (body === undefined) {
    throw new ApiError('Response was not JSON', { status: res.status })
  }
  return body
}

async function readBody(res) {
  const text = await res.text()
  if (!text) return null
  try {
    return JSON.parse(text)
  } catch {
    // HTML from a proxy or a stray dev server. Returning it as data is how a
    // wrong URL comes to look like an empty dashboard.
    return undefined
  }
}

const get = (path) => request(path)
const post = (path, body) =>
  request(path, {
    method: 'POST',
    headers: body ? { 'Content-Type': 'application/json' } : undefined,
    body: body ? JSON.stringify(body) : undefined,
  })

export const api = {
  stats: () => get('/stats'),
  health: () => get('/system-health'),
  logs: (params) => get(`/logs?${new URLSearchParams(params)}`),
  alerts: (limit = 40) => get(`/alerts?limit=${limit}`),
  soarActions: (limit = 25) => get(`/soar-actions?limit=${limit}`),
  ledger: (limit = 20) => get(`/blockchain?limit=${limit}`),
  blocklist: () => get('/blocklist'),
  model: () => get('/model'),
  playbooks: () => get('/playbooks'),
  config: () => get('/config'),
  threatIntel: () => get('/threat-intel'),

  verifyChain: () => post('/blockchain/validate'),
  simulateAttack: (attack_type) => post('/simulate-attack', { attack_type }),
  retrain: () => post('/retrain'),
  reset: () => post('/reset'),
  unblock: (ip) => request(`/blocklist/${encodeURIComponent(ip)}`, { method: 'DELETE' }),
}
