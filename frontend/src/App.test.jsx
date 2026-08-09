import { act, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import { ApiError } from './api/client'

// The module is mocked rather than fetch, so these tests exercise App's own
// orchestration — the gate, the transitions, the toasts — without re-testing
// the client, which has its own file.
vi.mock('./api/client', async (importOriginal) => {
  const actual = await importOriginal()
  return {
    ...actual,
    api: {
      stats: vi.fn(),
      health: vi.fn(),
      logs: vi.fn(),
      alerts: vi.fn(),
      soarActions: vi.fn(),
      ledger: vi.fn(),
      blocklist: vi.fn(),
      model: vi.fn(),
      verifyChain: vi.fn(),
      simulateAttack: vi.fn(),
      retrain: vi.fn(),
      reset: vi.fn(),
      unblock: vi.fn(),
    },
  }
})

// Chart.js measures a real canvas and throws in jsdom ("Cannot read properties
// of null (reading 'ownerDocument')"). The charts are stubbed because what is
// under test here is App's orchestration — the gate, the transitions, the
// toasts — not whether Chart.js draws.
vi.mock('./components/charts', () => ({
  TimelineChart: () => <div data-testid="chart-timeline" />,
  AlertDistChart: () => <div data-testid="chart-alerts" />,
  EventDistChart: () => <div data-testid="chart-events" />,
}))

const { api } = await import('./api/client')
const App = (await import('./App')).default

const STATS = {
  // Distinctive values: 42 appeared three times in this fixture, and an
  // assertion that matches three elements is not an assertion.
  total_logs: 4271,
  total_alerts: 3,
  critical_alerts: 1,
  events_dropped_lifetime: 7,
  soar_actions_count: 3,
  total_blocks: 42,
  logs_retained: 42,
  active_blocks: 1,
  retention_note: 'SQLite (WAL) at watchtower.db; events retained 24h',
  ruleset_version: 'rules-e2672e35',
  logs_over_time: [],
  alert_distribution: { critical: 1, high: 1, medium: 1, low: 0 },
  event_distribution: { failed_login: 10 },
  sources: ['firewall-01'],
}

const HEALTH = {
  summary: { state: 'ok', label: 'All systems operational' },
  components: [],
  sources: [{ name: 'synthetic', alive: true, origin: 'synthetic' }],
  cpu_percent: 2,
  memory_usage_mb: 60,
  peak_rss_mb: 70,
  events_per_second: 0.8,
}

function happyBackend() {
  api.health.mockResolvedValue(HEALTH)
  api.stats.mockResolvedValue(STATS)
  api.logs.mockResolvedValue([])
  api.alerts.mockResolvedValue([])
  api.soarActions.mockResolvedValue([])
  api.ledger.mockResolvedValue([])
  api.blocklist.mockResolvedValue({ entries: [], totals: {} })
  api.model.mockResolvedValue({ trained: false, current: null, rules: {}, history: [] })
}

/** Let the mocked promises settle and any timers fire.
 *
 * Fake timers are configured with `shouldAdvanceTime`, because `waitFor` polls
 * on real timers internally — under plain fake timers it never resolves and
 * every test here times out at five seconds. */
async function settle(ms = 50) {
  await act(async () => {
    vi.advanceTimersByTime(ms)
    await Promise.resolve()
    await Promise.resolve()
    await Promise.resolve()
  })
}

describe('App', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    vi.useFakeTimers({ shouldAdvanceTime: true })
  })

  it('holds at the connection gate until a real request comes back', async () => {
    api.health.mockRejectedValue(new ApiError('Cannot reach http://localhost:5001/api/v1', {
      offline: true, detail: 'Failed to fetch',
    }))
    render(<App />)
    await settle()

    expect(screen.getByText(/Cannot reach the backend/)).toBeInTheDocument()
    // Nothing about the pipeline is claimed while disconnected.
    expect(screen.queryByText(/All systems operational/)).not.toBeInTheDocument()
    expect(screen.queryByText('LIVE')).not.toBeInTheDocument()
  })

  it('shows the dashboard once the backend answers', async () => {
    happyBackend()
    render(<App />)
    await settle(100)

    await waitFor(() => expect(screen.getByText('LIVE')).toBeInTheDocument())
    expect(screen.getByText('Total Logs Ingested')).toBeInTheDocument()
    // Twice: the header pill and the pipeline bar's detection node, both fed
    // from the same /stats field rather than from two separate literals.
    expect(screen.getAllByText('rules-e2672e35')).toHaveLength(2)
    // And real data is on screen the moment the gate opens, not two seconds
    // later — the whole reason usePolling takes an `enabled` flag.
    expect(screen.getByText('4,271')).toBeInTheDocument()
    // The enforcement number is on the masthead, not buried.
    expect(screen.getByText('Events Dropped')).toBeInTheDocument()
  })

  it('goes back to the gate when the backend disappears', async () => {
    happyBackend()
    render(<App />)
    await settle(100)
    await waitFor(() => expect(screen.getByText('LIVE')).toBeInTheDocument())

    // A message distinct from the gate's own "Cannot reach the backend"
    // heading, so the assertion below matches one element rather than two.
    const gone = new ApiError('Connection refused by the API', { offline: true })
    api.stats.mockRejectedValue(gone)
    api.health.mockRejectedValue(gone)

    // Past OFFLINE_AFTER_MS, with the 1s clock ticking it there.
    await settle(25000)
    await waitFor(() =>
      expect(screen.getByText('Connection refused by the API')).toBeInTheDocument()
    )
    // The stale dashboard is gone, not left on screen looking current.
    expect(screen.queryByText('Total Logs Ingested')).not.toBeInTheDocument()
  })

  it('surfaces the backend’s own explanation when an action fails', async () => {
    happyBackend()
    render(<App />)
    await settle(100)
    await waitFor(() => expect(screen.getByText('LIVE')).toBeInTheDocument())

    api.simulateAttack.mockRejectedValue(
      new ApiError('HTTP 500 Internal Server Error', { status: 500, detail: 'store is read-only' })
    )
    fireEvent.click(screen.getByRole('button', { name: /Simulate Attack/ }))
    await settle()
    fireEvent.click(screen.getByRole('menuitem', { name: /Brute Force/ }))
    await settle()

    await waitFor(() =>
      expect(screen.getByText(/store is read-only/)).toBeInTheDocument()
    )
  })

  it('reports a zero retrain delta as the result, not as nothing happening', async () => {
    happyBackend()
    render(<App />)
    await settle(100)
    await waitFor(() => expect(screen.getByText('LIVE')).toBeInTheDocument())

    api.retrain.mockResolvedValue({
      status: 'trained', version: 2, delta_f1: 0,
      metrics: { f1: 0.9797, precision: 0.9605, recall: 0.9998 },
    })
    screen.getByRole('button', { name: /Retrain/ }).click()
    await settle(100)

    // The endpoint this replaced returned a figure that rose ~1% per press.
    await waitFor(() =>
      expect(screen.getByText(/identical data, nothing changed/)).toBeInTheDocument()
    )
  })

  it('shows the backend’s own row counts after a reset, not a fixed message', async () => {
    happyBackend()
    vi.spyOn(globalThis, 'confirm').mockReturnValue(true)
    render(<App />)
    await settle(100)
    await waitFor(() => expect(screen.getByText('LIVE')).toBeInTheDocument())

    api.reset.mockResolvedValue({
      status: 'success',
      message: 'Deleted 128 rows — 42 events, 3 alerts, 42 ledger blocks, 3 SOAR records',
    })
    screen.getByRole('button', { name: /Reset All/ }).click()
    await settle(100)

    // "All data cleared" used to be printed whatever had happened.
    await waitFor(() => expect(screen.getByText(/Deleted 128 rows/)).toBeInTheDocument())
  })

  it('does not reset the poll interval when the search box changes', async () => {
    happyBackend()
    const spy = vi.spyOn(globalThis, 'setInterval')
    render(<App />)
    await settle(100)
    await waitFor(() => expect(screen.getByText('LIVE')).toBeInTheDocument())
    const before = spy.mock.calls.length

    const box = screen.getByPlaceholderText(/Search logs/)
    for (const value of ['a', 'ad', 'adm', 'admi', 'admin']) {
      await act(async () => {
        box.value = value
        box.dispatchEvent(new Event('input', { bubbles: true }))
        await Promise.resolve()
      })
    }
    // The regression: `fetchAll` depended on `search`, so every keystroke tore
    // the timer down and rebuilt it, resetting the countdown each time.
    expect(spy.mock.calls.length).toBe(before)
  })
})
