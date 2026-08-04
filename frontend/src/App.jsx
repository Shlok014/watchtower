import { useCallback, useEffect, useRef, useState } from 'react'

import { ApiError, api } from './api/client'
import { LIVE, OFFLINE, usePolling } from './hooks/usePolling'

import { AlertDistChart, EventDistChart, TimelineChart } from './components/charts'
import { AlertsPanel } from './components/AlertsPanel'
import { BlocklistPanel } from './components/BlocklistPanel'
import { ConnectionBanner } from './components/ConnectionBanner'
import { ConnectionGate } from './components/ConnectionGate'
import { Footer } from './components/Footer'
import { Header } from './components/Header'
import { HealthPanel } from './components/HealthPanel'
import { LedgerPanel } from './components/LedgerPanel'
import { LogsPanel } from './components/LogsPanel'
import { ModelPanel } from './components/ModelPanel'
import { Panel } from './components/Panel'
import { PipelineBar } from './components/PipelineBar'
import { SOARPanel } from './components/SOARPanel'
import { StatCard } from './components/StatCard'
import { Toast } from './components/Toast'

export default function App() {
  const [connected, setConnected] = useState(false)
  const [connectError, setConnectError] = useState(null)
  const [attempts, setAttempts] = useState(0)

  const [data, setData] = useState({
    stats: null, logs: [], alerts: [], soar: [], ledger: [], health: null,
    blocklist: null, model: null,
  })
  const [filters, setFilters] = useState({ search: '', severity: '', source: '' })
  const [toast, setToast] = useState(null)
  const [chainResult, setChainResult] = useState(null)
  const [busy, setBusy] = useState(null)
  const toastTimer = useRef(null)

  // Filters live in a ref as well as in state: the polling interval reads them
  // when it fires, so typing in the search box never rebuilds the timer.
  const filtersRef = useRef(filters)
  useEffect(() => { filtersRef.current = filters }, [filters])

  const showToast = useCallback((message, type = 'success') => {
    setToast({ message, type })
    if (toastTimer.current) clearTimeout(toastTimer.current)
    toastTimer.current = setTimeout(() => setToast(null), 5000)
  }, [])
  useEffect(() => () => clearTimeout(toastTimer.current), [])

  const reportError = useCallback((err, what) => {
    const detail =
      err instanceof ApiError
        ? err.detail ? `${err.message} — ${err.detail}` : err.message
        : String(err)
    showToast(`❌ ${what} failed: ${detail}`, 'danger')
  }, [showToast])

  // ── the connection gate ────────────────────────────────────────────────────
  // One real request to one real endpoint. What this replaced was a six-stage
  // boot animation on a 400ms timer that never contacted the backend and played
  // the same sequence with the server switched off.
  const connect = useCallback(async () => {
    setAttempts((n) => n + 1)
    try {
      await api.health()
      setConnectError(null)
      setConnected(true)
    } catch (err) {
      setConnectError(err)
    }
  }, [])

  useEffect(() => {
    if (connected) return
    // setTimeout(..., 0) rather than calling connect() in the effect body: it
    // sets state, and a synchronous setState inside an effect cascades renders.
    const kickoff = setTimeout(connect, 0)
    const t = setInterval(connect, 2000)
    return () => {
      clearTimeout(kickoff)
      clearInterval(t)
    }
  }, [connected, connect])

  // ── polling ────────────────────────────────────────────────────────────────
  const fetchAll = useCallback(async () => {
    const f = filtersRef.current
    const params = { limit: '80' }
    if (f.severity) params.severity = f.severity
    if (f.source) params.source = f.source
    if (f.search) params.search = f.search

    // Promise.all, not allSettled: one failed endpoint means the backend is in
    // trouble and the whole snapshot is suspect. Merging a fresh half with a
    // stale half would produce a screen that is internally inconsistent and
    // says nothing about it.
    const [stats, logs, alerts, soar, ledger, health, blocklist, model] = await Promise.all([
      api.stats(), api.logs(params), api.alerts(40), api.soarActions(25),
      api.ledger(20), api.health(), api.blocklist(), api.model(),
    ])
    setData({ stats, logs, alerts, soar, ledger, health, blocklist, model })
  }, [])

  // Polling does not start until the gate has opened. Before this the hook was
  // handed a no-op that *resolved*, which counted as a successful poll — so the
  // badge read LIVE on the strength of having done nothing, and for the first
  // moments after connecting the dashboard showed a live badge above null data.
  // Found by writing the test for exactly that transition.
  const { status, error, ageSeconds, refresh } = usePolling(fetchAll, 2000, {
    enabled: connected,
  })

  // A backend that goes away entirely sends us back to the gate, rather than
  // leaving a dashboard of minutes-old numbers on screen. Derived, not set from
  // an effect: an effect that calls setState here cascades renders, and the
  // condition is a pure function of state we already have.
  const lostConnection = connected && status === OFFLINE && Boolean(error)
  const showGate = !connected || lostConnection

  // ── actions ────────────────────────────────────────────────────────────────
  const run = useCallback(async (name, fn, onDone) => {
    setBusy(name)
    try {
      const res = await fn()
      onDone?.(res)
      await refresh()
    } catch (err) {
      reportError(err, name)
    } finally {
      setBusy(null)
    }
  }, [refresh, reportError])

  const simulateAttack = (type) =>
    run('Simulate attack', () => api.simulateAttack(type), (res) =>
      showToast(`🚨 ${res.message}`, 'danger'))

  const retrain = () =>
    run('Retrain', api.retrain, (res) => {
      const d = res.delta_f1
      showToast(
        `🧠 Model v${res.version} — F1 ${res.metrics.f1}` +
          (d == null
            ? ' (first version)'
            : d === 0
              ? ' · Δ 0.0000 — identical data, nothing changed'
              : ` · Δ ${d > 0 ? '+' : ''}${d.toFixed(4)}`),
        'info'
      )
    })

  const verifyChain = () =>
    run('Verify chain', api.verifyChain, (res) => {
      setChainResult(res)
      showToast(
        res.ok
          ? `✅ Chain verified — ${res.blocks_checked} blocks, all digests recomputed`
          : `❌ Tamper detected at height ${res.first_bad_height} — ${res.findings?.[0]?.reason}`,
        res.ok ? 'success' : 'danger'
      )
    })

  const unblock = (ip) =>
    run('Unblock', () => api.unblock(ip), () => showToast(`🔓 ${ip} unblocked`, 'info'))

  const resetAll = () => {
    if (!confirm('⚠️ Delete every event, alert, ledger block, SOAR record and block? This cannot be undone.')) return
    // The message shown is the backend's, built from real row counts. The
    // version this replaced said "All data cleared" whatever had happened.
    run('Reset', api.reset, (res) => {
      setChainResult(null)
      showToast(`🗑️ ${res.message}`, 'success')
    })
  }

  if (showGate) {
    // Once we have connected at least once, the polling loop is already
    // retrying, so the gate's button refreshes rather than re-running the
    // handshake — and the error shown is the live one, not the stale handshake
    // failure from minutes ago.
    return (
      <ConnectionGate
        error={lostConnection ? error : connectError}
        attempts={lostConnection ? 0 : attempts}
        onRetry={lostConnection ? refresh : connect}
      />
    )
  }

  const { stats, logs, alerts, soar, ledger, health, blocklist, model } = data
  const dimmed = status !== LIVE
  const filtered = Boolean(filters.search || filters.severity || filters.source)

  return (
    <div className="app">
      <Header
        status={status}
        ageSeconds={ageSeconds}
        rulesetVersion={stats?.ruleset_version}
        onAttack={simulateAttack}
        onReset={resetAll}
        busy={Boolean(busy)}
      />

      <ConnectionBanner status={status} ageSeconds={ageSeconds} error={error} onRetry={refresh} />

      <PipelineBar stats={stats} health={health} />
      <HealthPanel health={health} dimmed={dimmed} />

      <div className="stats-grid">
        <StatCard icon="📊" value={stats?.total_logs} label="Total Logs Ingested" color="cyan"
                  title={stats?.retention_note} />
        <StatCard icon="🚨" value={stats?.total_alerts} label="Alerts Raised" color="red" />
        <StatCard icon="‼️" value={stats?.critical_alerts} label="Critical Alerts" color="critical" />
        <StatCard icon="🚫" value={stats?.events_dropped_lifetime} label="Events Dropped" color="amber"
                  title="Suppressed by the blocklist before detection ran" />
        <StatCard icon="🤖" value={stats?.soar_actions_count} label="Playbooks Run" color="green" />
        <StatCard icon="🔗" value={stats?.total_blocks} label="Ledger Blocks" color="purple" />
      </div>

      <div className="grid-2 section-row">
        <Panel icon="📈" title="Logs & Alerts Timeline" dimmed={dimmed}>
          <div className="panel-body"><div className="chart-container">
            <TimelineChart data={stats?.logs_over_time} />
          </div></div>
        </Panel>
        <Panel icon="🎯" title="Alert Severity Distribution" dimmed={dimmed}>
          <div className="panel-body"><div className="chart-container">
            <AlertDistChart data={stats?.alert_distribution} />
          </div></div>
        </Panel>
      </div>

      <div className="section-row">
        <Panel
          icon="📊"
          title="Event Type Distribution"
          tag={
            stats?.distribution_window
              ? `last ${stats.distribution_window} events, not lifetime`
              : undefined
          }
          dimmed={dimmed}
        >
          <div className="panel-body"><div className="chart-container">
            <EventDistChart data={stats?.event_distribution} />
          </div></div>
        </Panel>
      </div>

      <div className="grid-3 section-row">
        <LogsPanel logs={logs} filters={filters} setFilters={setFilters}
                   sources={stats?.sources || []} dimmed={dimmed} filtered={filtered} />
        <AlertsPanel alerts={alerts} dimmed={dimmed} />
      </div>

      <div className="grid-2 section-row">
        <SOARPanel actions={soar} dimmed={dimmed} />
        <BlocklistPanel blocklist={blocklist} onUnblock={unblock} dimmed={dimmed} />
      </div>

      <div className="grid-2 section-row">
        <ModelPanel model={model} onRetrain={retrain} retraining={busy === 'Retrain'} dimmed={dimmed} />
        <LedgerPanel blocks={ledger} onVerify={verifyChain} result={chainResult}
                     verifying={busy === 'Verify chain'} dimmed={dimmed} />
      </div>

      <Footer retentionNote={stats?.retention_note} />
      <Toast toast={toast} />
    </div>
  )
}
