import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'

import { AlertsPanel } from './AlertsPanel'
import { LogsPanel } from './LogsPanel'

const verdict = {
  detector: 'live_profile_shadow',
  status: 'scored',
  profile_digest: 'abcdef0123456789',
  anomaly_score: 1.234,
  shadow_anomaly: true,
  top_feature: 'request_frequency',
}

const alert = {
  id: 11, event: 'port_scan', severity: 'high', anomaly_score: 0.45,
  features: { threshold: 0.45 }, status: 'open', review_status: 'new',
  shadow_verdict: verdict,
}

const log = {
  id: 5, timestamp: '2026-10-04T12:00:00Z', origin: 'synthetic', source: 'test',
  event: 'log_info', ip: '192.0.2.5', user: 'demo', severity: 'low',
  reputation: { verdict: 'unavailable' }, shadow_verdict: verdict,
}

describe('shadow verdict display', () => {
  it('separates a rule alert score from the shadow score and identifies profile', () => {
    render(<AlertsPanel alerts={[alert]} />)
    expect(screen.getByText(/Rule score: 0.45/)).toBeInTheDocument()
    expect(screen.getByText(/Shadow: flagged · deviation 1.234/)).toBeInTheDocument()
    expect(screen.getByText(/profile abcdef01/)).toBeInTheDocument()
  })

  it('shows a shadow verdict even when rules did not raise an alert', () => {
    render(<LogsPanel logs={[log]} filters={{ search: '', severity: '', source: '' }}
                      setFilters={() => {}} sources={[]} />)
    expect(screen.getByRole('columnheader', { name: 'Shadow' })).toBeInTheDocument()
    expect(screen.getByText(/Shadow: flagged/)).toBeInTheDocument()
  })

  it('distinguishes unavailable, skipped, and older unrecorded events', () => {
    const logs = [
      { ...log, id: 1, shadow_verdict: { status: 'unavailable', reason: 'profile_missing' } },
      { ...log, id: 2, shadow_verdict: { status: 'skipped', reason: 'blocked_event' } },
      { ...log, id: 3, shadow_verdict: null },
    ]
    render(<LogsPanel logs={logs} filters={{ search: '', severity: '', source: '' }}
                      setFilters={() => {}} sources={[]} />)
    expect(screen.getByText(/Shadow: unavailable · profile missing/)).toBeInTheDocument()
    expect(screen.getByText(/Shadow: skipped · blocked at ingest/)).toBeInTheDocument()
    expect(screen.getByText(/Shadow: not recorded/)).toBeInTheDocument()
  })
})
