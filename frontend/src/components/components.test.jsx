import { fireEvent, render, screen } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'

import { ApiError } from '../api/client'
import { LIVE, OFFLINE, STALE } from '../hooks/usePolling'
import { AlertsPanel } from './AlertsPanel'
import { BlocklistPanel } from './BlocklistPanel'
import { ConnectionBanner, ConnectionPill } from './ConnectionBanner'
import { ConnectionGate } from './ConnectionGate'
import { HealthPanel } from './HealthPanel'
import { Header } from './Header'
import { LogsPanel } from './LogsPanel'
import { ModelPanel } from './ModelPanel'
import { SOARPanel } from './SOARPanel'

/* Fixtures are shaped exactly like the API responses, so a backend rename shows
   up here as a failing test rather than as an empty cell nobody notices. */

const ALERT = {
  id: 1,
  event: 'brute_force',
  severity: 'critical',
  ip: '203.0.113.77',
  source: 'firewall-01',
  user: 'root',
  anomaly_score: 0.65,
  ruleset_version: 'rules-e2672e35',
  explanation: '5 failed logins from 203.0.113.77 in 60s + High-risk event: brute force',
  features: { failed_attempts_count: 5, ip_reputation: 'tor_exit', request_frequency: 12, threshold: 0.45 },
  status: 'contained',
  soar_response: {
    status: 'contained',
    execution_steps: [
      { action: 'block_ip', status: 'executed', required: true, executed: true, detail: 'blocked for 3600s' },
      { action: 'webhook', status: 'skipped', required: false, executed: false, detail: 'no webhook configured' },
    ],
  },
}

describe('ConnectionGate', () => {
  it('shows the real error when the first request fails', () => {
    render(
      <ConnectionGate
        error={new ApiError('Cannot reach http://localhost:5001/api/v1', {
          offline: true,
          detail: 'Failed to fetch',
        })}
        attempts={3}
        onRetry={() => {}}
      />
    )
    expect(screen.getByText(/Cannot reach the backend/)).toBeInTheDocument()
    expect(screen.getByText(/Failed to fetch/)).toBeInTheDocument()
    // It tells you how to fix it, and how many times it has tried.
    expect(screen.getByText(/python -m watchtower run/)).toBeInTheDocument()
    expect(screen.getByText(/3 attempts/)).toBeInTheDocument()
  })

  it('does not claim any subsystem is healthy before connecting', () => {
    // The six-stage boot animation ticked green checkmarks on a 400ms timer
    // and played identically with the server switched off.
    render(<ConnectionGate error={null} attempts={1} onRetry={() => {}} />)
    expect(screen.getByText(/Awaiting the first response/)).toBeInTheDocument()
    expect(screen.queryByText(/✓/)).not.toBeInTheDocument()
  })
})

describe('connection state', () => {
  it('renders nothing while live', () => {
    const { container } = render(
      <ConnectionBanner status={LIVE} ageSeconds={1} error={null} onRetry={() => {}} />
    )
    expect(container).toBeEmptyDOMElement()
  })

  it('says the data on screen is not current', () => {
    render(<ConnectionBanner status={STALE} ageSeconds={9} error={null} onRetry={() => {}} />)
    expect(screen.getByText(/Data is stale/)).toBeInTheDocument()
    expect(screen.getByText(/last successful update 9s ago/)).toBeInTheDocument()
    expect(screen.getByText(/not the current state/)).toBeInTheDocument()
  })

  it('distinguishes offline from stale', () => {
    render(<ConnectionBanner status={OFFLINE} ageSeconds={null} error={null} onRetry={() => {}} />)
    expect(screen.getByText(/Backend unreachable/)).toBeInTheDocument()
    expect(screen.getByText(/never connected/)).toBeInTheDocument()
  })

  it('pills the three states rather than always reading LIVE', () => {
    const { rerender } = render(<ConnectionPill status={LIVE} ageSeconds={1} />)
    expect(screen.getByText('LIVE')).toBeInTheDocument()
    rerender(<ConnectionPill status={STALE} ageSeconds={8} />)
    expect(screen.getByText('STALE')).toBeInTheDocument()
    rerender(<ConnectionPill status={OFFLINE} ageSeconds={null} />)
    expect(screen.getByText('OFFLINE')).toBeInTheDocument()
  })
})

describe('HealthPanel', () => {
  it('renders the backend’s own summary, whatever it says', () => {
    render(
      <HealthPanel
        health={{
          summary: { state: 'degraded', label: 'Threat feed is stale' },
          components: [
            { name: 'Detection Engine', icon: '🧠', status: 'degraded', detail: 'no threat feed', p50_ms: null, p95_ms: null, samples: 0 },
          ],
          sources: [{ name: 'synthetic', alive: false }],
          cpu_percent: 3.2,
          memory_usage_mb: 61.4,
          events_per_second: 0.7,
        }}
      />
    )
    // Was the string literal "All Systems Operational", always.
    expect(screen.getByText('Threat feed is stale')).toBeInTheDocument()
    expect(screen.getByText(/no samples yet/)).toBeInTheDocument()
    expect(screen.getByText(/synthetic ✕ stopped/)).toBeInTheDocument()
  })

  it('says so when it has no health data at all', () => {
    render(<HealthPanel health={null} />)
    expect(screen.getByText(/No health data received yet/)).toBeInTheDocument()
  })

  it('shows a finite replay as complete instead of stopped', () => {
    render(
      <HealthPanel
        health={{
          summary: { state: 'ok', label: 'All systems operational' },
          components: [],
          sources: [{ name: 'replay:hdfs', alive: false, completed: true }],
        }}
      />
    )
    expect(screen.getByText(/replay:hdfs ✓ complete/)).toBeInTheDocument()
  })
})

describe('Header', () => {
  it('exposes the attack menu state to assistive technology', () => {
    render(<Header status="live" ageSeconds={0} onAttack={() => {}} onReset={() => {}} busy={false} />)

    const trigger = screen.getByRole('button', { name: 'Simulate Attack' })
    expect(trigger).toHaveAttribute('aria-haspopup', 'menu')
    expect(trigger).toHaveAttribute('aria-expanded', 'false')

    fireEvent.click(trigger)

    expect(trigger).toHaveAttribute('aria-expanded', 'true')
    expect(screen.getByRole('menu')).toBeInTheDocument()
    expect(screen.getByRole('menuitem', { name: 'Brute Force' })).toBeInTheDocument()
  })
})

describe('AlertsPanel', () => {
  it('renders the score, its threshold, and the features that fired', () => {
    render(<AlertsPanel alerts={[ALERT]} />)
    expect(screen.getByText(/0.65/)).toBeInTheDocument()
    expect(screen.getByText(/0.45 threshold/)).toBeInTheDocument()
    expect(screen.getByText('Failed:5')).toBeInTheDocument()
    expect(screen.getByText('Rep:tor_exit')).toBeInTheDocument()
  })

  it('marks each SOAR step with what actually happened to it', () => {
    render(<AlertsPanel alerts={[ALERT]} />)
    // ✓ for executed, – for skipped. The version this replaced showed a ✓
    // beside every step, including ones nothing had run.
    expect(screen.getByText(/✓ block_ip/)).toBeInTheDocument()
    expect(screen.getByText(/– webhook/)).toBeInTheDocument()
    expect(screen.getByText(/contained — required steps ran/)).toBeInTheDocument()
  })

  it('has a real empty state', () => {
    render(<AlertsPanel alerts={[]} />)
    expect(screen.getByText(/nothing has crossed the threshold/)).toBeInTheDocument()
  })
})

describe('LogsPanel', () => {
  const LOG = {
    id: 1, timestamp: '2026-08-04T21:00:00Z', source: 'firewall-01', event: 'failed_login',
    ip: '10.0.0.1', user: 'root', severity: 'medium', origin: 'replay:hdfs', dropped: false,
    reputation: { verdict: 'internal', detail: 'RFC1918' },
  }

  it('shows provenance for every row', () => {
    render(<LogsPanel logs={[LOG]} filters={{ search: '', severity: '', source: '' }}
                      setFilters={() => {}} sources={[]} />)
    expect(screen.getByText('replay:hdfs')).toBeInTheDocument()
  })

  it('marks suppressed events instead of hiding them', () => {
    render(<LogsPanel logs={[{ ...LOG, dropped: true }]} filters={{ search: '', severity: '', source: '' }}
                      setFilters={() => {}} sources={[]} />)
    // Hiding them would make the blocklist invisible in the one view where its
    // effect is observable.
    expect(screen.getByText('dropped')).toBeInTheDocument()
  })

  it('tells "no logs" apart from "no matches"', () => {
    const { rerender } = render(
      <LogsPanel logs={[]} filters={{ search: '', severity: '', source: '' }} setFilters={() => {}} sources={[]} />
    )
    expect(screen.getByText(/No logs ingested yet/)).toBeInTheDocument()
    rerender(
      <LogsPanel logs={[]} filters={{ search: 'zzz', severity: '', source: '' }} setFilters={() => {}} sources={[]} filtered />
    )
    expect(screen.getByText(/No logs match these filters/)).toBeInTheDocument()
  })
})

describe('BlocklistPanel', () => {
  it('shows how much traffic each block actually suppressed', () => {
    render(
      <BlocklistPanel
        blocklist={{
          entries: [{ ip: '203.0.113.77', reason: 'repeated authentication failures', events_dropped: 10, seconds_remaining: 3598, expired: false }],
          totals: { events_dropped_lifetime: 10, active_blocks: 1 },
          enforcement: 'Blocks are enforced at this pipeline’s ingestion layer.',
        }}
        onUnblock={() => {}}
      />
    )
    expect(screen.getByText('203.0.113.77')).toBeInTheDocument()
    expect(screen.getByText('10')).toBeInTheDocument()
    // And it states the scope rather than implying a firewall — in the header
    // tag and again in the backend's own note, which is the authoritative one.
    expect(screen.getByText(/nothing touches a firewall/)).toBeInTheDocument()
    expect(screen.getByText(/Blocks are enforced at this pipeline/)).toBeInTheDocument()
  })

  it('calls back with the address to unblock', async () => {
    const onUnblock = vi.fn()
    render(
      <BlocklistPanel
        blocklist={{ entries: [{ ip: '1.2.3.4', reason: 'x', events_dropped: 0, seconds_remaining: 10, expired: false }], totals: {} }}
        onUnblock={onUnblock}
      />
    )
    screen.getByRole('button', { name: /Unblock/ }).click()
    expect(onUnblock).toHaveBeenCalledWith('1.2.3.4')
  })
})

describe('ModelPanel', () => {
  it('keeps the rule engine and the trained model apart', () => {
    render(
      <ModelPanel
        model={{
          trained: true,
          current: {
            version: 2, estimator: 'LogisticRegression', seed: 42, sklearn: '1.9.0',
            train_rows: 287530, test_rows: 287531, delta_f1: 0,
            dataset: { label: 'loghub HDFS_v1 (full, 11.2M lines)' },
            metrics: { f1: 0.9797, precision: 0.9605, recall: 0.9998, roc_auc: 0.9994 },
          },
          rules: { ruleset_version: 'rules-e2672e35', threshold: 0.45, note: 'The live dashboard’s detection is this rule set, not the trained model.' },
          live_scoring: null,
          live_scoring_error: null,
        }}
        onRetrain={() => {}}
      />
    )
    expect(screen.getByText(/rule set, not the trained model/)).toBeInTheDocument()
    expect(screen.getByText('0.9797')).toBeInTheDocument()
    // A zero delta is displayed as a fact, not hidden.
    expect(screen.getByText(/retraining on unchanged data changes nothing/)).toBeInTheDocument()
  })

  it('says there is no model rather than showing a blank score', () => {
    render(<ModelPanel model={{ trained: false, current: null, rules: {} }} onRetrain={() => {}} />)
    expect(screen.getByText(/No model has been trained/)).toBeInTheDocument()
  })

  it('never presents a live partial-block score as the benchmark', () => {
    render(
      <ModelPanel
        model={{
          current: { version: 1, metrics: { f1: 0.98 }, dataset: {}, seed: 42 },
          rules: {},
          live_scoring: {
            lines_seen: 372, blocks_tracked: 43, blocks_evicted: 0,
            unmatched_lines: 0, out_of_vocabulary_lines: 0,
            recent_probabilities: { samples: 20, min: 0.71, median: 0.99, max: 1.0 },
            note: 'Live scores are over partial blocks and are not comparable to held_out_metrics.',
          },
        }}
        onRetrain={() => {}}
      />
    )
    expect(screen.getByText(/not comparable to held_out_metrics/)).toBeInTheDocument()
    // The spread is shown so the skew is visible rather than described.
    expect(screen.getByText(/min 0.71/)).toBeInTheDocument()
  })
})

describe('SOARPanel', () => {
  it('reports how many steps really executed', () => {
    render(
      <SOARPanel
        actions={[{
          id: 1, status: 'contained', priority: 'P1', playbook: 'Brute force containment',
          event: 'brute_force', ip: '203.0.113.77', selection_time_us: 812.4,
          execution_steps: [
            { action: 'block_ip', status: 'executed', executed: true, detail: '' },
            { action: 'webhook', status: 'skipped', executed: false, detail: '' },
          ],
        }]}
      />
    )
    expect(screen.getByText(/1 of 2 steps executed/)).toBeInTheDocument()
    expect(screen.getByText(/no firewall/)).toBeInTheDocument()
  })

  it('has an empty state that does not imply activity', () => {
    render(<SOARPanel actions={[]} />)
    expect(screen.getByText(/No playbook has run yet/)).toBeInTheDocument()
  })
})
