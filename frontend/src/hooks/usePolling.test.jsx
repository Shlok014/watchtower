import { act, render, screen } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'

import { LIVE, OFFLINE, STALE, usePolling } from './usePolling'

function Probe({ fetchFn, intervalMs = 2000 }) {
  const { status, ageSeconds, error } = usePolling(fetchFn, intervalMs)
  return (
    <div>
      <span data-testid="status">{status}</span>
      <span data-testid="age">{ageSeconds === null ? 'never' : ageSeconds}</span>
      <span data-testid="error">{error ? error.message : ''}</span>
    </div>
  )
}

/** Advance fake timers and let the promises the tick started settle. */
async function advance(ms) {
  await act(async () => {
    vi.advanceTimersByTime(ms)
    await Promise.resolve()
    await Promise.resolve()
  })
}

describe('usePolling', () => {
  it('reports live after a successful poll', async () => {
    vi.useFakeTimers()
    render(<Probe fetchFn={async () => {}} />)
    await advance(10)
    expect(screen.getByTestId('status')).toHaveTextContent(LIVE)
  })

  it('reports offline before it has ever succeeded', () => {
    vi.useFakeTimers()
    render(<Probe fetchFn={() => new Promise(() => {})} />)
    // The header used to read LIVE here — before a single request returned.
    expect(screen.getByTestId('status')).toHaveTextContent(OFFLINE)
    expect(screen.getByTestId('age')).toHaveTextContent('never')
  })

  it('goes stale when polls start failing, without losing the data', async () => {
    vi.useFakeTimers()
    let ok = true
    render(
      <Probe
        fetchFn={async () => {
          if (!ok) throw new Error('Cannot reach the backend')
        }}
      />
    )
    await advance(10)
    expect(screen.getByTestId('status')).toHaveTextContent(LIVE)

    ok = false
    await advance(2000)
    expect(screen.getByTestId('status')).toHaveTextContent(STALE)
    expect(screen.getByTestId('error')).toHaveTextContent('Cannot reach the backend')
  })

  it('ages to offline on its own when nothing is coming back', async () => {
    vi.useFakeTimers()
    let ok = true
    render(<Probe fetchFn={async () => { if (!ok) throw new Error('down') }} />)
    await advance(10)
    ok = false
    // The separate 1s clock is what makes this possible: without it the UI
    // would sit on its last render forever, still claiming to be live.
    await advance(25000)
    expect(screen.getByTestId('status')).toHaveTextContent(OFFLINE)
  })

  it('does not queue polls behind a slow backend', async () => {
    vi.useFakeTimers()
    let started = 0
    let release
    render(
      <Probe
        fetchFn={() => {
          started += 1
          return new Promise((r) => {
            release = r
          })
        }}
      />
    )
    await advance(10)
    expect(started).toBe(1)
    // Three interval ticks pass while the first request is still outstanding.
    await advance(6000)
    expect(started).toBe(1)

    await act(async () => {
      release()
      await Promise.resolve()
    })
    await advance(2000)
    expect(started).toBe(2)
  })

  it('keeps one interval across re-renders with a changing fetch function', async () => {
    vi.useFakeTimers()
    const setInterval = vi.spyOn(globalThis, 'setInterval')
    const { rerender } = render(<Probe fetchFn={async () => {}} />)
    await advance(10)
    const created = setInterval.mock.calls.length

    // This is the regression: `fetchAll` depended on `search`, so every
    // keystroke tore down the timer and reset the countdown.
    for (let i = 0; i < 5; i++) {
      rerender(<Probe fetchFn={async () => i} />)
    }
    expect(setInterval.mock.calls.length).toBe(created)
  })
})
