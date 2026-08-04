import { useCallback, useEffect, useRef, useState } from 'react'

/**
 * Poll on a stable interval, and track whether the data on screen is current.
 *
 * Two things this fixes.
 *
 * **The interval used to be torn down and recreated on every search keystroke.**
 * `fetchAll` depended on `search`, the effect depended on `fetchAll`, so typing
 * "admin" rebuilt the timer five times and reset the countdown each time. The
 * fetch function now lives in a ref: the interval is created once and reads the
 * latest closure when it fires.
 *
 * **The dashboard could not tell you when it last heard from the backend.** The
 * header read `LIVE` unconditionally, and every panel kept rendering its last
 * good data with no indication that the data was minutes old and the backend was
 * gone. `status` below is derived from the age of the last *successful* poll, so
 * it degrades on its own even when nothing is coming back to trigger a render.
 */

export const LIVE = 'live'
export const STALE = 'stale'
export const OFFLINE = 'offline'

/** Data older than this is no longer "live", at a 2s poll interval. */
const STALE_AFTER_MS = 6000
/** Older than this and we stop calling it data. */
const OFFLINE_AFTER_MS = 20000

export function usePolling(fetchFn, intervalMs = 2000) {
  const [lastSuccessAt, setLastSuccessAt] = useState(null)
  const [error, setError] = useState(null)
  const [now, setNow] = useState(() => Date.now())

  // The ref is the whole point: the interval closes over this box, not over
  // fetchFn, so changing filters never restarts the timer.
  const fnRef = useRef(fetchFn)
  useEffect(() => {
    fnRef.current = fetchFn
  }, [fetchFn])

  const inFlight = useRef(false)

  const runOnce = useCallback(async () => {
    // A slow backend must not queue up requests behind itself. Without this,
    // an 8s timeout against a 2s interval means four concurrent polls and a
    // "last success" that jumps backwards as they land out of order.
    if (inFlight.current) return
    inFlight.current = true
    try {
      await fnRef.current()
      setLastSuccessAt(Date.now())
      setError(null)
    } catch (err) {
      setError(err)
    } finally {
      inFlight.current = false
      setNow(Date.now())
    }
  }, [])

  useEffect(() => {
    let cancelled = false
    const tick = () => {
      if (!cancelled) runOnce()
    }
    tick()
    const poll = setInterval(tick, intervalMs)
    // A separate, slower clock so `status` ages even while every poll is
    // failing — otherwise the UI would sit on LIVE forever after the last
    // successful render, since nothing would re-render it.
    const clock = setInterval(() => !cancelled && setNow(Date.now()), 1000)
    return () => {
      cancelled = true
      clearInterval(poll)
      clearInterval(clock)
    }
  }, [runOnce, intervalMs])

  const ageMs = lastSuccessAt === null ? null : now - lastSuccessAt
  let status = LIVE
  if (lastSuccessAt === null || ageMs > OFFLINE_AFTER_MS) status = OFFLINE
  else if (ageMs > STALE_AFTER_MS || error) status = STALE

  return {
    status,
    error,
    lastSuccessAt,
    /** Seconds since the last successful poll, or null if there has never been one. */
    ageSeconds: ageMs === null ? null : Math.floor(ageMs / 1000),
    refresh: runOnce,
  }
}
