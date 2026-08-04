import { beforeEach, describe, expect, it, vi } from 'vitest'

import { ApiError, api } from './client'

/**
 * The client this replaces was three lines that swallowed everything:
 *
 *     try { const r = await fetch(url, opts); return await r.json() } catch { return null }
 *
 * Every test below fails against that version.
 */

function mockFetch(impl) {
  const spy = vi.fn(impl)
  vi.stubGlobal('fetch', spy)
  return spy
}

const json = (body, init = {}) =>
  new Response(JSON.stringify(body), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
    ...init,
  })

describe('api client', () => {
  beforeEach(() => vi.unstubAllGlobals())

  it('returns the parsed body on success', async () => {
    mockFetch(async () => json({ total_logs: 7 }))
    await expect(api.stats()).resolves.toEqual({ total_logs: 7 })
  })

  it('throws on a non-ok response instead of rendering it as data', async () => {
    // The specific regression: a 500 whose body happens to be JSON used to be
    // handed to the dashboard and rendered.
    mockFetch(async () => json({ error: 'internal_error' }, { status: 500, statusText: 'Server Error' }))
    await expect(api.stats()).rejects.toBeInstanceOf(ApiError)
  })

  it('carries the backend’s own explanation into the error', async () => {
    mockFetch(async () =>
      json({ error: 'bad_request', detail: 'limit must be an integer' }, { status: 400 })
    )
    await expect(api.logs({ limit: 'abc' })).rejects.toMatchObject({
      status: 400,
      detail: 'limit must be an integer',
    })
  })

  it('distinguishes "nothing answered" from "the backend said no"', async () => {
    mockFetch(async () => {
      throw new TypeError('Failed to fetch')
    })
    const err = await api.stats().catch((e) => e)
    expect(err.offline).toBe(true)
    expect(err.status).toBeUndefined()

    mockFetch(async () => json({}, { status: 503 }))
    const http = await api.stats().catch((e) => e)
    expect(http.offline).toBe(false)
    expect(http.status).toBe(503)
  })

  it('refuses a 200 that is not JSON', async () => {
    // A proxy or the wrong port answering with HTML. The old client threw
    // inside .json(), returned null, and every caller read that as "no data".
    mockFetch(
      async () => new Response('<!doctype html><h1>It works!</h1>', { status: 200 })
    )
    await expect(api.stats()).rejects.toThrow(/not JSON/)
  })

  it('does not swallow a 404 as an empty dashboard', async () => {
    mockFetch(async () => json({ error: 'not_found', detail: 'no route' }, { status: 404 }))
    await expect(api.model()).rejects.toMatchObject({ status: 404 })
  })

  it('sends filters as query parameters', async () => {
    const spy = mockFetch(async () => json([]))
    await api.logs({ limit: '80', search: 'root', severity: 'critical' })
    const url = spy.mock.calls[0][0]
    expect(url).toContain('search=root')
    expect(url).toContain('severity=critical')
  })

  it('POSTs JSON with a content type', async () => {
    const spy = mockFetch(async () => json({ status: 'success' }))
    await api.simulateAttack('brute_force')
    const [, opts] = spy.mock.calls[0]
    expect(opts.method).toBe('POST')
    expect(opts.headers['Content-Type']).toBe('application/json')
    expect(JSON.parse(opts.body)).toEqual({ attack_type: 'brute_force' })
  })

  it('escapes the address in the unblock path', async () => {
    const spy = mockFetch(async () => json({ status: 'unblocked' }))
    await api.unblock('203.0.113.9/../admin')
    expect(spy.mock.calls[0][0]).toContain('203.0.113.9%2F..%2Fadmin')
  })
})
