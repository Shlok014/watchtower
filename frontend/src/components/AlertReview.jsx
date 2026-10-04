import { useEffect, useRef, useState } from 'react'

const NEXT = {
  new: ['investigating', 'Start investigation'],
  investigating: ['closed', 'Close review'],
  closed: ['investigating', 'Reopen investigation'],
}

export function AlertReview({ alert, canWrite = false, onHistory, onReview }) {
  const [open, setOpen] = useState(false)
  const [note, setNote] = useState('')
  const [saving, setSaving] = useState(false)
  const [saveError, setSaveError] = useState('')
  const [retry, setRetry] = useState(0)
  const [loaded, setLoaded] = useState({ key: null, detail: null, error: '' })
  const requestVersion = useRef(0)
  const pollStatus = alert.review_status || 'new'
  const key = `${alert.id}:${pollStatus}:${retry}`
  const current = loaded.key === key ? loaded : null
  const loading = open && Boolean(onHistory) && !current
  const detail = current?.detail
  const status = detail?.review_status || pollStatus
  const [target, action] = NEXT[status] || NEXT.new

  useEffect(() => {
    if (!open || !onHistory) return
    let active = true
    const version = ++requestVersion.current
    Promise.resolve().then(() => onHistory(alert.id)).then(
      (snapshot) => {
        if (active && requestVersion.current === version) setLoaded({ key, detail: snapshot, error: '' })
      },
      (err) => {
        if (active && requestVersion.current === version) {
          setLoaded({ key, detail: null, error: err.detail || err.message || 'Could not load review history' })
        }
      }
    )
    return () => { active = false }
  }, [open, key, alert.id, onHistory])

  function toggle() {
    setOpen((value) => !value)
  }

  function reload() {
    setRetry((value) => value + 1)
  }

  async function submit(event) {
    event.preventDefault()
    const reason = note.trim()
    if (!reason) {
      setSaveError('Enter a note before changing review state.')
      return
    }
    requestVersion.current++
    setSaving(true)
    setSaveError('')
    try {
      const snapshot = await onReview(alert.id, target, reason)
      setLoaded({ key, detail: snapshot, error: '' })
      setNote('')
    } catch (err) {
      setSaveError(err.detail || err.message || 'Review update failed')
      if (err.status === 409) reload()
    } finally {
      setSaving(false)
    }
  }

  const error = saveError || current?.error
  const canSubmit = canWrite && onReview && !loading && !current?.error

  return (
    <section className="alert-review" aria-label={`Analyst review for alert ${alert.id}`}>
      <div className="alert-review-summary">
        <span>Analyst review: <strong>{status}</strong></span>
        <button type="button" className="alert-review-toggle" onClick={toggle}
                aria-label={`Review alert ${alert.id}`} aria-expanded={open}>
          {open ? 'Hide history' : 'Review / history'}
        </button>
      </div>
      {open && (
        <div className="alert-review-detail">
          <p className="alert-review-context">SOAR outcome: {alert.status}. Review state does not change blocks or automated actions.</p>
          {loading ? <p role="status">Loading review history…</p> : current?.error ? null : detail?.history?.length ? (
            <ol className="alert-review-history">
              {detail.history.map((entry) => (
                <li key={entry.id}>
                  <span>{entry.from_status} → {entry.to_status} · {entry.actor} · {new Date(entry.timestamp).toLocaleString()}</span>
                  <p>{entry.note}</p>
                </li>
              ))}
            </ol>
          ) : <p className="alert-review-empty">No analyst decisions recorded yet.</p>}
          {error && <p className="alert-review-error" role="alert">{error} <button type="button" onClick={reload}>Retry history</button></p>}
          {canWrite && onReview ? (
            <form className="alert-review-form" onSubmit={submit}>
              <label htmlFor={`review-note-${alert.id}`}>Review note</label>
              <textarea id={`review-note-${alert.id}`} value={note} maxLength={500} rows={2}
                        onChange={(event) => setNote(event.target.value)} disabled={saving || !canSubmit}
                        placeholder="Record evidence or reason for this decision" />
              <button type="submit" className="btn btn-validate" disabled={saving || !canSubmit || !note.trim()}>
                {saving ? 'Saving…' : action}
              </button>
            </form>
          ) : <p className="alert-review-readonly">Read-only: only the owner can update review state.</p>}
        </div>
      )}
    </section>
  )
}
