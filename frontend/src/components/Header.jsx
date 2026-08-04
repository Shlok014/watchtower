import { useEffect, useRef, useState } from 'react'
import { ConnectionPill } from './ConnectionBanner'

const ATTACKS = [
  ['brute_force', '🔐 Brute Force'],
  ['ddos', '🌊 DDoS Attack'],
  ['insider_threat', '🕵️ Insider Threat'],
  ['malware_outbreak', '🦠 Malware Outbreak'],
  ['mixed', '💥 Multi-Vector'],
]

export function Header({ status, ageSeconds, rulesetVersion, onAttack, onReset, busy }) {
  const [menuOpen, setMenuOpen] = useState(false)
  const menuRef = useRef(null)

  // The menu used to stay open until something else was clicked, including
  // through a page the user had visibly moved on from.
  useEffect(() => {
    if (!menuOpen) return
    const close = (e) => {
      if (menuRef.current && !menuRef.current.contains(e.target)) setMenuOpen(false)
    }
    const esc = (e) => e.key === 'Escape' && setMenuOpen(false)
    document.addEventListener('mousedown', close)
    document.addEventListener('keydown', esc)
    return () => {
      document.removeEventListener('mousedown', close)
      document.removeEventListener('keydown', esc)
    }
  }, [menuOpen])

  return (
    <header className="header">
      <div className="header-brand">
        <div className="header-logo">🛡️</div>
        <div>
          <div className="header-title">Watchtower</div>
          <div className="header-subtitle">Security Operations Center</div>
        </div>
      </div>
      <div className="header-controls">
        <span className="model-tag" title="Ruleset version — the hash of the detection weights themselves">
          {rulesetVersion || '—'}
        </span>
        {/* Was the string literal "LIVE", always. */}
        <ConnectionPill status={status} ageSeconds={ageSeconds} />
        <div className="attack-dropdown" ref={menuRef}>
          <button className="btn btn-attack" onClick={() => setMenuOpen((o) => !o)} disabled={busy}>
            ⚡ Simulate Attack ▾
          </button>
          {menuOpen && (
            <div className="attack-menu">
              {ATTACKS.map(([type, label]) => (
                <button key={type} onClick={() => { setMenuOpen(false); onAttack(type) }}>
                  {label}
                </button>
              ))}
            </div>
          )}
        </div>
        <button className="btn btn-reset" onClick={onReset} disabled={busy}>🗑️ Reset All</button>
      </div>
    </header>
  )
}
