import { useEffect, useRef, useState } from 'react'
import { Bug, Crosshair, Lock, ShieldCheck, Trash2, UserSearch, Waves, Zap } from 'lucide-react'
import { ConnectionPill } from './ConnectionBanner'

const ATTACKS = [
  ['brute_force', Lock, 'Brute Force'],
  ['ddos', Waves, 'DDoS Attack'],
  ['insider_threat', UserSearch, 'Insider Threat'],
  ['malware_outbreak', Bug, 'Malware Outbreak'],
  ['mixed', Crosshair, 'Multi-Vector'],
]

export function Header({ status, ageSeconds, rulesetVersion, onAttack, onReset, busy, canWrite = true }) {
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
        <div className="header-logo" aria-hidden="true"><ShieldCheck size={21} strokeWidth={1.8} /></div>
        <div>
          <div className="header-title">Watchtower</div>
          <div className="header-subtitle">Security Operations Center</div>
        </div>
      </div>
      <div className="header-controls">
        <span className="model-tag" title="Ruleset fingerprint — weights, windows, cooldown, threshold, and file auth signal">
          {rulesetVersion || '—'}
        </span>
        {/* Was the string literal "LIVE", always. */}
        <ConnectionPill status={status} ageSeconds={ageSeconds} />
        <div className="attack-dropdown" ref={menuRef}>
          <button className="btn btn-attack" onClick={() => setMenuOpen((o) => !o)} disabled={busy || !canWrite}
                  aria-haspopup="menu" aria-expanded={menuOpen} aria-controls="attack-menu">
            <Zap size={15} strokeWidth={1.8} /> Simulate Attack
          </button>
          {menuOpen && canWrite && (
            <div id="attack-menu" className="attack-menu" role="menu" aria-label="Attack simulation menu">
              {ATTACKS.map(([type, Icon, label]) => (
                <button key={type} role="menuitem" onClick={() => { setMenuOpen(false); onAttack(type) }}>
                  <Icon size={14} strokeWidth={1.7} /> {label}
                </button>
              ))}
            </div>
          )}
        </div>
        <button className="btn btn-reset" onClick={onReset} disabled={busy || !canWrite}>
          <Trash2 size={15} strokeWidth={1.8} /> Reset All
        </button>
      </div>
    </header>
  )
}
