export function Footer({ retentionNote }) {
  return (
    <footer className="footer">
      <div className="footer-content">
        <span className="footer-shield">🛡️</span>
        <span>Built by <span className="footer-name">Shlok Dahale</span></span>
        <span className="footer-divider">•</span>
        <span className="footer-tag">Watchtower — MIT licensed</span>
        {/* Storage policy comes from the backend, which derives it from the
            live configuration. It used to be a hardcoded string describing
            in-memory ring buffers that no longer existed. */}
        {retentionNote && (<><span className="footer-divider">•</span><span className="footer-tag">{retentionNote}</span></>)}
      </div>
    </footer>
  )
}
