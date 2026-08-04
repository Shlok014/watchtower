import { Panel, EmptyState } from './Panel'

export function LedgerPanel({ blocks, onVerify, result, verifying, dimmed }) {
  return (
    <Panel icon="🔗" title="Audit Ledger" dimmed={dimmed}
           tag="tamper-evident SHA-256 chain"
           badge={`${blocks.length} shown`} badgeColor="cyan"
           actions={
             <button className="btn btn-validate" onClick={onVerify} disabled={verifying}>
               {verifying ? '⏳ Verifying…' : '🔍 Verify Chain'}
             </button>
           }>
      {result && (
        <div className={`chain-validation ${result.ok ? 'valid' : 'invalid'}`}>
          {result.ok ? (
            <>✅ Verified — {result.blocks_checked} blocks, every digest recomputed from the live event rows
              {result.pruned_events > 0 &&
                ` (${result.pruned_events} reference events removed by retention, checked against the stored preimage)`}
            </>
          ) : (
            <>
              ❌ Tamper detected — {result.findings?.length} finding(s), first at height {result.first_bad_height}
              <ul className="chain-findings">
                {result.findings?.slice(0, 5).map((f, i) => (
                  <li key={i}><code>{f.reason}</code> at block {f.block_id} — {f.detail}</li>
                ))}
              </ul>
            </>
          )}
        </div>
      )}
      <div className="panel-body">
        <div className="blockchain-chain">
          {blocks.length === 0 ? (
            <EmptyState>No blocks — nothing has been ingested yet</EmptyState>
          ) : blocks.slice(0, 15).map((b, i) => (
            <div key={b.block_id || i} className="block-card">
              <div className="block-card-header">
                <span className="block-id">Block #{b.block_id}</span>
                <span className="block-nonce" title="Hash of this block's log entry">log {b.log_hash?.slice(0, 8)}…</span>
              </div>
              <div className="block-hash-row">
                <span className="block-label">Hash</span>
                <span className="block-hash" title={b.hash}>{b.hash?.slice(0, 24)}…</span>
              </div>
              <div className="block-hash-row">
                <span className="block-label">Prev</span>
                <span className="block-hash prev" title={b.prev_hash}>{b.prev_hash?.slice(0, 24)}…</span>
              </div>
              <div className="block-time">{b.timestamp ? new Date(b.timestamp).toLocaleTimeString() : ''}</div>
              {i < blocks.slice(0, 15).length - 1 && <div className="chain-arrow">⬇</div>}
            </div>
          ))}
        </div>
      </div>
    </Panel>
  )
}
