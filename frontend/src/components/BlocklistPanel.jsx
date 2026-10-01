import { ShieldBan } from 'lucide-react'
import { Panel, EmptyState } from './Panel'

/* The panel that makes the closed loop visible. `events_dropped` counts events
   this pipeline really discarded before detection ran — not actions it reported
   taking. */
export function BlocklistPanel({ blocklist, onUnblock, dimmed, publicDemo = false }) {
  const entries = blocklist?.entries || []
  const totals = blocklist?.totals
  return (
    <Panel icon={ShieldBan} title="Enforcement" dimmed={dimmed}
           tag="ingestion layer — nothing touches a firewall"
           badge={totals ? `${totals.events_dropped_lifetime} dropped` : '—'}
           badgeColor="red">
      <div className="panel-body">
        {entries.length === 0 ? (
          <EmptyState>No addresses are blocked</EmptyState>
        ) : (
          <table className="logs-table">
            <thead>
              <tr><th>Address</th><th>Reason</th><th>Dropped</th><th>Expires in</th>{!publicDemo && <th>Action</th>}</tr>
            </thead>
            <tbody>
              {entries.map((e) => (
                <tr key={e.ip}>
                  <td className="mono">{e.ip}</td>
                  <td>{e.reason}</td>
                  <td><strong>{e.events_dropped}</strong></td>
                  <td>{e.expired ? 'expired' : `${e.seconds_remaining}s`}</td>
                  {!publicDemo && (
                    <td>
                      <button className="btn btn-validate" onClick={() => onUnblock(e.ip)}
                              title="Remove the block; this address's events resume being detected">
                        Unblock
                      </button>
                    </td>
                  )}
                </tr>
              ))}
            </tbody>
          </table>
        )}
        {blocklist?.enforcement && (
          <div className="panel-note">{blocklist.enforcement}</div>
        )}
      </div>
    </Panel>
  )
}
