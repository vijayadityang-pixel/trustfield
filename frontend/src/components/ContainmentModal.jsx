import { useEffect, useState } from 'react'
import { X, ShieldOff, AlertTriangle, CheckCircle2, Loader2 } from 'lucide-react'
import { triggerContainment } from '../services/api'

// Static catalog — backend does not yet expose a per-alert action menu.
// Types must match the action_type values accepted by POST /containment/trigger.
const ACTION_CATALOG = [
  {
    type: 'REVOKE_CREDENTIALS',
    label: 'Revoke credentials',
    description: 'Immediately invalidate active credentials for this identity.',
    reversible: false,
  },
  {
    type: 'DISABLE_ACCOUNT',
    label: 'Disable account',
    description: 'Suspend the account/identity from further access.',
    reversible: true,
  },
  {
    type: 'ISOLATE_RESOURCE',
    label: 'Isolate resource',
    description: 'Cut network/access isolation around the affected resource.',
    reversible: true,
  },
  {
    type: 'BLOCK_IP',
    label: 'Block IP',
    description: 'Block the source IP associated with this activity.',
    reversible: true,
  },
  {
    type: 'ROTATE_KEYS',
    label: 'Rotate keys',
    description: 'Rotate access keys/secrets for the affected identity.',
    reversible: true,
  },
]

export default function ContainmentModal({ alert, onClose, onExecuted }) {
  const [status, setStatus] = useState('ready') // ready | confirming | executing | done | exec_error
  const [selected, setSelected] = useState(null)
  const [ackIrreversible, setAckIrreversible] = useState(false)

  useEffect(() => {
    if (!alert) return
    setStatus('ready')
    setSelected(null)
    setAckIrreversible(false)
  }, [alert])

  if (!alert) return null

  async function handleExecute() {
    setStatus('executing')
    try {
      await triggerContainment(
        selected.type,
        alert.cloud_provider,
        alert.resource_id,
        alert.id
      )
      setStatus('done')
      onExecuted && onExecuted()
    } catch (_) {
      setStatus('exec_error')
    }
  }

  return (
    <div
      style={{
        position: 'fixed',
        inset: 0,
        background: 'rgba(5, 7, 10, 0.7)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        zIndex: 50,
        padding: 20,
      }}
      onClick={onClose}
    >
      <div
        className="card"
        style={{ width: 480, maxWidth: '100%', boxShadow: 'var(--shadow-elevated)' }}
        onClick={(e) => e.stopPropagation()}
      >
        <div className="card-header">
          <h3 className="card-title">
            <ShieldOff size={15} color="var(--risk-critical)" />
            Containment
          </h3>
          <button className="btn btn-ghost" onClick={onClose}>
            <X size={16} />
          </button>
        </div>

        <div style={{ fontSize: 12.5, color: 'var(--text-muted)', marginBottom: 16 }}>
          Acting on: <span style={{ color: 'var(--text-primary)', fontWeight: 500 }}>{alert.title}</span>
        </div>

        {(status === 'ready' || status === 'confirming') && (
          <>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 8, marginBottom: 16 }}>
              {ACTION_CATALOG.map((action) => (
                <label
                  key={action.type}
                  style={{
                    display: 'flex',
                    gap: 10,
                    padding: '10px 12px',
                    borderRadius: 'var(--radius-md)',
                    border: `1px solid ${selected?.type === action.type ? 'var(--accent-trust)' : 'var(--border)'}`,
                    background: selected?.type === action.type ? 'var(--bg-hover)' : 'var(--bg-elevated)',
                    cursor: 'pointer',
                  }}
                >
                  <input
                    type="radio"
                    name="containment-action"
                    checked={selected?.type === action.type}
                    onChange={() => setSelected(action)}
                    style={{ marginTop: 3 }}
                  />
                  <div>
                    <div style={{ fontSize: 13.5, fontWeight: 500 }}>{action.label}</div>
                    <div style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 2 }}>{action.description}</div>
                    <div style={{ fontSize: 11, color: action.reversible ? 'var(--risk-low)' : 'var(--risk-critical)', marginTop: 4 }}>
                      {action.reversible ? 'Reversible' : 'Not reversible'}
                    </div>
                  </div>
                </label>
              ))}
            </div>

            {selected && !selected.reversible && (
              <label style={{ display: 'flex', gap: 8, alignItems: 'flex-start', fontSize: 12.5, color: 'var(--text-muted)', marginBottom: 14 }}>
                <input type="checkbox" checked={ackIrreversible} onChange={(e) => setAckIrreversible(e.target.checked)} style={{ marginTop: 2 }} />
                I understand this action cannot be automatically rolled back.
              </label>
            )}

            <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end' }}>
              <button className="btn btn-ghost" onClick={onClose}>Cancel</button>
              <button
                className="btn btn-danger"
                disabled={!selected || (!selected.reversible && !ackIrreversible)}
                onClick={handleExecute}
              >
                Execute action
              </button>
            </div>
          </>
        )}

        {status === 'executing' && (
          <div className="empty-state" style={{ padding: '24px 0' }}>
            <Loader2 size={22} className="spin" style={{ animation: 'spin 1s linear infinite' }} />
            <div className="empty-state-title">Executing {selected?.label}…</div>
          </div>
        )}

        {status === 'done' && (
          <div className="empty-state" style={{ padding: '24px 0' }}>
            <CheckCircle2 size={26} color="var(--risk-low)" />
            <div className="empty-state-title">Action executed</div>
            <div>{selected?.label} has been applied. The alert will update shortly.</div>
            <button className="btn btn-primary" onClick={onClose} style={{ marginTop: 8 }}>Done</button>
          </div>
        )}

        {status === 'exec_error' && (
          <div className="empty-state" style={{ padding: '24px 0' }}>
            <AlertTriangle size={24} color="var(--risk-critical)" />
            <div className="empty-state-title">Execution failed</div>
            <div>The action wasn't applied. Check backend logs and try again.</div>
            <button className="btn" onClick={() => setStatus('ready')} style={{ marginTop: 8 }}>Back</button>
          </div>
        )}
      </div>
      <style>{`@keyframes spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }`}</style>
    </div>
  )
}