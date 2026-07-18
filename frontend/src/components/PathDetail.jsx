import { useEffect, useState } from 'react'
import { Route, ArrowRight, ShieldAlert, Info } from 'lucide-react'
import { fetchAlert } from '../services/api'

const RISK_CLASS = (score) => {
  if (score >= 80) return 'critical'
  if (score >= 55) return 'high'
  if (score >= 30) return 'medium'
  return 'low'
}

export default function PathDetail({ alertId, onHighlightPath }) {
  const [detail, setDetail] = useState(null)
  const [status, setStatus] = useState('idle')

  useEffect(() => {
    if (!alertId) {
      setDetail(null)
      setStatus('idle')
      return
    }
    setStatus('loading')
    fetchAlert(alertId)
      .then((data) => {
        setDetail(data)
        setStatus('ready')
        if (onHighlightPath) {
          const hopIds = (data.path?.hops || []).map((h) => (typeof h === 'string' ? h : h.id))
          onHighlightPath(hopIds)
        }
      })
      .catch(() => setStatus('error'))
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [alertId])

  if (status === 'idle') {
    return (
      <div className="card empty-state" style={{ minHeight: 200 }}>
        <Route size={22} color="var(--text-faint)" />
        <div className="empty-state-title">Select an alert</div>
        <div>Its escalation path will appear here, hop by hop.</div>
      </div>
    )
  }

  if (status === 'loading') {
    return <div className="card skeleton" style={{ minHeight: 200 }} />
  }

  if (status === 'error') {
    return (
      <div className="card empty-state" style={{ minHeight: 200 }}>
        <div className="empty-state-title">Couldn't load path detail</div>
      </div>
    )
  }

  const hops = (detail.path?.hops || []).map((h) => (typeof h === 'string' ? { id: h, label: h, type: 'Identity' } : h))
  const pattern = detail.pattern

  return (
    <div className="card">
      <div className="card-header">
        <h3 className="card-title">
          <Route size={15} color="var(--accent-trust)" />
          Escalation path
        </h3>
        {detail.path?.risk_score != null && (
          <span className={`badge badge-${RISK_CLASS(detail.path.risk_score)}`}>
            <span className="badge-dot" />
            risk {detail.path.risk_score}
          </span>
        )}
      </div>

      {hops.length === 0 ? (
        <div className="empty-state" style={{ padding: '24px 0' }}>
          <div>This alert isn't tied to a multi-hop path.</div>
        </div>
      ) : (
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, overflowX: 'auto', paddingBottom: 8 }}>
          {hops.map((hop, idx) => (
            <div key={hop.id} style={{ display: 'flex', alignItems: 'center', gap: 8, flexShrink: 0 }}>
              <div
                style={{
                  border: '1px solid var(--border-bright)',
                  borderRadius: 'var(--radius-md)',
                  padding: '8px 12px',
                  minWidth: 130,
                  background: 'var(--bg-elevated)',
                }}
              >
                <div style={{ fontSize: 10.5, color: 'var(--text-faint)', textTransform: 'uppercase', marginBottom: 3 }}>
                  {hop.type || 'Identity'}
                </div>
                <div className="mono" style={{ fontSize: 12 }}>{hop.label || hop.id}</div>
              </div>
              {idx < hops.length - 1 && <ArrowRight size={15} color="var(--text-faint)" />}
            </div>
          ))}
        </div>
      )}

      {pattern && (
        <div style={{ marginTop: 18, borderTop: '1px solid var(--border)', paddingTop: 16 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
            <ShieldAlert size={14} color="var(--risk-high)" />
            <span style={{ fontWeight: 600, fontSize: 13.5 }}>{pattern.name}</span>
            <span className="mono" style={{ color: 'var(--text-faint)', fontSize: 11.5 }}>
              {pattern.mitre_attack?.technique_id}
            </span>
          </div>
          <p style={{ fontSize: 13, color: 'var(--text-muted)', lineHeight: 1.5, margin: '0 0 12px' }}>
            {pattern.description}
          </p>
          {pattern.indicators?.length > 0 && (
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 11.5, color: 'var(--text-faint)', marginBottom: 6 }}>
                <Info size={12} />
                INDICATORS
              </div>
              <ul style={{ margin: 0, paddingLeft: 18, fontSize: 12.5, color: 'var(--text-muted)', lineHeight: 1.6 }}>
                {pattern.indicators.map((ind, i) => (
                  <li key={i}>{ind}</li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
