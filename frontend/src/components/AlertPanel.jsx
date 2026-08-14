import { useEffect, useState, useCallback } from 'react'
import { Bell, ChevronRight, RotateCcw } from 'lucide-react'
import { fetchAlerts, updateAlertStatus } from '../services/api'
import { riskPercent } from '../utils/risk'

const SEVERITIES = ['critical', 'high', 'medium', 'low']
const STATUSES = ['open', 'in_progress', 'resolved', 'dismissed']
const PROVIDERS = ['aws', 'azure', 'gcp', 'k8s']


function relativeTime(iso) {
  if (!iso) return ''
  const diffMs = Date.now() - new Date(iso).getTime()
  const mins = Math.round(diffMs / 60000)
  if (mins < 1) return 'just now'
  if (mins < 60) return `${mins}m ago`
  const hrs = Math.round(mins / 60)
  if (hrs < 24) return `${hrs}h ago`
  return `${Math.round(hrs / 24)}d ago`
}

export default function AlertPanel({ onSelectAlert, selectedAlertId }) {
  const [alerts, setAlerts] = useState([])
  const [status, setStatus] = useState('loading')
  const [severityFilter, setSeverityFilter] = useState('')
  const [statusFilter, setStatusFilter] = useState('')
  const [providerFilter, setProviderFilter] = useState('')

  const load = useCallback(() => {
    setStatus('loading')
    fetchAlerts({
      severity: severityFilter || undefined,
      status: statusFilter || undefined,
      cloud_provider: providerFilter || undefined,
    })
      .then((data) => {
        setAlerts(data || [])
        setStatus((data || []).length ? 'ready' : 'empty')
      })
      .catch(() => setStatus('error'))
  }, [severityFilter, statusFilter, providerFilter])

  useEffect(() => {
    load()
  }, [load])

  async function handleAcknowledge(e, alertId) {
    e.stopPropagation()
    try {
      await updateAlertStatus(alertId, 'in_progress')
      load()
    } catch (_) {
      // surfaced via row staying in its current state; a toast layer can hook in here later
    }
  }

  return (
    <div className="card">
      <div className="card-header">
        <h3 className="card-title">
          <Bell size={15} color="var(--accent-trust)" />
          Alerts
        </h3>
        <div style={{ display: 'flex', gap: 8 }}>
          <select className="select" value={severityFilter} onChange={(e) => setSeverityFilter(e.target.value)}>
            <option value="">All severities</option>
            {SEVERITIES.map((s) => (
              <option key={s} value={s}>{s}</option>
            ))}
          </select>
          <select className="select" value={statusFilter} onChange={(e) => setStatusFilter(e.target.value)}>
            <option value="">All statuses</option>
            {STATUSES.map((s) => (
              <option key={s} value={s}>{s}</option>
            ))}
          </select>
          <select className="select" value={providerFilter} onChange={(e) => setProviderFilter(e.target.value)}>
            <option value="">All providers</option>
            {PROVIDERS.map((p) => (
              <option key={p} value={p}>{p}</option>
            ))}
          </select>
          <button className="btn btn-ghost" onClick={load} title="Refresh">
            <RotateCcw size={14} />
          </button>
        </div>
      </div>

      {status === 'loading' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
          {[1, 2, 3].map((i) => (
            <div key={i} className="skeleton" style={{ height: 56 }} />
          ))}
        </div>
      )}

      {status === 'error' && (
        <div className="empty-state">
          <div className="empty-state-title">Couldn't load alerts</div>
          <button className="btn" onClick={load}>Retry</button>
        </div>
      )}

      {status === 'empty' && (
        <div className="empty-state">
          <div className="empty-state-title">No alerts match these filters</div>
          <div>Clear the filters, or run a scan to generate new findings.</div>
        </div>
      )}

      {status === 'ready' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
          {alerts.map((alert) => (
            <div
              key={alert.id}
              onClick={() => onSelectAlert && onSelectAlert(alert)}
              style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                padding: '12px 14px',
                borderRadius: 'var(--radius-md)',
                border: `1px solid ${selectedAlertId === alert.id ? 'var(--accent-trust)' : 'var(--border)'}`,
                background: selectedAlertId === alert.id ? 'var(--bg-hover)' : 'var(--bg-elevated)',
                cursor: 'pointer',
                gap: 12,
              }}
            >
              <div style={{ minWidth: 0, flex: 1 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
                  <span className={`badge badge-${alert.severity}`}>
                    <span className="badge-dot" />
                    {alert.severity}
                  </span>
                  <span className="badge badge-neutral">{alert.status}</span>
                  <span className="mono" style={{ color: 'var(--text-faint)' }}>{alert.alert_type}</span>
                </div>
                <div style={{ fontSize: 13.5, fontWeight: 500, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  {alert.title}
                </div>
                <div style={{ fontSize: 11.5, color: 'var(--text-faint)', marginTop: 2 }}>
                  {alert.raw_evidence?.mitre_technique} · {relativeTime(alert.created_at)} · risk {riskPercent(alert.risk_score)}
                </div>
              </div>
              {alert.status === 'open' && (
                <button className="btn btn-ghost" onClick={(e) => handleAcknowledge(e, alert.id)}>
                  Acknowledge
                </button>
              )}
              <ChevronRight size={16} color="var(--text-faint)" />
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
