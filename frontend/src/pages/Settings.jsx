import { useEffect, useRef, useState } from 'react'
import { Cloud, PlayCircle, History, CheckCircle2, XCircle, Loader2 } from 'lucide-react'
import { runScan, fetchScanJob, fetchScanJobs } from '../services/api'

const PROVIDERS = [
  { id: 'aws', label: 'AWS' },
  { id: 'azure', label: 'Azure' },
  { id: 'gcp', label: 'GCP' },
  { id: 'kubernetes', label: 'Kubernetes' },
]

export default function Settings() {
  const [selectedProviders, setSelectedProviders] = useState(['aws', 'azure', 'gcp', 'kubernetes'])
  const [reason, setReason] = useState('')
  const [activeScan, setActiveScan] = useState(null)
  const [history, setHistory] = useState([])
  const [historyStatus, setHistoryStatus] = useState('loading')
  const pollRef = useRef(null)

  function loadHistory() {
    setHistoryStatus('loading')
    fetchScanJobs()
      .then((d) => {
        setHistory(d || [])
        setHistoryStatus('ready')
      })
      .catch(() => setHistoryStatus('error'))
  }

  useEffect(() => {
    loadHistory()
    return () => pollRef.current && clearInterval(pollRef.current)
  }, [])

  function toggleProvider(id) {
    setSelectedProviders((prev) => (prev.includes(id) ? prev.filter((p) => p !== id) : [...prev, id]))
  }

  async function handleRunScan() {
    if (selectedProviders.length === 0) return
    try {
      const { job_id } = await runScan(selectedProviders, reason || undefined)
      setActiveScan({ id: job_id, status: 'pending' })
      pollRef.current = setInterval(async () => {
        try {
          const s = await fetchScanJob(job_id)
          setActiveScan(s)
          if (s.status === 'completed' || s.status === 'failed' || s.status === 'cancelled') {
            clearInterval(pollRef.current)
            loadHistory()
          }
        } catch (_) {
          clearInterval(pollRef.current)
        }
      }, 2000)
    } catch (_) {
      setActiveScan({ status: 'failed' })
    }
  }

  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title">Settings</h1>
          <p className="page-subtitle">Trigger scans across connected clouds and review run history.</p>
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16, marginBottom: 16 }}>
        <div className="card">
          <div className="card-header">
            <h3 className="card-title">
              <Cloud size={15} color="var(--accent-trust)" />
              Providers
            </h3>
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            {PROVIDERS.map((p) => (
              <label key={p.id} style={{ display: 'flex', alignItems: 'center', gap: 10, fontSize: 13.5 }}>
                <input type="checkbox" checked={selectedProviders.includes(p.id)} onChange={() => toggleProvider(p.id)} />
                {p.label}
              </label>
            ))}
          </div>

          <div style={{ marginTop: 18, paddingTop: 16, borderTop: '1px solid var(--border)' }}>
            <div style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 8 }}>Reason (optional)</div>
            <input
              type="text"
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              placeholder="e.g. weekly audit"
              className="select"
              style={{ width: '100%' }}
            />
          </div>

          <button
            className="btn btn-primary"
            style={{ marginTop: 18, width: '100%', justifyContent: 'center' }}
            onClick={handleRunScan}
            disabled={activeScan && !['completed', 'failed', 'cancelled'].includes(activeScan.status)}
          >
            <PlayCircle size={15} />
            Run scan
          </button>
        </div>

        <div className="card">
          <div className="card-header">
            <h3 className="card-title">Active run</h3>
          </div>
          {!activeScan && (
            <div className="empty-state" style={{ padding: '20px 0' }}>
              <div>No scan running. Trigger one from the left panel.</div>
            </div>
          )}
          {activeScan && (
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 10 }}>
                {activeScan.status === 'completed' && <CheckCircle2 size={16} color="var(--risk-low)" />}
                {activeScan.status === 'failed' && <XCircle size={16} color="var(--risk-critical)" />}
                {(activeScan.status === 'running' || activeScan.status === 'pending') && (
                  <Loader2 size={16} style={{ animation: 'spin 1s linear infinite' }} />
                )}
                <span style={{ fontSize: 13.5, fontWeight: 500, textTransform: 'capitalize' }}>{activeScan.status}</span>
              </div>
              <div style={{ fontSize: 12.5, color: 'var(--text-muted)', display: 'flex', flexDirection: 'column', gap: 4 }}>
                {activeScan.nodes_discovered != null && <div>Nodes discovered: {activeScan.nodes_discovered}</div>}
                {activeScan.edges_discovered != null && <div>Edges discovered: {activeScan.edges_discovered}</div>}
                {activeScan.alerts_generated != null && <div>Alerts generated: {activeScan.alerts_generated}</div>}
              </div>
              <div className="mono" style={{ fontSize: 11, color: 'var(--text-faint)', marginTop: 8 }}>
                {activeScan.id}
              </div>
            </div>
          )}
        </div>
      </div>

      <div className="card">
        <div className="card-header">
          <h3 className="card-title">
            <History size={15} color="var(--accent-trust)" />
            Scan history
          </h3>
          <button className="btn btn-ghost" onClick={loadHistory}>Refresh</button>
        </div>

        {historyStatus === 'loading' && <div className="skeleton" style={{ height: 140 }} />}
        {historyStatus === 'error' && <div className="empty-state" style={{ padding: '16px 0' }}>Couldn't load scan history.</div>}
        {historyStatus === 'ready' && history.length === 0 && (
          <div className="empty-state" style={{ padding: '16px 0' }}>No scans have run yet.</div>
        )}
        {historyStatus === 'ready' && history.length > 0 && (
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
            <thead>
              <tr style={{ textAlign: 'left', color: 'var(--text-faint)', fontSize: 11.5, textTransform: 'uppercase' }}>
                <th style={{ padding: '6px 8px' }}>Job ID</th>
                <th style={{ padding: '6px 8px' }}>Status</th>
                <th style={{ padding: '6px 8px' }}>Started</th>
                <th style={{ padding: '6px 8px' }}>Alerts</th>
              </tr>
            </thead>
            <tbody>
              {history.map((s) => (
                <tr key={s.id} style={{ borderTop: '1px solid var(--border)' }}>
                  <td className="mono" style={{ padding: '8px' }}>{s.id}</td>
                  <td style={{ padding: '8px', textTransform: 'capitalize' }}>{s.status}</td>
                  <td style={{ padding: '8px', color: 'var(--text-muted)' }}>{s.started_at ? new Date(s.started_at).toLocaleString() : '—'}</td>
                  <td style={{ padding: '8px' }}>{s.alerts_generated ?? '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
      <style>{`@keyframes spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }`}</style>
    </div>
  )
}