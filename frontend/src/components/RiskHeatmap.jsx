import { useEffect, useMemo, useState } from 'react'
import { Flame } from 'lucide-react'
import { fetchGraph } from '../services/api'

const PROVIDERS = ['aws', 'azure', 'gcp', 'kubernetes']
const TYPES = ['Identity', 'Role', 'Policy', 'Resource', 'ServiceAccount']

function riskColor(avg) {
  if (avg >= 80) return 'var(--risk-critical)'
  if (avg >= 55) return 'var(--risk-high)'
  if (avg >= 30) return 'var(--risk-medium)'
  if (avg > 0) return 'var(--risk-low)'
  return 'var(--border)'
}

export default function RiskHeatmap({ onCellSelect }) {
  const [nodes, setNodes] = useState([])
  const [status, setStatus] = useState('loading')

  useEffect(() => {
    fetchGraph()
      .then((data) => {
        setNodes(data.nodes || [])
        setStatus((data.nodes || []).length ? 'ready' : 'empty')
      })
      .catch(() => setStatus('error'))
  }, [])

  const matrix = useMemo(() => {
    const cells = {}
    PROVIDERS.forEach((p) => {
      TYPES.forEach((t) => {
        cells[`${p}|${t}`] = { sum: 0, count: 0 }
      })
    })
    nodes.forEach((n) => {
      const key = `${n.provider}|${n.type}`
      if (cells[key]) {
        cells[key].sum += n.risk_score ?? 0
        cells[key].count += 1
      }
    })
    return cells
  }, [nodes])

  if (status === 'loading') {
    return <div className="skeleton" style={{ height: 260, width: '100%' }} />
  }

  if (status === 'error' || status === 'empty') {
    return (
      <div className="empty-state" style={{ height: 260 }}>
        <Flame size={24} color="var(--text-faint)" />
        <div className="empty-state-title">No risk data to map yet</div>
        <div>Heatmap fills in once a scan has run.</div>
      </div>
    )
  }

  return (
    <div style={{ overflowX: 'auto' }}>
      <div style={{ display: 'grid', gridTemplateColumns: `110px repeat(${TYPES.length}, 1fr)`, gap: 6, minWidth: 560 }}>
        <div />
        {TYPES.map((t) => (
          <div key={t} style={{ fontSize: 11, color: 'var(--text-faint)', textAlign: 'center', paddingBottom: 4, textTransform: 'uppercase', letterSpacing: '0.03em' }}>
            {t}
          </div>
        ))}
        {PROVIDERS.map((provider) => (
          <div key={provider} style={{ display: 'contents' }}>
            <div style={{ fontSize: 12.5, color: 'var(--text-muted)', display: 'flex', alignItems: 'center', fontWeight: 500, textTransform: 'capitalize' }}>
              {provider}
            </div>
            {TYPES.map((type) => {
              const cell = matrix[`${provider}|${type}`]
              const avg = cell.count ? cell.sum / cell.count : 0
              return (
                <button
                  key={type}
                  onClick={() => cell.count && onCellSelect && onCellSelect({ provider, type, avg, count: cell.count })}
                  title={cell.count ? `${cell.count} node(s), avg risk ${Math.round(avg)}` : 'No data'}
                  style={{
                    border: '1px solid var(--border)',
                    borderRadius: 8,
                    background: cell.count ? riskColor(avg) : 'var(--bg-elevated)',
                    opacity: cell.count ? 0.25 + 0.75 * (avg / 100) : 0.5,
                    height: 52,
                    cursor: cell.count ? 'pointer' : 'default',
                    display: 'flex',
                    flexDirection: 'column',
                    alignItems: 'center',
                    justifyContent: 'center',
                    color: '#0a0d12',
                    fontFamily: 'var(--font-mono)',
                  }}
                >
                  {cell.count ? (
                    <>
                      <span style={{ fontWeight: 600, fontSize: 13 }}>{Math.round(avg)}</span>
                      <span style={{ fontSize: 9.5, opacity: 0.85 }}>{cell.count} node{cell.count !== 1 ? 's' : ''}</span>
                    </>
                  ) : (
                    <span style={{ fontSize: 11, color: 'var(--text-faint)' }}>—</span>
                  )}
                </button>
              )
            })}
          </div>
        ))}
      </div>
      <div style={{ display: 'flex', gap: 14, marginTop: 14, fontSize: 11, color: 'var(--text-muted)' }}>
        <span><span style={{ display: 'inline-block', width: 8, height: 8, borderRadius: 2, background: 'var(--risk-low)', marginRight: 5 }} />low</span>
        <span><span style={{ display: 'inline-block', width: 8, height: 8, borderRadius: 2, background: 'var(--risk-medium)', marginRight: 5 }} />medium</span>
        <span><span style={{ display: 'inline-block', width: 8, height: 8, borderRadius: 2, background: 'var(--risk-high)', marginRight: 5 }} />high</span>
        <span><span style={{ display: 'inline-block', width: 8, height: 8, borderRadius: 2, background: 'var(--risk-critical)', marginRight: 5 }} />critical</span>
      </div>
    </div>
  )
}
