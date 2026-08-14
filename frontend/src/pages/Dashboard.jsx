import { useEffect, useState } from 'react'
import { Network, ShieldAlert, Activity, Cloud, Flame, X } from 'lucide-react'
import TrustGraph from '../components/TrustGraph'
import RiskHeatmap from '../components/RiskHeatmap'
import { fetchGraphStats, fetchAlerts } from '../services/api'
import { riskPercent } from '../utils/risk'
import { nodeCategory } from '../utils/nodeTypes'

export default function Dashboard() {
  const [stats, setStats] = useState(null)
  const [openAlertCount, setOpenAlertCount] = useState(null)
  const [selectedNode, setSelectedNode] = useState(null)

  useEffect(() => {
    fetchGraphStats().then(setStats).catch(() => setStats(false))
    fetchAlerts({ status: 'open' }).then((d) => setOpenAlertCount((d || []).length)).catch(() => setOpenAlertCount(false))
  }, [])

  const tiles = [
    {
      label: 'Nodes in trust graph',
      value: stats === false ? '—' : stats?.total_nodes ?? '…',
      icon: Network,
      cls: 'trust',
    },
    {
      label: 'Open alerts',
      value: openAlertCount === false ? '—' : openAlertCount ?? '…',
      icon: ShieldAlert,
      cls: openAlertCount > 0 ? 'critical' : '',
    },
    {
      label: 'Critical findings',
      value: stats === false ? '—' : stats?.high_risk_nodes ?? '…',
      icon: Flame,
      cls: 'critical',
    },
    {
      label: 'Providers connected',
      value: stats === false ? '—' : stats?.providers_connected?.length ?? '…',
      icon: Cloud,
      cls: '',
    },
  ]

  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title">Dashboard</h1>
          <p className="page-subtitle">Live trust graph and risk posture across AWS, Azure, GCP, and Kubernetes.</p>
        </div>
      </div>

      <div className="stat-grid">
        {tiles.map((t) => (
          <div className="stat-tile" key={t.label}>
            <div className="stat-tile-label" style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
              <t.icon size={13} />
              {t.label}
            </div>
            <div className={`stat-tile-value ${t.cls}`}>{t.value}</div>
          </div>
        ))}
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: selectedNode ? '1fr 280px' : '1fr', gap: 16, marginBottom: 20 }}>
        <div className="card">
          <div className="card-header">
            <h3 className="card-title">
              <Network size={15} color="var(--accent-trust)" />
              Trust graph
            </h3>
            <span style={{ fontSize: 11.5, color: 'var(--text-faint)' }}>Click a node for detail</span>
          </div>
          <TrustGraph onNodeSelect={setSelectedNode} />
        </div>

        {selectedNode && (
          <div className="card" style={{ alignSelf: 'flex-start' }}>
            <div className="card-header">
              <h3 className="card-title" style={{ fontSize: 13 }}>Node detail</h3>
              <button className="btn btn-ghost" onClick={() => setSelectedNode(null)}>
                <X size={14} />
              </button>
            </div>
            <div style={{ fontSize: 11, color: 'var(--text-faint)', textTransform: 'uppercase', marginBottom: 4 }}>
              {nodeCategory(selectedNode.node_type)} · {selectedNode.cloud_provider}
            </div>
            <div className="mono" style={{ fontSize: 12.5, marginBottom: 10, wordBreak: 'break-all' }}>
              {selectedNode.name}
            </div>
            <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>Risk score</div>
            <div style={{ fontSize: 22, fontFamily: 'var(--font-display)', fontWeight: 600, marginTop: 2 }}>
              {selectedNode.risk_score != null ? riskPercent(selectedNode.risk_score) : '—'}
            </div>
          </div>
        )}
      </div>

      <div className="card">
        <div className="card-header">
          <h3 className="card-title">
            <Activity size={15} color="var(--accent-trust)" />
            Risk heatmap
          </h3>
          <span style={{ fontSize: 11.5, color: 'var(--text-faint)' }}>By provider × resource type</span>
        </div>
        <RiskHeatmap />
      </div>
    </div>
  )
}
