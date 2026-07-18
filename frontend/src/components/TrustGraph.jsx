import { useEffect, useMemo, useState, useCallback } from 'react'
import ReactFlow, {
  Background,
  Controls,
  MiniMap,
  Handle,
  Position,
  MarkerType,
} from 'reactflow'
import 'reactflow/dist/style.css'
import { ShieldAlert, KeyRound, Boxes, Users, Cpu } from 'lucide-react'
import { fetchGraph } from '../services/api'

const RISK_COLOR = (score) => {
  if (score >= 80) return 'var(--risk-critical)'
  if (score >= 55) return 'var(--risk-high)'
  if (score >= 30) return 'var(--risk-medium)'
  return 'var(--risk-low)'
}

const TYPE_ICON = {
  Identity: Users,
  Role: KeyRound,
  Policy: ShieldAlert,
  Resource: Boxes,
  ServiceAccount: Cpu,
}

function TrustNode({ data, selected }) {
  const Icon = TYPE_ICON[data.type] || Boxes
  const color = RISK_COLOR(data.risk_score ?? 0)
  return (
    <div
      style={{
        background: 'var(--bg-elevated)',
        border: `1.5px solid ${selected ? 'var(--accent-trust)' : color}`,
        borderRadius: 10,
        padding: '8px 12px',
        minWidth: 150,
        boxShadow: selected ? '0 0 0 3px var(--accent-trust-dim)' : 'none',
        cursor: 'pointer',
      }}
    >
      <Handle type="target" position={Position.Top} style={{ background: color, width: 7, height: 7 }} />
      <div style={{ display: 'flex', alignItems: 'center', gap: 7 }}>
        <Icon size={13} color={color} />
        <span style={{ fontSize: 11, color: 'var(--text-faint)', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
          {data.type}
        </span>
      </div>
      <div className="mono" style={{ marginTop: 4, color: 'var(--text-primary)', fontSize: 12, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
        {data.label}
      </div>
      <div style={{ marginTop: 5, height: 3, borderRadius: 2, background: 'var(--border)', overflow: 'hidden' }}>
        <div style={{ width: `${data.risk_score ?? 0}%`, height: '100%', background: color }} />
      </div>
      <Handle type="source" position={Position.Bottom} style={{ background: color, width: 7, height: 7 }} />
    </div>
  )
}

const nodeTypes = { trust: TrustNode }

function radialLayout(nodes) {
  const groups = {}
  nodes.forEach((n) => {
    groups[n.type] = groups[n.type] || []
    groups[n.type].push(n)
  })
  const types = Object.keys(groups)
  const positioned = {}
  const ringGap = 220
  types.forEach((type, ringIndex) => {
    const ringNodes = groups[type]
    const radius = 140 + ringIndex * ringGap
    ringNodes.forEach((n, i) => {
      const angle = (2 * Math.PI * i) / Math.max(ringNodes.length, 1)
      positioned[n.id] = {
        x: radius * Math.cos(angle) + radius + ringIndex * 40,
        y: radius * Math.sin(angle) + radius,
      }
    })
  })
  return positioned
}

const EDGE_COLOR = {
  TRUSTS: 'var(--accent-trust)',
  ASSUMES: 'var(--risk-high)',
  GRANTS: 'var(--risk-low)',
  ATTACHED_TO: 'var(--text-faint)',
  BINDS: 'var(--risk-medium)',
}

export default function TrustGraph({ filters = {}, highlightPath = [], onNodeSelect }) {
  const [rawNodes, setRawNodes] = useState([])
  const [rawEdges, setRawEdges] = useState([])
  const [status, setStatus] = useState('loading')

  const load = useCallback(() => {
    setStatus('loading')
    fetchGraph(filters)
      .then((data) => {
        setRawNodes(data.nodes || [])
        setRawEdges(data.edges || [])
        setStatus((data.nodes || []).length ? 'ready' : 'empty')
      })
      .catch(() => setStatus('error'))
  }, [JSON.stringify(filters)])

  useEffect(() => {
    load()
  }, [load])

  const positions = useMemo(() => radialLayout(rawNodes), [rawNodes])

  const flowNodes = useMemo(
    () =>
      rawNodes.map((n) => ({
        id: n.id,
        type: 'trust',
        position: positions[n.id] || { x: 0, y: 0 },
        data: n,
      })),
    [rawNodes, positions]
  )

  const flowEdges = useMemo(
    () =>
      rawEdges.map((e) => {
        const isHighlighted =
          highlightPath.length > 1 &&
          highlightPath.some((id, idx) => id === e.source && highlightPath[idx + 1] === e.target)
        return {
          id: e.id,
          source: e.source,
          target: e.target,
          label: e.type,
          animated: isHighlighted,
          style: {
            stroke: isHighlighted ? 'var(--risk-critical)' : EDGE_COLOR[e.type] || 'var(--border-bright)',
            strokeWidth: isHighlighted ? 2.5 : 1.2,
          },
          labelStyle: { fill: 'var(--text-faint)', fontSize: 10 },
          markerEnd: { type: MarkerType.ArrowClosed, color: isHighlighted ? 'var(--risk-critical)' : EDGE_COLOR[e.type] || 'var(--border-bright)' },
        }
      }),
    [rawEdges, highlightPath]
  )

  if (status === 'loading') {
    return <div className="skeleton" style={{ height: 480, width: '100%' }} />
  }

  if (status === 'error') {
    return (
      <div className="empty-state" style={{ height: 480 }}>
        <ShieldAlert size={28} color="var(--risk-high)" />
        <div className="empty-state-title">Couldn't load the trust graph</div>
        <div>Check that the backend is running and reachable.</div>
        <button className="btn" onClick={load}>Retry</button>
      </div>
    )
  }

  if (status === 'empty') {
    return (
      <div className="empty-state" style={{ height: 480 }}>
        <Boxes size={28} color="var(--text-faint)" />
        <div className="empty-state-title">No graph data yet</div>
        <div>Run a scan from Settings to populate the trust graph.</div>
      </div>
    )
  }

  return (
    <div style={{ height: 480, width: '100%', borderRadius: 'var(--radius-md)', overflow: 'hidden', border: '1px solid var(--border)' }}>
      <ReactFlow
        nodes={flowNodes}
        edges={flowEdges}
        nodeTypes={nodeTypes}
        onNodeClick={(_, node) => onNodeSelect && onNodeSelect(node.data)}
        fitView
        proOptions={{ hideAttribution: true }}
        defaultEdgeOptions={{ type: 'default' }}
      >
        <Background color="var(--border)" gap={22} size={1} />
        <Controls showInteractive={false} />
        <MiniMap
          pannable
          zoomable
          style={{ background: 'var(--bg-elevated)' }}
          maskColor="rgba(10,13,18,0.7)"
          nodeColor={(n) => RISK_COLOR(n.data?.risk_score ?? 0)}
        />
      </ReactFlow>
    </div>
  )
}
