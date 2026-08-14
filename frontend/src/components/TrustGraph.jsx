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
import dagre from 'dagre'
import { ShieldAlert, KeyRound, Boxes, Users, Cpu } from 'lucide-react'
import { fetchGraph } from '../services/api'
import { riskPercent, riskColor } from '../utils/risk'
import { nodeCategory } from '../utils/nodeTypes'

const TYPE_ICON = {
  Identity: Users,
  Role: KeyRound,
  Policy: ShieldAlert,
  Resource: Boxes,
  ServiceAccount: Cpu,
}

// Fixed accent per type category, independent of risk - lets you tell "what
// kind of node is this" apart from "how risky is it" at a glance.
const TYPE_ACCENT = {
  Identity: '#4fd1c5',
  Role: '#8b8ff5',
  ServiceAccount: '#f5a623',
  Policy: '#f2836a',
  Resource: '#5b6679',
}

function TrustNode({ data, selected }) {
  const category = nodeCategory(data.node_type)
  const Icon = TYPE_ICON[category] || Boxes
  const accent = TYPE_ACCENT[category] || TYPE_ACCENT.Resource
  const risk = riskColor(data.risk_score)
  const pct = riskPercent(data.risk_score)
  return (
    <div
      style={{
        background: 'var(--bg-elevated)',
        border: `1.5px solid ${selected ? 'var(--accent-trust)' : accent}`,
        borderRadius: 10,
        padding: '8px 12px',
        minWidth: 160,
        boxShadow: selected ? '0 0 0 3px var(--accent-trust-dim)' : 'none',
        cursor: 'pointer',
      }}
    >
      <Handle type="target" position={Position.Left} style={{ background: accent, width: 7, height: 7 }} />
      <div style={{ display: 'flex', alignItems: 'center', gap: 7 }}>
        <Icon size={13} color={accent} />
        <span style={{ fontSize: 11, color: 'var(--text-faint)', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
          {category}
        </span>
      </div>
      <div className="mono" style={{ marginTop: 4, color: 'var(--text-primary)', fontSize: 12, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
        {data.name}
      </div>
      <div style={{ marginTop: 5, height: 3, borderRadius: 2, background: 'var(--border)', overflow: 'hidden' }}>
        <div style={{ width: `${pct}%`, height: '100%', background: risk }} />
      </div>
      <Handle type="source" position={Position.Right} style={{ background: accent, width: 7, height: 7 }} />
    </div>
  )
}

const nodeTypes = { trust: TrustNode }

const NODE_WIDTH = 190
const NODE_HEIGHT = 66

function dagreLayout(nodes, edges) {
  const connectedIds = new Set()
  edges.forEach((e) => {
    connectedIds.add(e.source_id)
    connectedIds.add(e.target_id)
  })
  const connectedNodes = nodes.filter((n) => connectedIds.has(n.node_id))
  const isolatedNodes = nodes.filter((n) => !connectedIds.has(n.node_id))

  const g = new dagre.graphlib.Graph()
  g.setDefaultEdgeLabel(() => ({}))
  g.setGraph({ rankdir: 'LR', nodesep: 40, ranksep: 140 })

  connectedNodes.forEach((n) => {
    g.setNode(n.node_id, { width: NODE_WIDTH, height: NODE_HEIGHT })
  })
  edges.forEach((e) => {
    if (g.hasNode(e.source_id) && g.hasNode(e.target_id)) {
      g.setEdge(e.source_id, e.target_id)
    }
  })
  dagre.layout(g)

  const positions = {}
  let maxY = 0
  connectedNodes.forEach((n) => {
    const pos = g.node(n.node_id)
    positions[n.node_id] = pos ? { x: pos.x - NODE_WIDTH / 2, y: pos.y - NODE_HEIGHT / 2 } : { x: 0, y: 0 }
    if (pos) maxY = Math.max(maxY, pos.y)
  })

  // Nodes with no edges to anything else in the current view (the common
  // case - most identities/roles only link to a handful of others) get no
  // rank from dagre and would otherwise all collapse onto a single column.
  // Pack them into a roughly square grid instead, below the connected
  // layout, so the graph stays browsable at any node count.
  const gridCols = Math.max(1, Math.ceil(Math.sqrt(isolatedNodes.length)))
  const gridStartY = connectedNodes.length ? maxY + NODE_HEIGHT + 80 : 0
  isolatedNodes.forEach((n, i) => {
    const col = i % gridCols
    const row = Math.floor(i / gridCols)
    positions[n.node_id] = {
      x: col * (NODE_WIDTH + 40),
      y: gridStartY + row * (NODE_HEIGHT + 30),
    }
  })

  return positions
}

// Golden-angle spiral (phyllotaxis / sunflower spacing): plotting points at
// radius ~ sqrt(index) and angle = index * goldenAngle gives an even,
// non-overlapping spiral regardless of node count. Sorting by risk before
// assigning index means the highest-risk nodes always land nearest center -
// the density of the core is a real signal, not decoration.
const GOLDEN_ANGLE = Math.PI * (3 - Math.sqrt(5))
const GRAVITY_SPACING = 46

function gravityLayout(nodes) {
  if (!nodes.length) return {}
  const sorted = [...nodes].sort((a, b) => {
    const diff = (b.risk_score ?? 0) - (a.risk_score ?? 0)
    return diff !== 0 ? diff : String(a.node_id).localeCompare(String(b.node_id))
  })

  const positions = {}
  sorted.forEach((n, i) => {
    const radius = GRAVITY_SPACING * Math.sqrt(i + 0.5)
    const angle = i * GOLDEN_ANGLE
    positions[n.node_id] = {
      x: radius * Math.cos(angle) - NODE_WIDTH / 2,
      y: radius * Math.sin(angle) - NODE_HEIGHT / 2,
    }
  })
  return positions
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
  const [rfInstance, setRfInstance] = useState(null)
  const [layoutMode, setLayoutMode] = useState('grid')

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

  // `fitView` on <ReactFlow> only fits once, at first mount - but graph data
  // arrives asynchronously after that, so the initial fit locks onto an
  // empty/near-empty canvas and never re-fits once real nodes land. Refit
  // manually whenever the node set actually changes.
  useEffect(() => {
    if (rfInstance && rawNodes.length) {
      rfInstance.fitView({ padding: 0.15, duration: 300 })
    }
  }, [rfInstance, rawNodes, layoutMode])

  const positions = useMemo(
    () => (layoutMode === 'gravity' ? gravityLayout(rawNodes) : dagreLayout(rawNodes, rawEdges)),
    [rawNodes, rawEdges, layoutMode]
  )

  const flowNodes = useMemo(
    () =>
      rawNodes.map((n) => ({
        id: n.node_id,
        type: 'trust',
        position: positions[n.node_id] || { x: 0, y: 0 },
        data: n,
      })),
    [rawNodes, positions]
  )

  const flowEdges = useMemo(
    () =>
      rawEdges.map((e, idx) => {
        const isHighlighted =
          highlightPath.length > 1 &&
          highlightPath.some((id, i) => id === e.source_id && highlightPath[i + 1] === e.target_id)
        return {
          id: `${e.source_id}-${e.relationship_type}-${e.target_id}-${idx}`,
          source: e.source_id,
          target: e.target_id,
          label: e.relationship_type,
          animated: isHighlighted,
          style: {
            stroke: isHighlighted ? 'var(--risk-critical)' : EDGE_COLOR[e.relationship_type] || 'var(--border-bright)',
            strokeWidth: isHighlighted ? 2.5 : 1.2,
          },
          labelStyle: { fill: 'var(--text-faint)', fontSize: 10 },
          markerEnd: {
            type: MarkerType.ArrowClosed,
            color: isHighlighted ? 'var(--risk-critical)' : EDGE_COLOR[e.relationship_type] || 'var(--border-bright)',
          },
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
    <div>
      <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 6, marginBottom: 8 }}>
        <button
          className="btn btn-ghost"
          style={layoutMode === 'grid' ? { color: 'var(--accent-trust)', background: 'var(--bg-hover)' } : undefined}
          onClick={() => setLayoutMode('grid')}
        >
          Grid
        </button>
        <button
          className="btn btn-ghost"
          style={layoutMode === 'gravity' ? { color: 'var(--accent-trust)', background: 'var(--bg-hover)' } : undefined}
          onClick={() => setLayoutMode('gravity')}
        >
          Gravity well
        </button>
      </div>
      <div style={{ height: 480, width: '100%', borderRadius: 'var(--radius-md)', overflow: 'hidden', border: '1px solid var(--border)' }}>
        <ReactFlow
          nodes={flowNodes}
          edges={flowEdges}
          nodeTypes={nodeTypes}
          onNodeClick={(_, node) => onNodeSelect && onNodeSelect(node.data)}
          onInit={setRfInstance}
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
            nodeColor={(n) => riskColor(n.data?.risk_score)}
          />
        </ReactFlow>
      </div>
    </div>
  )
}