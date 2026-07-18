import { useState } from 'react'
import { Network } from 'lucide-react'
import AlertPanel from '../components/AlertPanel'
import PathDetail from '../components/PathDetail'
import ContainmentModal from '../components/ContainmentModal'
import TrustGraph from '../components/TrustGraph'

export default function Alerts() {
  const [selectedAlert, setSelectedAlert] = useState(null)
  const [highlightPath, setHighlightPath] = useState([])
  const [containmentAlert, setContainmentAlert] = useState(null)
  const [refreshKey, setRefreshKey] = useState(0)

  function handleSelectAlert(alert) {
    setSelectedAlert(alert)
  }

  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title">Alerts</h1>
          <p className="page-subtitle">Triage findings, inspect escalation paths, and trigger containment.</p>
        </div>
        {selectedAlert && (
          <button className="btn btn-danger" onClick={() => setContainmentAlert(selectedAlert)}>
            Contain this finding
          </button>
        )}
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1.3fr 1fr', gap: 16, marginBottom: 20, alignItems: 'flex-start' }}>
        <AlertPanel key={refreshKey} onSelectAlert={handleSelectAlert} selectedAlertId={selectedAlert?.id} />
        <PathDetail alertId={selectedAlert?.id} onHighlightPath={setHighlightPath} />
      </div>

      {highlightPath.length > 1 && (
        <div className="card">
          <div className="card-header">
            <h3 className="card-title">
              <Network size={15} color="var(--accent-trust)" />
              Path highlighted in graph
            </h3>
          </div>
          <TrustGraph highlightPath={highlightPath} />
        </div>
      )}

      {containmentAlert && (
        <ContainmentModal
          alert={containmentAlert}
          onClose={() => setContainmentAlert(null)}
          onExecuted={() => setRefreshKey((k) => k + 1)}
        />
      )}
    </div>
  )
}
