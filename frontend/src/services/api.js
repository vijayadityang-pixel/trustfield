import axios from 'axios'

const baseURL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000/api/v1'

export const client = axios.create({
  baseURL,
  timeout: 15000,
})

client.interceptors.request.use((config) => {
  const token = localStorage.getItem('trustfield_token')
  if (token) {
    config.headers.Authorization = `Bearer ${token}`
  }
  return config
})

client.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      localStorage.removeItem('trustfield_token')
      if (window.location.pathname !== '/login') {
        window.location.href = '/login'
      }
    }
    const detail = error.response?.data?.detail || error.message || 'Request failed'
    return Promise.reject(new Error(detail))
  }
)

/* ---------------------------------------------------------- */
/* Auth — routes_auth.py                                       */
/* ---------------------------------------------------------- */

export async function login(email, password) {
  const { data } = await client.post('/auth/login', { email, password })
  localStorage.setItem('trustfield_token', data.access_token)
  return data
}

export function logout() {
  localStorage.removeItem('trustfield_token')
}

export async function fetchCurrentUser() {
  const { data } = await client.get('/auth/me')
  return data
}

export function isAuthenticated() {
  return Boolean(localStorage.getItem('trustfield_token'))
}

/* ---------------------------------------------------------- */
/* Graph — routes_graph.py                                     */
/* ---------------------------------------------------------- */

export async function fetchGraph(filters = {}) {
  const { data } = await client.get('/graph/', { params: filters })
  return data
}

export async function fetchGraphStats(filters = {}) {
  const { data } = await client.get('/graph/stats', { params: filters })
  return data
}

export async function fetchNode(nodeId) {
  const { data } = await client.get(`/graph/nodes/${nodeId}`)
  return data
}

export async function searchNodes(query, filters = {}) {
  const { data } = await client.get('/graph/nodes/search', { params: { q: query, ...filters } })
  return data
}

export async function fetchEscalationPaths(filters = {}) {
  const { data } = await client.get('/graph/escalation-paths', { params: filters })
  return data
}

export async function fetchPathBetween(sourceNode, targetNode) {
  const { data } = await client.get(`/graph/escalation-paths/${sourceNode}/${targetNode}`)
  return data
}

export async function refreshGraph(cloudProvider) {
  const { data } = await client.post('/graph/refresh', null, {
    params: cloudProvider ? { cloud_provider: cloudProvider } : {},
  })
  return data
}

export async function fetchSubgraph(nodeId, depth = 2, direction = 'both') {
  const { data } = await client.get(`/graph/subgraph/${nodeId}`, { params: { depth, direction } })
  return data
}

export async function fetchRiskScores(filters = {}) {
  const { data } = await client.get('/graph/risk-scores', { params: filters })
  return data
}

/* ---------------------------------------------------------- */
/* Alerts — routes_alerts.py                                   */
/* ---------------------------------------------------------- */

export async function fetchAlerts(filters = {}) {
  const { data } = await client.get('/alerts/', { params: filters })
  return data
}

export async function fetchAlertSummary() {
  const { data } = await client.get('/alerts/summary')
  return data
}

export async function fetchAlert(alertId) {
  const { data } = await client.get(`/alerts/${alertId}`)
  return data
}

export async function updateAlertStatus(alertId, status, analystNotes, assignedTo) {
  const { data } = await client.patch(`/alerts/${alertId}`, {
    status,
    analyst_notes: analystNotes,
    assigned_to: assignedTo,
  })
  return data
}

export async function deleteAlert(alertId) {
  await client.delete(`/alerts/${alertId}`)
}

export async function escalateAlert(alertId) {
  const { data } = await client.post(`/alerts/${alertId}/escalate`)
  return data
}

/* ---------------------------------------------------------- */
/* Scan — routes_scan.py                                       */
/* ---------------------------------------------------------- */

export async function runScan(providers, reason) {
  const { data } = await client.post('/scan/', { providers, reason })
  return data
}

export async function fetchScanJobs(filters = {}) {
  const { data } = await client.get('/scan/', { params: filters })
  return data
}

export async function fetchLatestScan(cloudProvider) {
  const { data } = await client.get('/scan/latest', {
    params: cloudProvider ? { cloud_provider: cloudProvider } : {},
  })
  return data
}

export async function fetchScanJob(jobId) {
  const { data } = await client.get(`/scan/${jobId}`)
  return data
}

export async function cancelScan(jobId) {
  await client.delete(`/scan/${jobId}`)
}

export async function fetchScanResults(jobId) {
  const { data } = await client.get(`/scan/${jobId}/results`)
  return data
}

/* ---------------------------------------------------------- */
/* Containment — routes_containment.py                         */
/* ---------------------------------------------------------- */

export async function triggerContainment(actionType, cloudProvider, targetResource, alertId, reason) {
  const { data } = await client.post('/containment/trigger', {
    action_type: actionType,
    cloud_provider: cloudProvider,
    target_resource: targetResource,
    alert_id: alertId,
    reason,
  })
  return data
}

export async function fetchContainmentActions(filters = {}) {
  const { data } = await client.get('/containment/actions', { params: filters })
  return data
}

export async function fetchContainmentAction(actionId) {
  const { data } = await client.get(`/containment/actions/${actionId}`)
  return data
}

export async function rollbackContainmentAction(actionId) {
  const { data } = await client.post(`/containment/actions/${actionId}/rollback`)
  return data
}

export async function fetchPlaybooks() {
  const { data } = await client.get('/containment/playbooks')
  return data
}

export async function runPlaybook(playbookId, alertId) {
  const { data } = await client.post(`/containment/playbooks/${playbookId}/run`, null, {
    params: { alert_id: alertId },
  })
  return data
}
export async function resolveK8sBinding(identityId, viaRole) {
  const { data } = await client.get('/containment/resolve/k8s-binding', {
    params: { identity_id: identityId, via_role: viaRole },
  })
  return data
}

export async function resolveGcpBinding(identityId, targetSaId) {
  const { data } = await client.get('/containment/resolve/gcp-binding', {
    params: { identity_id: identityId, target_sa_id: targetSaId },
  })
  return data
}