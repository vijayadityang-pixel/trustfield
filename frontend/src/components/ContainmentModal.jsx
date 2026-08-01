import { useEffect, useState } from 'react'
import { X, ShieldOff, AlertTriangle, CheckCircle2, Loader2, Info } from 'lucide-react'
import { triggerContainment, fetchAlert, resolveK8sBinding, resolveGcpBinding, fetchContainmentAction } from '../services/api'

// Action types must match exactly what each cloud engine's execute()
// dispatch table accepts (containment/{aws,azure,k8s,gcp}_response.py).
// Catalog is keyed by cloud_provider since each backend engine only
// supports its own action set - showing AWS-only actions for a k8s
// alert (or vice versa) would let a user select something that fails
// immediately on execute().
const CATALOG_BY_PROVIDER = {
  aws: [
    {
      type: 'REVOKE_CREDENTIALS',
      label: 'Revoke credentials',
      description: 'Delete access keys (user) or revoke active sessions (role).',
      reversible: false,
    },
    {
      type: 'DISABLE_ACCOUNT',
      label: 'Disable account',
      description: 'Remove console login and deactivate access keys.',
      reversible: true,
    },
    {
      type: 'ATTACH_DENY_ALL_POLICY',
      label: 'Attach deny-all policy',
      description: 'Lock out the identity immediately while preserving it for investigation.',
      reversible: true,
    },
    {
      type: 'ISOLATE_RESOURCE',
      label: 'Isolate EC2 instance',
      description: 'Move the instance to an empty isolation security group.',
      reversible: true,
    },
    {
      type: 'ROTATE_KEYS',
      label: 'Rotate access keys',
      description: 'Create a new access key and deactivate all existing keys.',
      reversible: false,
    },
    {
      type: 'BLOCK_IP',
      label: 'Block IP',
      description: 'Add a deny rule for this IP to the default VPC network ACL.',
      reversible: true,
    },
  ],
  azure: [
    {
      type: 'DISABLE_ACCOUNT',
      label: 'Disable account',
      description: 'Disable the Azure AD user or service principal and revoke tokens.',
      reversible: true,
    },
    {
      type: 'REVOKE_CREDENTIALS',
      label: 'Revoke credentials',
      description: 'Revoke all sign-in sessions and refresh tokens for this user.',
      reversible: false,
    },
    {
      type: 'REMOVE_ROLE_ASSIGNMENT',
      label: 'Remove role assignment',
      description: 'Delete a specific RBAC role assignment.',
      reversible: false,
    },
    {
      type: 'DISABLE_SERVICE_PRINCIPAL',
      label: 'Disable service principal',
      description: 'Disable the Azure AD service principal.',
      reversible: true,
    },
  ],
  k8s: [
    {
      type: 'REMOVE_ROLE_BINDING',
      label: 'Remove role binding',
      description: 'Delete the RoleBinding or ClusterRoleBinding granting this access.',
      reversible: false,
    },
  ],
  gcp: [
    {
      type: 'REMOVE_IAM_BINDING',
      label: 'Remove IAM binding',
      description: 'Revoke the specific role binding granting impersonation access to this service account.',
      reversible: true,
    },
  ],
}

// Providers whose actions operate on a specific edge/binding rather than
// a whole account, and therefore need a resolved target_resource fetched
// from the backend before execution can work - alert.resource_id alone
// is never enough for these (it's a Role or Identity node ID, not a
// binding ID). AWS/Azure actions are account/resource-scoped and can use
// alert.resource_id directly.
const PROVIDERS_REQUIRING_RESOLUTION = new Set(['k8s', 'gcp'])

// /containment/trigger only queues a background task and returns
// immediately with status "pending" - it does NOT wait for the real
// setIamPolicy/kubectl/boto3 call to finish. Without polling here, the
// UI would show "Action executed" success even when the underlying
// action later fails (confirmed live: a real GCP 403 PERMISSION_DENIED
// still showed a success message before this fix).
async function pollContainmentAction(actionId, { intervalMs = 800, timeoutMs = 15000 } = {}) {
  const start = Date.now()
  while (Date.now() - start < timeoutMs) {
    const action = await fetchContainmentAction(actionId)
    if (action.status === 'completed' || action.status === 'failed') return action
    await new Promise((r) => setTimeout(r, intervalMs))
  }
  throw new Error('Timed out waiting for containment action to finish.')
}

export default function ContainmentModal({ alert, onClose, onExecuted }) {
  const [status, setStatus] = useState('ready') // ready | confirming | executing | done | exec_error
  const [selected, setSelected] = useState(null)
  const [ackIrreversible, setAckIrreversible] = useState(false)
  const [execError, setExecError] = useState(null)

  // resolveState.status: 'idle' | 'resolving' | 'resolved' | 'unsupported' | 'error'
  const [resolveState, setResolveState] = useState({ status: 'idle', targetResource: null, message: null })

  useEffect(() => {
    if (!alert) return
    setStatus('ready')
    setSelected(null)
    setAckIrreversible(false)
    setExecError(null)
    setResolveState({ status: 'idle', targetResource: null, message: null })

    const provider = (alert.cloud_provider || '').toLowerCase()
    if (!PROVIDERS_REQUIRING_RESOLUTION.has(provider)) return

    let cancelled = false
    setResolveState({ status: 'resolving', targetResource: null, message: null })

    // Fetch the full alert rather than trusting the `alert` prop, since
    // list-view callers (AlertPanel) may hand over a row object from a
    // slimmer response shape. raw_evidence/source_node_id/target_node_id
    // are needed here regardless of what the caller already had.
    fetchAlert(alert.id)
      .then((full) => {
        if (cancelled) return null

        if (provider === 'gcp') {
          if (!full.source_node_id || !full.target_node_id) {
            setResolveState({
              status: 'unsupported',
              targetResource: null,
              message: 'This alert is missing the identity/service-account data needed to resolve the IAM binding.',
            })
            return null
          }
          return resolveGcpBinding(full.source_node_id, full.target_node_id)
        }

        // k8s: only k8s_escalation_primitive findings resolve to a single
        // RoleBinding/ClusterRoleBinding. privilege_escalation/role_chaining
        // findings on k8s are multi-hop chains with no single binding to
        // remove - offering REMOVE_ROLE_BINDING for those would always fail
        // on execute (see Week 8 punch list).
        if (full.alert_type !== 'K8S_ESCALATION_PRIMITIVE') {
          setResolveState({
            status: 'unsupported',
            targetResource: null,
            message: 'This finding spans a multi-hop chain with no single role binding to remove. Contain the source identity through another workflow, or resolve it manually in the cluster.',
          })
          return null
        }

        const viaRole = full.raw_evidence?.metadata?.via_role
        if (!full.source_node_id || !viaRole) {
          setResolveState({
            status: 'unsupported',
            targetResource: null,
            message: 'This alert is missing the role-binding data needed to resolve a containment target.',
          })
          return null
        }
        return resolveK8sBinding(full.source_node_id, viaRole)
      })
      .then((result) => {
        if (cancelled || !result) return
        setResolveState({ status: 'resolved', targetResource: result.target_resource, message: null })
      })
      .catch((err) => {
        if (cancelled) return
        setResolveState({
          status: 'error',
          targetResource: null,
          message: err.message || 'Failed to resolve a containment target for this alert.',
        })
      })

    return () => {
      cancelled = true
    }
  }, [alert])

  if (!alert) return null

  const provider = (alert.cloud_provider || '').toLowerCase()
  const actions = CATALOG_BY_PROVIDER[provider] || []
  const needsResolution = PROVIDERS_REQUIRING_RESOLUTION.has(provider)

  async function handleExecute() {
    setStatus('executing')
    setExecError(null)
    try {
      const targetResource = needsResolution ? resolveState.targetResource : alert.resource_id
      const { action_id } = await triggerContainment(
        selected.type,
        alert.cloud_provider,
        targetResource,
        alert.id
      )
      const finalAction = await pollContainmentAction(action_id)
      if (finalAction.status === 'failed') {
        setExecError(finalAction.error_message || 'The action failed. Check backend logs for details.')
        setStatus('exec_error')
        return
      }
      setStatus('done')
      onExecuted && onExecuted()
    } catch (err) {
      setExecError(err.message || null)
      setStatus('exec_error')
    }
  }

  const canShowActions =
    !needsResolution || resolveState.status === 'resolved'
  const isBlockedByResolution =
    needsResolution && (resolveState.status === 'unsupported' || resolveState.status === 'error')
  const isResolving = needsResolution && resolveState.status === 'resolving'

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
            {isResolving && (
              <div className="empty-state" style={{ padding: '20px 0' }}>
                <Loader2 size={20} style={{ animation: 'spin 1s linear infinite' }} />
                <div className="empty-state-title">Resolving containment target…</div>
              </div>
            )}

            {isBlockedByResolution && (
              <div
                style={{
                  display: 'flex',
                  gap: 10,
                  padding: '10px 12px',
                  borderRadius: 'var(--radius-md)',
                  border: '1px solid var(--border)',
                  background: 'var(--bg-elevated)',
                  fontSize: 12.5,
                  color: 'var(--text-muted)',
                  marginBottom: 16,
                }}
              >
                <Info size={15} style={{ flexShrink: 0, marginTop: 1 }} />
                <div>{resolveState.message}</div>
              </div>
            )}

            {canShowActions && (
              <>
                {actions.length === 0 && (
                  <div style={{ fontSize: 12.5, color: 'var(--text-muted)', marginBottom: 16 }}>
                    No containment actions are available for provider "{alert.cloud_provider || 'unknown'}".
                  </div>
                )}

                <div style={{ display: 'flex', flexDirection: 'column', gap: 8, marginBottom: 16 }}>
                  {actions.map((action) => (
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
              </>
            )}

            <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end' }}>
              <button className="btn btn-ghost" onClick={onClose}>Cancel</button>
              {canShowActions && (
                <button
                  className="btn btn-danger"
                  disabled={!selected || (!selected.reversible && !ackIrreversible)}
                  onClick={handleExecute}
                >
                  Execute action
                </button>
              )}
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
            <div>{execError || "The action wasn't applied. Check backend logs and try again."}</div>
            <button className="btn" onClick={() => setStatus('ready')} style={{ marginTop: 8 }}>Back</button>
          </div>
        )}
      </div>
      <style>{`@keyframes spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }`}</style>
    </div>
  )
}