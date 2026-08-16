import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import ContainmentModal from '../ContainmentModal'
import {
  triggerContainment,
  fetchAlert,
  fetchContainmentAction,
  resolveK8sBinding,
  resolveGcpBinding,
} from '../../services/api'

// CATALOG_BY_PROVIDER is keyed by cloud_provider and each backend engine
// only supports its own action set - these tests pin that mapping so a
// future edit can't silently show AWS-only actions for a k8s alert (or
// vice versa) without a test failing.
vi.mock('../../services/api', () => ({
  triggerContainment: vi.fn(),
  fetchAlert: vi.fn(),
  fetchContainmentAction: vi.fn(),
  resolveK8sBinding: vi.fn(),
  resolveGcpBinding: vi.fn(),
}))

const baseAlert = {
  id: 'alert-1',
  title: 'Privilege escalation via role chaining',
  cloud_provider: 'aws',
  resource_id: 'arn:aws:iam::403959680247:role/victim',
}

describe('ContainmentModal', () => {
  beforeEach(() => {
    triggerContainment.mockReset()
    fetchAlert.mockReset()
    fetchContainmentAction.mockReset()
    resolveK8sBinding.mockReset()
    resolveGcpBinding.mockReset()
  })

  it('renders nothing when alert is null', () => {
    const { container } = render(<ContainmentModal alert={null} onClose={vi.fn()} />)
    expect(container).toBeEmptyDOMElement()
  })

  it('shows the AWS action catalog for an aws alert', () => {
    render(<ContainmentModal alert={baseAlert} onClose={vi.fn()} />)
    expect(screen.getByText('Revoke credentials')).toBeInTheDocument()
    expect(screen.getByText('Rotate access keys')).toBeInTheDocument()
    expect(screen.getByText('Block IP')).toBeInTheDocument()
    // azure/k8s-only actions must not leak into the aws catalog
    expect(screen.queryByText('Remove role binding')).not.toBeInTheDocument()
    expect(screen.queryByText('Remove role assignment')).not.toBeInTheDocument()
  })

  it('shows only the k8s action for a k8s alert once the binding resolves', async () => {
    // k8s is in PROVIDERS_REQUIRING_RESOLUTION, so the modal calls
    // fetchAlert() then resolveK8sBinding() before it will render the
    // action catalog. Only K8S_ESCALATION_PRIMITIVE findings resolve.
    fetchAlert.mockResolvedValueOnce({
      id: 'alert-1',
      alert_type: 'K8S_ESCALATION_PRIMITIVE',
      source_node_id: 'sa-victim',
      raw_evidence: { metadata: { via_role: 'edit-role' } },
    })
    resolveK8sBinding.mockResolvedValueOnce({ target_resource: 'rolebinding-1' })

    render(
      <ContainmentModal
        alert={{ ...baseAlert, cloud_provider: 'k8s' }}
        onClose={vi.fn()}
      />
    )

    await waitFor(() => expect(screen.getByText('Remove role binding')).toBeInTheDocument())
    expect(screen.queryByText('Rotate access keys')).not.toBeInTheDocument()
    expect(resolveK8sBinding).toHaveBeenCalledWith('sa-victim', 'edit-role')
  })

  it('shows a blocked message when gcp resolution data is missing', async () => {
    // gcp is also in PROVIDERS_REQUIRING_RESOLUTION and now has a real
    // action catalog (Remove IAM binding), so it's no longer "unrecognized" -
    // the relevant edge case is missing source/target node data blocking
    // resolution, not an empty catalog.
    fetchAlert.mockResolvedValueOnce({
      id: 'alert-1',
      source_node_id: null,
      target_node_id: null,
    })

    render(
      <ContainmentModal
        alert={{ ...baseAlert, cloud_provider: 'gcp' }}
        onClose={vi.fn()}
      />
    )

    await waitFor(() =>
      expect(
        screen.getByText(/missing the identity\/service-account data/)
      ).toBeInTheDocument()
    )
    expect(screen.queryByText('Remove IAM binding')).not.toBeInTheDocument()
    expect(resolveGcpBinding).not.toHaveBeenCalled()
  })

  it('enables Execute immediately for a reversible action, no ack needed', () => {
    render(<ContainmentModal alert={baseAlert} onClose={vi.fn()} />)
    fireEvent.click(screen.getByLabelText(/Disable account/))
    expect(screen.getByRole('button', { name: /Execute action/ })).toBeEnabled()
  })

  it('keeps Execute disabled for an irreversible action until acknowledged', () => {
    render(<ContainmentModal alert={baseAlert} onClose={vi.fn()} />)
    fireEvent.click(screen.getByLabelText(/Revoke credentials/))
    const executeBtn = screen.getByRole('button', { name: /Execute action/ })
    expect(executeBtn).toBeDisabled()

    fireEvent.click(
      screen.getByText(/I understand this action cannot be automatically rolled back/)
    )
    expect(executeBtn).toBeEnabled()
  })

  it('calls triggerContainment with the right args and shows the done state', async () => {
    // /containment/trigger returns { action_id } and only queues the job -
    // the modal then polls fetchContainmentAction(action_id) until it sees
    // status "completed" or "failed" before showing the done state.
    triggerContainment.mockResolvedValueOnce({ action_id: 'action-1' })
    fetchContainmentAction.mockResolvedValueOnce({ status: 'completed' })
    const onExecuted = vi.fn()
    render(<ContainmentModal alert={baseAlert} onClose={vi.fn()} onExecuted={onExecuted} />)

    fireEvent.click(screen.getByLabelText(/Disable account/))
    fireEvent.click(screen.getByRole('button', { name: /Execute action/ }))

    await waitFor(() => expect(screen.getByText('Action executed')).toBeInTheDocument())

    expect(triggerContainment).toHaveBeenCalledWith(
      'DISABLE_ACCOUNT',
      'aws',
      'arn:aws:iam::403959680247:role/victim',
      'alert-1'
    )
    expect(fetchContainmentAction).toHaveBeenCalledWith('action-1')
    expect(onExecuted).toHaveBeenCalled()
  })

  it('shows the error state and allows retry when execution fails', async () => {
    triggerContainment.mockRejectedValueOnce(new Error('boom'))
    render(<ContainmentModal alert={baseAlert} onClose={vi.fn()} />)

    fireEvent.click(screen.getByLabelText(/Disable account/))
    fireEvent.click(screen.getByRole('button', { name: /Execute action/ }))

    await waitFor(() => expect(screen.getByText('Execution failed')).toBeInTheDocument())

    fireEvent.click(screen.getByRole('button', { name: /Back/ }))
    expect(screen.getByRole('button', { name: /Execute action/ })).toBeInTheDocument()
  })

  it('calls onClose when the close button is clicked', () => {
    const onClose = vi.fn()
    render(<ContainmentModal alert={baseAlert} onClose={onClose} />)
    fireEvent.click(screen.getByRole('button', { name: /Cancel/ }))
    expect(onClose).toHaveBeenCalled()
  })
})