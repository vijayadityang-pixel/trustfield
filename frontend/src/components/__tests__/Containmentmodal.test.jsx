import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import ContainmentModal from '../ContainmentModal'
import { triggerContainment } from '../../services/api'

// CATALOG_BY_PROVIDER is keyed by cloud_provider and each backend engine
// only supports its own action set - these tests pin that mapping so a
// future edit can't silently show AWS-only actions for a k8s alert (or
// vice versa) without a test failing.
vi.mock('../../services/api', () => ({
  triggerContainment: vi.fn(),
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

  it('shows only the k8s action for a k8s alert', () => {
    render(
      <ContainmentModal
        alert={{ ...baseAlert, cloud_provider: 'k8s' }}
        onClose={vi.fn()}
      />
    )
    expect(screen.getByText('Remove role binding')).toBeInTheDocument()
    expect(screen.queryByText('Rotate access keys')).not.toBeInTheDocument()
  })

  it('shows a fallback message for an unrecognized provider', () => {
    render(
      <ContainmentModal
        alert={{ ...baseAlert, cloud_provider: 'gcp' }}
        onClose={vi.fn()}
      />
    )
    expect(
      screen.getByText(/No containment actions are available for provider "gcp"/)
    ).toBeInTheDocument()
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
    triggerContainment.mockResolvedValueOnce({})
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