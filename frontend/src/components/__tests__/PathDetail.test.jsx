import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import PathDetail from '../PathDetail'
import { fetchAlert } from '../../services/api'

vi.mock('../../services/api', () => ({
  fetchAlert: vi.fn(),
}))

describe('PathDetail', () => {
  beforeEach(() => {
    fetchAlert.mockReset()
  })

  it('shows the idle placeholder when no alertId is given', () => {
    render(<PathDetail alertId={null} />)
    expect(screen.getByText('Select an alert')).toBeInTheDocument()
    expect(fetchAlert).not.toHaveBeenCalled()
  })

  it('renders string hops with arrows between them and the risk badge', async () => {
    fetchAlert.mockResolvedValueOnce({
      escalation_path: ['user:a', 'role:mid', 'role:admin'],
      risk_score: 72,
    })
    render(<PathDetail alertId="alert-1" />)

    await waitFor(() => expect(screen.getByText('user:a')).toBeInTheDocument())
    expect(screen.getByText('role:mid')).toBeInTheDocument()
    expect(screen.getByText('role:admin')).toBeInTheDocument()
    expect(screen.getByText('risk 72')).toBeInTheDocument()
  })

  it('renders object hops using label/type when the path is object-shaped', async () => {
    fetchAlert.mockResolvedValueOnce({
      escalation_path: [
        { id: 'sa:victim', label: 'victim-sa', type: 'ServiceAccount' },
        { id: 'role:admin', label: 'admin-role', type: 'ClusterRole' },
      ],
      risk_score: 55,
    })
    render(<PathDetail alertId="alert-1" />)

    await waitFor(() => expect(screen.getByText('victim-sa')).toBeInTheDocument())
    expect(screen.getByText('admin-role')).toBeInTheDocument()
    expect(screen.getByText('ServiceAccount')).toBeInTheDocument()
    expect(screen.getByText('ClusterRole')).toBeInTheDocument()
  })

  it('calls onHighlightPath with the hop ids once loaded', async () => {
    fetchAlert.mockResolvedValueOnce({
      escalation_path: ['user:a', { id: 'role:admin', label: 'admin' }],
      risk_score: 40,
    })
    const onHighlightPath = vi.fn()
    render(<PathDetail alertId="alert-1" onHighlightPath={onHighlightPath} />)

    await waitFor(() =>
      expect(onHighlightPath).toHaveBeenCalledWith(['user:a', 'role:admin'])
    )
  })

  it('shows a message when the alert has no escalation path yet', async () => {
    fetchAlert.mockResolvedValueOnce({ escalation_path: [], risk_score: null })
    render(<PathDetail alertId="alert-1" />)

    await waitFor(() =>
      expect(screen.getByText(/isn't tied to a multi-hop path yet/)).toBeInTheDocument()
    )
  })

  it('shows the error state when the fetch fails', async () => {
    fetchAlert.mockRejectedValueOnce(new Error('network error'))
    render(<PathDetail alertId="alert-1" />)

    await waitFor(() =>
      expect(screen.getByText("Couldn't load path detail")).toBeInTheDocument()
    )
  })
})