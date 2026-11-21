import { cleanup, fireEvent, screen, within } from '@testing-library/react'
import { useState } from 'react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { json, renderAs } from '../../test-utils'
import { stagesResponse } from './fixture'
import type { StageName, StagesResponse } from './ui'
import { WorkflowBuilder } from './WorkflowBuilder'

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
})

function mockStages(data: StagesResponse = stagesResponse) {
  vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
    if (String(input).startsWith('/api/stages')) return json(data)
    return json({})
  })
}

function Harness({
  initial = ['nmap', 'httpx', 'nuclei'],
  disabled = false,
  aggressiveAllowed = true,
  onChange,
}: {
  initial?: StageName[]
  disabled?: boolean
  aggressiveAllowed?: boolean
  onChange?: (next: StageName[]) => void
}) {
  const [stages, setStages] = useState<StageName[]>(initial)
  return (
    <>
      <WorkflowBuilder
        value={stages}
        onChange={(next) => {
          setStages(next)
          onChange?.(next)
        }}
        disabled={disabled}
        aggressiveAllowed={aggressiveAllowed}
      />
      <output data-testid="value">{stages.join(',')}</output>
    </>
  )
}

const withSomeAggressiveAvailable: StagesResponse = {
  ...stagesResponse,
  stages: stagesResponse.stages.map((s) =>
    s.name === 'nuclei_active' || s.name === 'nikto' ? { ...s, available: true } : s,
  ),
}

describe('WorkflowBuilder', () => {
  it('locks nmap on and cascades dependency disable when httpx is turned off', async () => {
    mockStages()
    renderAs('admin', <Harness />)

    const nmap = await screen.findByRole('switch', { name: 'nmap' })
    const httpx = screen.getByRole('switch', { name: 'httpx' })
    const nuclei = screen.getByRole('switch', { name: 'nuclei' })

    expect(nmap).toBeChecked()
    expect(nmap).toBeDisabled()
    expect(httpx).toBeChecked()
    expect(httpx).toBeEnabled()
    expect(nuclei).toBeChecked()
    expect(nuclei).toBeEnabled()

    // Turning httpx off cascades to nuclei and disables it with "needs httpx".
    fireEvent.click(httpx)
    expect(httpx).not.toBeChecked()
    expect(nuclei).not.toBeChecked()
    expect(nuclei).toBeDisabled()
    expect(screen.getByText('needs httpx')).toBeInTheDocument()
    expect(screen.getByTestId('value')).toHaveTextContent('nmap')

    // Turning httpx back on re-enables nuclei without automatically turning it on.
    fireEvent.click(httpx)
    expect(httpx).toBeChecked()
    expect(nuclei).toBeEnabled()
    expect(nuclei).not.toBeChecked()
    expect(screen.queryByText('needs httpx')).not.toBeInTheDocument()
    expect(screen.getByTestId('value')).toHaveTextContent('nmap,httpx')
  })

  it('marks unavailable stages disabled with "Not available" and disables Aggressive preset', async () => {
    mockStages()
    renderAs('admin', <Harness />)

    const aggGroup = await screen.findByRole('group', { name: 'Aggressive' })
    for (const name of ['nuclei_active', 'nikto', 'wpscan', 'zap']) {
      const sw = within(aggGroup).getByRole('switch', { name })
      expect(sw).toBeDisabled()
      expect(sw).not.toBeChecked()
    }
    expect(within(aggGroup).getAllByText('Not available')).toHaveLength(4)
    expect(screen.getByRole('button', { name: 'Aggressive' })).toBeDisabled()
    expect(screen.getByRole('button', { name: 'Default' })).toBeEnabled()
  })

  it('applies Default and Aggressive presets using only available stages', async () => {
    mockStages(withSomeAggressiveAvailable)
    renderAs('admin', <Harness initial={['nmap']} />)

    const defaultBtn = await screen.findByRole('button', { name: 'Default' })
    const aggressiveBtn = screen.getByRole('button', { name: 'Aggressive' })
    expect(aggressiveBtn).toBeEnabled()

    // Aggressive preset enables only available stages (nuclei_active, nikto; not unavailable wpscan/zap).
    fireEvent.click(aggressiveBtn)
    expect(screen.getByTestId('value')).toHaveTextContent('nmap,httpx,nuclei,nuclei_active,nikto')
    expect(screen.getByRole('switch', { name: 'nuclei_active' })).toBeChecked()
    expect(screen.getByRole('switch', { name: 'nikto' })).toBeChecked()
    expect(screen.getByRole('switch', { name: 'wpscan' })).toBeDisabled()
    expect(screen.getByRole('switch', { name: 'zap' })).toBeDisabled()

    // Turning httpx off also cascades off available aggressive stages that need httpx.
    fireEvent.click(screen.getByRole('switch', { name: 'httpx' }))
    expect(screen.getByTestId('value')).toHaveTextContent('nmap')
    expect(screen.getByRole('switch', { name: 'nuclei_active' })).toBeDisabled()
    expect(screen.getByRole('switch', { name: 'nikto' })).toBeDisabled()

    // Default preset restores nmap, httpx, nuclei.
    fireEvent.click(defaultBtn)
    expect(screen.getByTestId('value')).toHaveTextContent('nmap,httpx,nuclei')
  })

  it('disables aggressive cards and Aggressive preset when aggressiveAllowed is false', async () => {
    mockStages(withSomeAggressiveAvailable)
    renderAs('editor', <Harness aggressiveAllowed={false} />)

    const nucleiActive = await screen.findByRole('switch', { name: 'nuclei_active' })
    const nikto = screen.getByRole('switch', { name: 'nikto' })
    expect(nucleiActive).toBeDisabled()
    expect(nikto).toBeDisabled()
    expect(screen.getByRole('button', { name: 'Aggressive' })).toBeDisabled()
    expect(screen.getByRole('switch', { name: 'httpx' })).toBeEnabled()
  })

  it('disables all switches and hides presets when disabled (read-only)', async () => {
    mockStages(withSomeAggressiveAvailable)
    renderAs('viewer', <Harness disabled />)

    const switches = await screen.findAllByRole('switch')
    expect(switches).toHaveLength(7)
    for (const sw of switches) {
      expect(sw).toBeDisabled()
    }
    expect(screen.queryByRole('button', { name: 'Default' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Aggressive' })).not.toBeInTheDocument()
  })
})
