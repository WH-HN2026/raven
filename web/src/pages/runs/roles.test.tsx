import { cleanup, screen } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import type { Schemas } from '../../api/client'
import type { Role } from '../../auth/permissions'
import { ROLES, json, renderAs } from '../../test-utils'
import { RunDetailPage } from './RunDetailPage'
import { RunsPage } from './RunsPage'

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
})

// runs:control (editor, admin) starts and stops runs.
const canControl: Record<Role, boolean> = { viewer: false, operator: false, editor: true, admin: true }

const profiles = { items: [{ id: 1, name: 'default', ports: '80', nmap_max_rate: 300, enabled: true, stages: ['nmap', 'httpx', 'nuclei'], aggressive: false }], total: 1 }
const run: Schemas['Run'] = {
  id: 7,
  profile_id: 1,
  status: 'running',
  created_at: '2026-11-21T10:00:00Z',
  started_at: '2026-11-21T10:00:00Z',
  finished_at: null,
  hosts_total: 3,
  hosts_up: 1,
  batches_total: 4,
  batches_done: 2,
  batches_failed: 0,
  aggressive: false,
  stats: {},
}

function mockApi() {
  vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
    const url = String(input)
    if (url.startsWith('/api/profiles')) return json(profiles)
    if (url.startsWith('/api/runs/7/batches')) return json({ items: [], total: 0 })
    if (url.startsWith('/api/runs/7')) return json(run)
    return json({ items: [run], total: 1 })
  })
}

describe('Runs controls per role', () => {
  it.each(ROLES)('runs list as %s', async (role) => {
    mockApi()
    renderAs(role, <RunsPage />, { path: '/runs' })
    expect(await screen.findByText('#7')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /Start run/ }) !== null).toBe(canControl[role])
  })

  it.each(ROLES)('run detail as %s', async (role) => {
    mockApi()
    renderAs(role, <RunDetailPage />, { path: '/runs/7', route: '/runs/:id' })
    expect(await screen.findByRole('progressbar')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /Stop/ }) !== null).toBe(canControl[role])
  })
})
