import { cleanup, screen } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import type { Schemas } from '../../api/client'
import { ROLES, json, renderAs } from '../../test-utils'
import { HostDetailPage } from './HostDetail'
import { HostsPage } from './HostsList'

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
})

const host: Schemas['Host'] = {
  ip: '10.10.0.2',
  hostnames: [],
  state: 'active',
  first_seen: '2026-11-20T10:00:00Z',
  last_seen: '2026-11-21T10:00:00Z',
  miss_count: 0,
  dojo_asset_id: null,
  open_service_count: 0,
  open_ports: [],
  technologies: [],
  owner: '',
  criticality: '',
  user_tags: [],
  overrides: {},
}

// Hosts pages are read-only so far (host edits come with W5/W8): every role sees only filter controls.
describe('Hosts controls per role', () => {
  it.each(ROLES)('hosts list as %s', async (role) => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({ items: [host], total: 1 }))
    renderAs(role, <HostsPage />, { path: '/hosts' })
    expect(await screen.findByText('10.10.0.2')).toBeInTheDocument()
    const filters = screen.getByRole('search')
    const outside = screen.queryAllByRole('button').filter((b) => !filters.contains(b) && b.textContent !== 'Previous' && b.textContent !== 'Next')
    expect(outside.map((b) => b.textContent)).toEqual([])
  })

  it.each(ROLES)('host detail as %s', async (role) => {
    const detail: Schemas['HostDetail'] = { ...host, notes: '', services: [], http: [], timeline: [] }
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json(detail))
    renderAs(role, <HostDetailPage />, { path: '/hosts/10.10.0.2', route: '/hosts/:ip' })
    expect(await screen.findByRole('heading', { name: '10.10.0.2' })).toBeInTheDocument()
    expect(screen.queryByRole('button')).toBeNull()
  })
})
