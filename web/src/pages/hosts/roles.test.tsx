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
  active_finding_count: 0,
  open_ports: [],
  technologies: [],
  owner: '',
  criticality: '',
  user_tags: [],
  overrides: {},
}

// The hosts list has read-only controls; host detail edit controls need hosts:edit (operator and up).
describe('Hosts controls per role', () => {
  it.each(ROLES)('hosts list as %s', async (role) => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({ items: [host], total: 1 }))
    renderAs(role, <HostsPage />, { path: '/hosts' })
    expect(await screen.findByText('10.10.0.2')).toBeInTheDocument()
    const filters = screen.getByRole('search')
    const outside = screen.queryAllByRole('button').filter((b) => !filters.contains(b) && !b.closest('th[aria-sort]') && b.textContent !== 'Previous' && b.textContent !== 'Next')
    expect(outside.map((b) => b.textContent)).toEqual([])
  })

  it.each(ROLES)('host detail as %s', async (role) => {
    const svc: Schemas['Service'] = {
      id: 7,
      ip: '10.10.0.2',
      port: 22,
      proto: 'tcp',
      name: 'ssh',
      product: 'OpenSSH',
      version: '9.6',
      scan: { name: 'ssh', product: 'OpenSSH', version: '9.6' },
      overridden: [],
      banner: '',
      state: 'open',
      first_seen: '2026-11-20T10:00:00Z',
      last_seen: '2026-11-21T10:00:00Z',
      overrides: {},
    }
    const detail: Schemas['HostDetail'] = { ...host, notes: '', services: [svc], http: [], timeline: [] }
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json(detail))
    renderAs(role, <HostDetailPage />, { path: '/hosts/10.10.0.2', route: '/hosts/:ip' })
    expect(await screen.findByText('ssh')).toBeInTheDocument()
    const buttons = screen.queryAllByRole('button')
      .filter((b) => !b.closest('th[aria-sort]'))
      .map((b) => b.getAttribute('aria-label') ?? b.textContent)
    expect(buttons).toEqual(role === 'viewer' ? [] : ['Edit 22/tcp', 'Edit'])
  })
})
