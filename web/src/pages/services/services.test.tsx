import { cleanup, fireEvent, screen, waitFor, within } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import type { Schemas } from '../../api/client'
import { ROLES, json, renderAs } from '../../test-utils'
import { ServicesPage } from './ServicesPage'
import { apiQuery, emptyFilters, filtersFromParams, paramsFromFilters } from './ui'

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
})

const techItems: Schemas['TechnologySummary'][] = [
  {
    technology: 'WordPress',
    version: '6.4',
    host_count: 2,
    service_count: 2,
    cve_match_count: 0,
    cve_count: 0,
    max_severity: '',
  },
  {
    technology: 'OpenSSH',
    version: '7.4',
    host_count: 1,
    service_count: 1,
    cve_match_count: 1,
    cve_count: 3,
    max_severity: 'High',
  },
]

const svcItems: Schemas['ServiceItem'][] = [
  {
    id: 10,
    ip: '172.30.0.10',
    port: 80,
    proto: 'tcp',
    name: 'http',
    product: 'nginx',
    version: '1.25.3',
    scan: { name: 'http', product: 'nginx', version: '1.25.3' },
    overridden: [],
    banner: '',
    state: 'open',
    first_seen: '2026-11-20T10:00:00Z',
    last_seen: '2026-11-21T10:00:00Z',
    overrides: {},
    hostnames: ['wp.lab'],
    technologies: ['WordPress:6.4', 'PHP:8.2'],
    cve_count: 0,
    cve_severity: '',
  },
  {
    id: 11,
    ip: '172.30.0.11',
    port: 22,
    proto: 'tcp',
    name: 'ssh',
    product: 'OpenSSH',
    version: '7.4',
    scan: { name: 'ssh', product: 'OpenSSH', version: '7.4' },
    overridden: [],
    banner: '',
    state: 'open',
    first_seen: '2026-11-20T10:00:00Z',
    last_seen: '2026-11-21T10:00:00Z',
    overrides: {},
    hostnames: ['ssh.lab'],
    technologies: [],
    cve_count: 3,
    cve_severity: 'High',
  },
]

describe('services filter helpers', () => {
  it('round-trips filters and drops defaults', () => {
    const f = {
      ...emptyFilters,
      port: '443',
      proto: 'tcp',
      product: 'nginx',
      technology: 'WordPress',
      version: '6.4',
      state: 'open',
    }
    const p = paramsFromFilters(f, 50, 20)
    expect(filtersFromParams(p)).toEqual(f)
    expect(apiQuery(f, 50)).toMatchObject({
      port: 443,
      proto: 'tcp',
      product: 'nginx',
      technology: 'WordPress',
      version: '6.4',
      state: 'open',
      limit: 50,
      offset: 50,
    })
  })
})

describe('ServicesPage', () => {
  it('renders technologies summary and services list, filters by tech click, sorts, and links to host detail', async () => {
    const spy = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      const url = String(input)
      if (url.startsWith('/api/technologies')) return json({ items: techItems, total: 2 })
      return json({ items: svcItems, total: 2 })
    })
    renderAs('viewer', <ServicesPage />, { path: '/services', route: '/services' })

    const techTable = await screen.findByRole('table', { name: 'Technologies' })
    expect(await within(techTable).findByText('WordPress')).toBeInTheDocument()
    expect(within(techTable).getByText('OpenSSH')).toBeInTheDocument()
    expect(within(techTable).getByText('3 (1)')).toBeInTheDocument()

    const svcTable = screen.getByRole('table', { name: 'Services' })
    expect(within(svcTable).getByRole('link', { name: '172.30.0.10' })).toHaveAttribute('href', '/hosts/172.30.0.10')
    expect(within(svcTable).getByText('80/tcp')).toBeInTheDocument()

    // Click a technology row to filter services
    fireEvent.click(within(techTable).getByRole('button', { name: 'WordPress' }))
    await waitFor(() =>
      expect(spy.mock.calls.some(([u]) => String(u).includes('/api/services?') && String(u).includes('technology=WordPress') && String(u).includes('version=6.4'))).toBe(true),
    )

    const port = within(svcTable).getByRole('button', { name: 'Port' })
    fireEvent.click(port)
    await waitFor(() =>
      expect(spy.mock.calls.some(([u]) => String(u).includes('/api/services?') && String(u).includes('sort=port&dir=asc'))).toBe(true),
    )
    fireEvent.click(port)
    await waitFor(() =>
      expect(spy.mock.calls.some(([u]) => String(u).includes('/api/services?') && String(u).includes('sort=port&dir=desc'))).toBe(true),
    )
    fireEvent.click(within(techTable).getByRole('button', { name: 'Version' }))
    await waitFor(() =>
      expect(spy.mock.calls.some(([u]) => String(u).includes('/api/technologies?') && String(u).includes('sort=version&dir=asc'))).toBe(true),
    )
    expect(port.closest('th')).toHaveAttribute('aria-sort', 'descending')
  })

  it.each(ROLES)('renders export links and no errors for %s', async (role) => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      if (String(input).startsWith('/api/technologies')) return json({ items: techItems, total: 2 })
      return json({ items: svcItems, total: 2 })
    })
    renderAs(role, <ServicesPage />, { path: '/services?product=nginx', route: '/services' })
    expect(await screen.findByRole('link', { name: 'Export CSV' })).toHaveAttribute(
      'href',
      '/api/export/services?format=csv&product=nginx',
    )
    expect(screen.getByRole('link', { name: 'Export JSON' })).toHaveAttribute(
      'href',
      '/api/export/services?format=json&product=nginx',
    )
  })
})
