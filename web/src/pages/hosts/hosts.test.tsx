import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { MemoryRouter, Route, Routes, useLocation } from 'react-router'
import type { Schemas } from '../../api/client'
import { AuthContext } from '../../auth/AuthContext'
import { HostDetailPage } from './HostDetail'
import { HostsPage } from './HostsList'
import { apiQuery, filtersFromParams, paramsFromFilters, portsSummary } from './ui'

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
})

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })

function LocationProbe() {
  const loc = useLocation()
  return <div data-testid="location">{loc.pathname + loc.search}</div>
}

function renderAt(url: string) {
  const me: Schemas['Me'] = { user: { id: 2, username: 'v', role: 'viewer' }, permissions: ['read', 'export'] }
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <AuthContext.Provider value={{ me, setMe: () => {} }}>
        <MemoryRouter initialEntries={[url]}>
          <Routes>
            <Route path="/hosts" element={<HostsPage />} />
            <Route path="/hosts/:ip" element={<HostDetailPage />} />
          </Routes>
          <LocationProbe />
        </MemoryRouter>
      </AuthContext.Provider>
    </QueryClientProvider>,
  )
}

const host: Schemas['Host'] = {
  ip: '10.10.0.2',
  hostnames: ['wp.lab'],
  state: 'active',
  first_seen: '2026-11-20T10:00:00Z',
  last_seen: '2026-11-21T10:00:00Z',
  miss_count: 0,
  dojo_asset_id: null,
  open_service_count: 2,
  active_finding_count: 3,
  open_ports: [80, 443],
  technologies: ['WordPress'],
  owner: 'web team',
  criticality: 'high',
  user_tags: ['dmz'],
  overrides: {},
}

describe('filter helpers', () => {
  it('round-trips filters through the query string and drops empty values', () => {
    const p = paramsFromFilters({ state: 'active', port: ' 443 ', tech: '', tag: 'dmz', q: '' }, 50)
    expect(p.toString()).toBe('state=active&port=443&tag=dmz&offset=50')
    expect(filtersFromParams(p)).toEqual({ state: 'active', port: '443', tech: '', tag: 'dmz', q: '' })
  })
  it('builds the API query: numeric port, unknown state dropped', () => {
    expect(apiQuery({ state: 'bogus', port: '22', tech: ' php ', tag: '', q: '' }, 0)).toEqual({
      state: undefined,
      port: 22,
      tech: 'php',
      tag: undefined,
      q: undefined,
      limit: 50,
      offset: 0,
    })
  })
  it('summarises long port lists', () => {
    expect(portsSummary([22, 80, 443])).toBe('22, 80, 443')
    expect(portsSummary([1, 2, 3, 4, 5], 3)).toBe('1, 2, 3 +2')
  })
})

describe('HostsPage', () => {
  it('links per-host active finding counts to the matching filter', async () => {
    const second = { ...host, ip: 'fd00::5', active_finding_count: 0 }
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({ items: [host, second], total: 2 }))
    renderAt('/hosts')
    expect(await screen.findByRole('columnheader', { name: 'Findings' })).toBeInTheDocument()
    const firstCount = await screen.findByRole('link', { name: '3 active findings for 10.10.0.2' })
    expect(firstCount).toHaveTextContent('3')
    expect(firstCount).toHaveAttribute('href', '/findings?active=true&ip=10.10.0.2')
    const secondCount = screen.getByRole('link', { name: '0 active findings for fd00::5' })
    expect(secondCount).toHaveTextContent('0')
    expect(secondCount).toHaveAttribute('href', '/findings?active=true&ip=fd00%3A%3A5')
  })

  it('loads filters from the URL, applies new ones to the URL and the API', async () => {
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockImplementation(async () => json({ items: [host], total: 1 }))
    renderAt('/hosts?state=active&tag=dmz')

    const row = await screen.findByRole('link', { name: '10.10.0.2' })
    expect(row).toHaveAttribute('href', '/hosts/10.10.0.2')
    expect(screen.getByText('80, 443')).toBeInTheDocument()
    expect(screen.getByText('WordPress')).toBeInTheDocument()
    expect(fetchMock.mock.calls[0]![0]).toBe('/api/hosts?state=active&tag=dmz&limit=50&offset=0')
    expect(screen.getByLabelText('Tag')).toHaveValue('dmz')

    fireEvent.change(screen.getByLabelText('Open port'), { target: { value: '443' } })
    fireEvent.change(screen.getByLabelText('Technology'), { target: { value: 'WordPress' } })
    fireEvent.click(screen.getByRole('button', { name: 'Apply' }))
    await waitFor(() =>
      expect(screen.getByTestId('location')).toHaveTextContent('/hosts?state=active&port=443&tech=WordPress&tag=dmz'),
    )
    await waitFor(() =>
      expect(fetchMock.mock.calls.at(-1)![0]).toBe(
        '/api/hosts?state=active&port=443&tech=WordPress&tag=dmz&limit=50&offset=0',
      ),
    )

    // the state toggle applies immediately
    const state = screen.getByRole('group', { name: 'State' })
    expect(within(state).getByRole('button', { name: 'Active' })).toHaveAttribute('aria-pressed', 'true')
    fireEvent.click(within(state).getByRole('button', { name: 'Unstable' }))
    await waitFor(() => expect(screen.getByTestId('location')).toHaveTextContent('state=unstable'))

    fireEvent.click(screen.getByRole('button', { name: 'Reset' }))
    await waitFor(() => expect(screen.getByTestId('location')).toHaveTextContent(/^\/hosts$/))
    expect(screen.getByLabelText('Tag')).toHaveValue('')
  })

  it('paginates through the URL and shows an empty state', async () => {
    const fetchMock = vi
      .spyOn(globalThis, 'fetch')
      .mockImplementation(async (input) =>
        String(input).includes('offset=50') ? json({ items: [], total: 120 }) : json({ items: [host], total: 120 }),
      )
    renderAt('/hosts')
    expect(await screen.findByText('1–50 of 120')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Next' }))
    await waitFor(() => expect(screen.getByTestId('location')).toHaveTextContent('/hosts?offset=50'))
    expect(await screen.findByText('51–100 of 120')).toBeInTheDocument()
    expect(fetchMock.mock.calls.at(-1)![0]).toBe('/api/hosts?limit=50&offset=50')
  })

  it('blocks a non-numeric port', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(async () => json({ items: [], total: 0 }))
    renderAt('/hosts')
    expect(await screen.findByText('No hosts yet.')).toBeInTheDocument()
    fireEvent.change(screen.getByLabelText('Open port'), { target: { value: 'http' } })
    expect(screen.getByRole('button', { name: 'Apply' })).toBeDisabled()
  })
})

const service = (over: Partial<Schemas['Service']>): Schemas['Service'] => ({
  id: 1,
  ip: '10.10.0.2',
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
  ...over,
})

describe('HostDetailPage', () => {
  it('shows services with override markers, an HTTP empty state and the timeline', async () => {
    const detail: Schemas['HostDetail'] = {
      ...host,
      notes: 'decrypted note',
      services: [
        service({
          id: 1,
          product: 'OpenResty',
          overridden: ['product'],
          overrides: { product: 'OpenResty' },
          banner: 'nginx banner',
        }),
        service({ id: 2, port: 21, name: 'ftp', product: 'vsftpd', version: '3.0.3', state: 'gone' }),
      ],
      http: [],
      timeline: [
        { run_id: 7, up: false, observed_at: '2026-11-21T10:00:00Z' },
        { run_id: 6, up: true, observed_at: '2026-11-20T10:00:00Z' },
      ],
    }
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockResolvedValue(json(detail))
    renderAt('/hosts/10.10.0.2')

    expect(await screen.findByText('decrypted note')).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: '10.10.0.2' })).toBeInTheDocument()
    expect(fetchMock.mock.calls[0]![0]).toBe('/api/hosts/10.10.0.2')
    const edited = screen.getByText('edited')
    expect(edited).toHaveAttribute('title', 'Scan value: nginx')
    expect(screen.getByText('OpenResty')).toBeInTheDocument()
    expect(screen.getByText('nginx banner')).toBeInTheDocument()
    expect(screen.getByText('21/tcp')).toBeInTheDocument()
    expect(screen.getByText('No HTTP observations.')).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Active findings: 3' })).toHaveAttribute(
      'href',
      '/findings?active=true&ip=10.10.0.2',
    )
    const tl = screen.getByRole('list', { name: 'Up/down timeline' })
    expect(within(tl).getAllByRole('listitem').map((li) => li.textContent)).toEqual([
      expect.stringContaining('downrun #7'),
      expect.stringContaining('uprun #6'),
    ])
    // read-only: no edit/delete controls
    expect(screen.queryByRole('button')).toBeNull()
  })

  it('renders decrypted HTTP observations', async () => {
    const detail: Schemas['HostDetail'] = {
      ...host,
      notes: '',
      services: [service({})],
      http: [
        {
          id: 9,
          service_id: 1,
          url: 'http://10.10.0.2/',
          status: 200,
          title: 'My Blog',
          headers: { Server: 'nginx', 'X-Environment': 'staging' },
          cookies: ['wp_session=abc; HttpOnly'],
          tls_cert: '',
          redirects: ['http://10.10.0.2/wp/'],
          technologies: ['WordPress', 'PHP'],
          favicon_hash: '-1234',
          run_id: 7,
          observed_at: '2026-11-21T10:00:00Z',
        },
      ],
      timeline: [],
    }
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json(detail))
    renderAt('/hosts/10.10.0.2')
    expect(await screen.findByText('http://10.10.0.2/')).toBeInTheDocument()
    expect(screen.getByText('My Blog')).toBeInTheDocument()
    expect(screen.getByText('X-Environment')).toBeInTheDocument()
    expect(screen.getByText('staging')).toBeInTheDocument()
    expect(screen.getByText('wp_session=abc; HttpOnly')).toBeInTheDocument()
    expect(screen.getByText('-1234')).toBeInTheDocument()
    expect(screen.getByText('No run observations.')).toBeInTheDocument()
  })

  it('shows a not-found message for an unknown host', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({ error: { code: 'not_found', message: 'host not found' } }, 404))
    renderAt('/hosts/10.99.0.1')
    expect(await screen.findByText('Host 10.99.0.1 is not known.')).toBeInTheDocument()
  })
})
