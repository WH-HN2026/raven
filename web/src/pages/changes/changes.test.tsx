import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { MemoryRouter, Route, Routes, useLocation } from 'react-router'
import type { Schemas } from '../../api/client'
import { AuthContext } from '../../auth/AuthContext'
import { ChangesPage } from './ChangesPage'
import { HostTimelinePage } from './HostTimeline'
import { compareRuns, counts, diffRows, runParam, shownFields } from './ui'

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
})

function at<T>(a: T[], i: number): T {
  const v = a[i]
  if (v === undefined) throw new Error('missing item ' + i)
  return v
}

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
const apiErr = (status: number, message: string) =>
  json({ error: { code: status === 404 ? 'not_found' : 'bad_request', message } }, status)

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
            <Route path="/changes" element={<ChangesPage />} />
            <Route path="/changes/hosts/:ip" element={<HostTimelinePage />} />
          </Routes>
          <LocationProbe />
        </MemoryRouter>
      </AuthContext.Provider>
    </QueryClientProvider>,
  )
}

const run = (id: number): Schemas['DiffRun'] => ({
  id,
  profile_id: 1,
  status: 'done',
  started_at: id === 4 ? '2026-11-21T09:00:00Z' : '2026-11-21T10:00:00Z',
  finished_at: '2026-11-21T10:05:00Z',
})
const fp = (o: Partial<Schemas['ServiceFingerprint']> = {}): Schemas['ServiceFingerprint'] => ({
  name: 'http',
  product: 'nginx',
  version: '1.24',
  title: '',
  technologies: [],
  ...o,
})

const diff: Schemas['RunDiff'] = {
  from: run(1),
  to: run(2),
  summary: { hosts_new: 1, hosts_gone: 1, services_new: 1, services_gone: 0, services_changed: 1 },
  hosts_new: [{ ip: '172.30.0.20', other_run: 'not_scanned', ports: [22, 80] }],
  hosts_gone: [{ ip: '172.30.0.30', other_run: 'down', ports: [3306] }],
  services_new: [{ ip: '172.30.0.10', port: 8080, proto: 'tcp', before: null, after: fp({ product: 'Jetty' }), fields: [] }],
  services_gone: [],
  services_changed: [
    {
      ip: '172.30.0.10',
      port: 80,
      proto: 'tcp',
      before: fp({ version: '1.24', technologies: ['WordPress'] }),
      after: fp({ version: '1.25', technologies: ['WordPress'] }),
      fields: ['version'],
    },
  ],
  truncated: false,
}

const runList: Schemas['RunList'] = {
  items: [4, 3, 2, 1].map((id) => ({
    ...run(id),
    status: id === 3 ? 'running' : 'done',
    created_at: '2026-11-21T10:00:00Z',
    hosts_total: 4,
    hosts_up: 3,
    batches_total: 1,
    batches_done: 1,
    batches_failed: 0,
    stats: {},
  })),
  total: 4,
}

function mockApi(changes: (url: URL) => Response) {
  return vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
    const url = new URL(String(input), 'http://x')
    if (url.pathname === '/api/changes') return changes(url)
    if (url.pathname === '/api/profiles')
      return json({ items: [{ id: 1, name: 'Lab', enabled: true, nmap_max_rate: 100 }], total: 1 })
    if (url.pathname === '/api/runs') return json(runList)
    const id = Number(url.pathname.match(/^\/api\/runs\/(\d+)$/)?.[1])
    const item = runList.items.find((r) => r.id === id)
    if (item) return json(item)
    return json({}, 404)
  })
}

describe('helpers', () => {
  it('reads run ids from the query string', () => {
    const p = new URLSearchParams('from=4&to=x')
    expect(runParam(p, 'from')).toBe(4)
    expect(runParam(p, 'to')).toBeNull()
    expect(runParam(new URLSearchParams('from=0'), 'from')).toBeNull()
  })
  it('uses ID only when timestamps match at database precision', () => {
    expect(compareRuns(run(1), run(2))).toBeLessThan(0)
    expect(compareRuns(run(4), run(1))).toBeLessThan(0)
    expect(
      compareRuns(
        { id: 20, started_at: '2026-11-21T10:00:00.123450Z' },
        { id: 10, started_at: '2026-11-21T11:00:00.123451+01:00' },
      ),
    ).toBeLessThan(0)
  })
  it('flattens the diff new → changed → gone and counts it', () => {
    expect(diffRows(diff).map((r) => r.kind + ':' + r.type)).toEqual([
      'new:host',
      'new:service',
      'changed:service',
      'gone:host',
    ])
    expect(counts(diff)).toEqual({ new: 2, changed: 1, gone: 1, all: 4 })
  })
  it('shows non-empty and changed fields', () => {
    expect(shownFields(fp(), [])).toEqual(['name', 'product', 'version'])
    expect(shownFields(fp(), ['title'])).toEqual(['name', 'product', 'version', 'title'])
    expect(shownFields(null, [])).toEqual([])
  })
})

describe('ChangesPage', () => {
  it('renders the API default diff and highlights the changed field', async () => {
    const fetch = mockApi(() => json(diff))
    renderAt('/changes')
    const table = await screen.findByRole('table', { name: 'Changes' })
    expect(String(at(fetch.mock.calls, 0)[0])).toBe('/api/changes')
    expect(screen.getByRole('heading', { name: /Run #1 → run #2/ })).toBeTruthy()
    const rows = within(table).getAllByRole('row').slice(1)
    expect(rows).toHaveLength(4)
    expect(within(at(rows, 0)).getByText('+ New')).toBeTruthy()
    expect(within(at(rows, 0)).getByText('not scanned')).toBeTruthy()
    expect(within(at(rows, 0)).getByText('up · 22, 80')).toBeTruthy()
    expect(within(at(rows, 0)).getByRole('link', { name: '172.30.0.20' }).getAttribute('href')).toBe('/hosts/172.30.0.20')
    expect(within(at(rows, 0)).getByRole('link', { name: 'Timeline' }).getAttribute('href')).toBe(
      '/changes/hosts/172.30.0.20',
    )
    // changed row: only the version line is highlighted, before and after
    const changed = at(rows, 2)
    const hits = changed.querySelectorAll('[data-changed]')
    expect(hits).toHaveLength(2)
    expect(at([...hits], 0).textContent).toContain('1.24')
    expect(at([...hits], 1).textContent).toContain('1.25')
    expect(within(changed).getAllByText('WordPress')).toHaveLength(2)
    // pickers show the resolved runs; only done runs are offered
    await waitFor(() => expect((screen.getByLabelText('From (baseline)') as HTMLSelectElement).value).toBe('1'))
    expect((screen.getByLabelText('To') as HTMLSelectElement).value).toBe('2')
    expect(within(screen.getByLabelText('To')).queryByText(/Run #3/)).toBeNull()
  })

  it('filters by change kind', async () => {
    mockApi(() => json(diff))
    renderAt('/changes')
    const table = await screen.findByRole('table', { name: 'Changes' })
    fireEvent.click(screen.getByRole('button', { name: 'Gone 1' }))
    const rows = within(table).getAllByRole('row').slice(1)
    expect(rows).toHaveLength(1)
    expect(within(at(rows, 0)).getByText('− Gone')).toBeTruthy()
    expect(within(at(rows, 0)).getByText('up · 3306')).toBeTruthy()
    expect(within(at(rows, 0)).getByText('down')).toBeTruthy()
  })

  it('offers only chronological choices and syncs a selection with the URL', async () => {
    const fetch = mockApi(() => json(diff))
    renderAt('/changes?from=1&to=2')
    await screen.findByRole('table', { name: 'Changes' })
    expect(fetch.mock.calls.map(([url]) => url)).toContain('/api/changes?from=1&to=2')
    const from = screen.getByLabelText<HTMLSelectElement>('From (baseline)')
    const to = screen.getByLabelText<HTMLSelectElement>('To')
    const values = (select: HTMLSelectElement) => Array.from(select.options, (o) => o.value)
    await waitFor(() => expect(values(from)).toEqual(['1', '4']))
    expect(values(to)).toEqual(['2'])
    fireEvent.change(from, { target: { value: '4' } })
    expect(screen.getByTestId('location').textContent).toBe('/changes?from=4&to=2')
    await waitFor(() => expect(values(to)).toEqual(['2', '1']))
  })

  it('silently swaps a reversed URL using start time before ID', async () => {
    const fetch = mockApi(() => json({ ...diff, from: run(4), to: run(2) }))
    renderAt('/changes?from=2&to=4')
    await screen.findByRole('heading', { name: /Run #4 → run #2/ })
    expect(screen.getByTestId('location').textContent).toBe('/changes?from=4&to=2')
    const diffRequests = fetch.mock.calls.map(([url]) => String(url)).filter((url) => url.startsWith('/api/changes'))
    expect(diffRequests).toEqual(['/api/changes?from=4&to=2'])
  })

  it('shows empty and truncated states', async () => {
    const empty = {
      ...diff,
      summary: { hosts_new: 0, hosts_gone: 0, services_new: 0, services_gone: 0, services_changed: 0 },
      hosts_new: [],
      hosts_gone: [],
      services_new: [],
      services_changed: [],
      truncated: true,
    }
    mockApi(() => json(empty))
    renderAt('/changes')
    expect(await screen.findByText('No changes')).toBeTruthy()
    expect(screen.getByRole('alert').textContent).toContain('truncated')
  })

  it('shows the 400 same-run error', async () => {
    mockApi(() => apiErr(400, 'from and to are the same run'))
    renderAt('/changes?from=2&to=2')
    expect((await screen.findByRole('alert')).textContent).toContain('from and to are the same run')
    expect(screen.queryByRole('table')).toBeNull()
  })

  it('shows the 404 no-previous-run error', async () => {
    mockApi(() => apiErr(404, 'no previous done run'))
    renderAt('/changes')
    expect((await screen.findByRole('alert')).textContent).toContain('No runs to compare: no previous done run')
  })
})

describe('HostTimelinePage', () => {
  it('renders runs × ports', async () => {
    const tl: Schemas['HostTimeline'] = {
      ip: '172.30.0.10',
      ports: [22, 80],
      runs: [
        { run: run(2), up: true, observed_at: '2026-11-21T10:05:00Z', open_ports: [80] },
        { run: run(1), up: false, observed_at: '2026-11-21T09:05:00Z', open_ports: [] },
      ],
    }
    const fetch = vi.spyOn(globalThis, 'fetch').mockResolvedValue(json(tl))
    renderAt('/changes/hosts/172.30.0.10')
    const table = await screen.findByRole('table', { name: 'Timeline' })
    expect(String(at(fetch.mock.calls, 0)[0])).toBe('/api/changes/hosts/172.30.0.10?runs=20')
    const rows = within(table).getAllByRole('row').slice(1)
    expect(within(at(rows, 0)).getByText('up')).toBeTruthy()
    expect(within(at(rows, 0)).getByRole('img', { name: '80 open' })).toBeTruthy()
    expect(within(at(rows, 0)).getByRole('img', { name: '22 closed' })).toBeTruthy()
    expect(within(at(rows, 1)).getByText('down')).toBeTruthy()
    expect(screen.getByRole('link', { name: 'Host detail' }).getAttribute('href')).toBe('/hosts/172.30.0.10')
  })
})
