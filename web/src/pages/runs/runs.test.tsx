import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import type { ReactNode } from 'react'
import { MemoryRouter, Route, Routes } from 'react-router'
import { afterEach, describe, expect, it, vi } from 'vitest'
import type { Schemas } from '../../api/client'
import { AuthContext } from '../../auth/AuthContext'
import type { Permission } from '../../auth/permissions'
import { RunDetailPage } from './RunDetailPage'
import { RunsPage } from './RunsPage'
import { formatDuration, isActive, POLL_MS, pollWhile, ProgressBar, runDurationMs, StatusBadge } from './ui'

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
  vi.useRealTimers()
})

const ADMIN: Permission[] = ['read', 'export', 'runs:control']
const VIEWER: Permission[] = ['read', 'export']

function wrap(ui: ReactNode, permissions: Permission[] = ADMIN, path = '/runs') {
  const me: Schemas['Me'] = { user: { id: 1, username: 'u', role: 'admin' }, permissions }
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <AuthContext.Provider value={{ me, setMe: () => {} }}>
        <MemoryRouter initialEntries={[path]}>
          <Routes>
            <Route path="/runs" element={ui} />
            <Route path="/runs/:id" element={<RunDetailPage />} />
          </Routes>
        </MemoryRouter>
      </AuthContext.Provider>
    </QueryClientProvider>,
  )
}

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })

function run(over: Partial<Schemas['Run']> = {}): Schemas['Run'] {
  return {
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
    batches_failed: 1,
    stats: { candidates: 3, batch_size: 1 },
    ...over,
  }
}

const profiles = { items: [{ id: 1, name: 'default', ports: '80', nmap_max_rate: 300, enabled: true }], total: 1 }

const batch = (over: Partial<Schemas['Batch']> = {}): Schemas['Batch'] => ({
  id: 1,
  run_id: 7,
  seq: 1,
  host_count: 2,
  hosts_up: 1,
  status: 'done',
  error: '',
  attempts: 1,
  started_at: null,
  finished_at: null,
  duration_ms: 12_400,
  ...over,
})

describe('helpers', () => {
  it('treats only pending/running as active and polls only then', () => {
    expect(['pending', 'running'].every((s) => isActive(s as Schemas['RunStatus']))).toBe(true)
    for (const s of ['suspended', 'done', 'failed', 'stopped'] as const) expect(isActive(s)).toBe(false)
    expect(pollWhile(true)).toBe(POLL_MS)
    expect(pollWhile(false)).toBe(false)
  })

  it('formats durations', () => {
    expect(formatDuration(null)).toBe('—')
    expect(formatDuration(850)).toBe('850 ms')
    expect(formatDuration(12_400)).toBe('12 s')
    expect(formatDuration(125_000)).toBe('2 min 5 s')
    expect(runDurationMs(run({ status: 'done', finished_at: '2026-11-21T10:01:00Z' }))).toBe(60_000)
    expect(runDurationMs(run({ status: 'pending', started_at: null }))).toBeNull()
  })

  it('renders status badges and progress', () => {
    render(
      <>
        <StatusBadge status="failed" />
        <ProgressBar run={run()} />
      </>,
    )
    expect(screen.getByText('failed')).toBeInTheDocument()
    const bar = screen.getByRole('progressbar')
    expect(bar).toHaveAttribute('aria-valuenow', '2')
    expect(bar).toHaveAttribute('aria-valuemax', '4')
    expect(screen.getByText('2/4')).toBeInTheDocument()
    expect(screen.getByText('(1 failed)')).toBeInTheDocument()
  })
})

describe('RunsPage', () => {
  it('lists runs with profile name, status, progress and hosts', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) =>
      String(input).startsWith('/api/profiles')
        ? json(profiles)
        : json({ items: [run(), run({ id: 6, status: 'done', batches_done: 4, batches_failed: 0 })], total: 2 }),
    )
    wrap(<RunsPage />)
    const table = await screen.findByRole('table')
    expect(await within(table).findByText('#7')).toBeInTheDocument()
    expect(within(table).getAllByText('default')).toHaveLength(2)
    expect(within(table).getByText('running')).toBeInTheDocument()
    expect(within(table).getByText('done')).toBeInTheDocument()
    expect(within(table).getAllByText('1 / 3')).toHaveLength(2)
    expect(within(table).getByText('4/4')).toBeInTheDocument()
  })

  it('hides the start form from a viewer', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) =>
      String(input).startsWith('/api/profiles') ? json(profiles) : json({ items: [run()], total: 1 }),
    )
    wrap(<RunsPage />, VIEWER)
    expect(await screen.findByText('#7')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /Start run/ })).not.toBeInTheDocument()
    expect(screen.queryByLabelText('Profile')).not.toBeInTheDocument()
  })

  it('starts a run with CSRF and explains a 409 conflict', async () => {
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      const url = String(input)
      if (url.startsWith('/api/profiles')) return json(profiles)
      if (init?.method === 'POST')
        return json({ error: { code: 'conflict', message: 'profile 1 already has an active run' } }, 409)
      return json({ items: [run()], total: 1 })
    })
    wrap(<RunsPage />)
    expect(await screen.findByRole('option', { name: /default/ })).toBeInTheDocument()
    await screen.findByText('#7')
    fireEvent.click(screen.getByRole('button', { name: 'Start run' }))
    const alert = await screen.findByRole('alert')
    expect(alert).toHaveTextContent('This profile already has an active run (run #7)')
    expect(within(alert).getByRole('link', { name: 'run #7' })).toHaveAttribute('href', '/runs/7')
    const post = fetchMock.mock.calls.find(([, i]) => i?.method === 'POST')!
    expect(post[0]).toBe('/api/runs')
    expect((post[1]?.headers as Record<string, string>)['X-RAVEN-CSRF']).toBe('1')
    expect(JSON.parse(post[1]?.body as string)).toEqual({ profile_id: 1 })
  })
})

describe('RunDetailPage', () => {
  it('polls while running and stops polling once the run is terminal', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true })
    let runCalls = 0
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      const url = String(input)
      if (url.startsWith('/api/profiles')) return json(profiles)
      if (url === '/api/runs/7/batches') return json({ items: [batch()], total: 1 })
      runCalls++
      return json(
        runCalls < 3
          ? run()
          : run({ status: 'done', finished_at: '2026-11-21T10:02:00Z', batches_done: 4, batches_failed: 0 }),
      )
    })
    wrap(<RunsPage />, ADMIN, '/runs/7')
    expect(await screen.findByText('running')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Stop run' })).toBeInTheDocument()

    await act(() => vi.advanceTimersByTimeAsync(POLL_MS))
    await act(() => vi.advanceTimersByTimeAsync(POLL_MS))
    await waitFor(() => expect(screen.getAllByText('done').length).toBeGreaterThan(1)) // run badge + batch badge
    expect(runCalls).toBe(3)
    expect(screen.queryByRole('button', { name: 'Stop run' })).not.toBeInTheDocument()

    await act(() => vi.advanceTimersByTimeAsync(POLL_MS * 4))
    expect(runCalls).toBe(3)
  })

  it('shows batches with duration and error', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      const url = String(input)
      if (url.startsWith('/api/profiles')) return json(profiles)
      if (url === '/api/runs/7/batches')
        return json({
          items: [batch(), batch({ id: 2, seq: 2, status: 'failed', attempts: 3, error: 'nmap: exit 1', duration_ms: 850 })],
          total: 2,
        })
      return json(run({ status: 'failed', finished_at: '2026-11-21T10:02:00Z' }))
    })
    wrap(<RunsPage />, ADMIN, '/runs/7')
    expect(await screen.findByText('12 s')).toBeInTheDocument()
    expect(screen.getByText('850 ms')).toBeInTheDocument()
    expect(screen.getByText('nmap: exit 1')).toBeInTheDocument()
    expect(screen.getByText('default')).toBeInTheDocument()
    expect(screen.getByText('2 min 0 s')).toBeInTheDocument()
  })

  it('asks for confirmation before stopping', async () => {
    let stopped = false
    const stoppedRun = run({ status: 'stopped', finished_at: '2026-11-21T10:01:00Z' })
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      const url = String(input)
      if (url.startsWith('/api/profiles')) return json(profiles)
      if (url === '/api/runs/7/batches') return json({ items: [], total: 0 })
      if (init?.method === 'POST') {
        stopped = true
        return json(stoppedRun)
      }
      return json(stopped ? stoppedRun : run())
    })
    wrap(<RunsPage />, ADMIN, '/runs/7')
    fireEvent.click(await screen.findByRole('button', { name: 'Stop run' }))
    expect(screen.getByRole('dialog', { name: 'Confirm stop' })).toHaveTextContent('Stop run #7?')
    expect(fetchMock.mock.calls.some(([, i]) => i?.method === 'POST')).toBe(false)
    fireEvent.click(screen.getByRole('button', { name: 'Confirm stop' }))
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
    expect(screen.getByText('stopped')).toBeInTheDocument() // the run's status badge
    const post = fetchMock.mock.calls.find(([, i]) => i?.method === 'POST')!
    expect(post[0]).toBe('/api/runs/7/stop')
    expect(screen.queryByRole('button', { name: 'Stop run' })).not.toBeInTheDocument()
  })

  it('hides the stop button from a viewer', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      const url = String(input)
      if (url.startsWith('/api/profiles')) return json(profiles)
      if (url === '/api/runs/7/batches') return json({ items: [batch({ status: 'running' })], total: 1 })
      return json(run())
    })
    wrap(<RunsPage />, VIEWER, '/runs/7')
    await waitFor(() => expect(screen.getAllByText('running')).toHaveLength(2)) // run + batch
    expect(screen.queryByRole('button', { name: /Stop/ })).not.toBeInTheDocument()
  })
})
