import { cleanup, fireEvent, screen, waitFor, within } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import type { Schemas } from '../../api/client'
import { json, renderAs } from '../../test-utils'
import { HostDetailPage } from './HostDetail'
import { normalizeTag, overridesPatch } from './HostEdit'

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
})

const svc: Schemas['Service'] = {
  id: 7,
  ip: '172.30.0.10',
  port: 80,
  proto: 'tcp',
  name: 'http',
  product: 'Acme httpd',
  version: '2.4',
  scan: { name: 'http', product: 'nginx', version: '2.4' },
  overridden: ['product'],
  banner: '',
  state: 'open',
  first_seen: '2026-11-20T10:00:00Z',
  last_seen: '2026-11-21T10:00:00Z',
  overrides: { product: 'Acme httpd' },
}

const detail: Schemas['HostDetail'] = {
  ip: '172.30.0.10',
  hostnames: [],
  state: 'active',
  first_seen: '2026-11-20T10:00:00Z',
  last_seen: '2026-11-21T10:00:00Z',
  miss_count: 0,
  dojo_asset_id: 12,
  open_service_count: 1,
  open_ports: [80],
  technologies: [],
  owner: 'web team',
  criticality: 'medium',
  user_tags: ['dmz'],
  overrides: {},
  notes: 'old note',
  services: [svc],
  http: [],
  timeline: [],
}

type Call = { url: string; method: string; body: unknown }

/** Mocks fetch: GET returns the detail, PATCH returns `patchRes(body)`; records calls. */
function mockApi(patchRes: (url: string, body: Record<string, unknown>) => unknown) {
  const calls: Call[] = []
  vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
    const url = String(input)
    const method = init?.method ?? 'GET'
    const body = init?.body ? JSON.parse(String(init.body)) : undefined
    calls.push({ url, method, body })
    if (method === 'PATCH') return json(patchRes(url, body))
    return json(detail)
  })
  return calls
}

const renderDetail = () =>
  renderAs('operator', <HostDetailPage />, { path: '/hosts/172.30.0.10', route: '/hosts/:ip' })

describe('helpers', () => {
  it('normalizes and validates tags', () => {
    expect(normalizeTag('  Web/Prod ')).toBe('web/prod')
    expect(normalizeTag('bad tag')).toBeNull()
    expect(normalizeTag('-x')).toBeNull()
    expect(normalizeTag('')).toBeNull()
  })

  it('sends only changed overrides; scan value or empty clears', () => {
    expect(overridesPatch(svc, { name: 'http', product: 'Acme httpd', version: '2.4' })).toEqual({})
    expect(overridesPatch(svc, { name: 'web', product: 'nginx', version: ' ' })).toEqual({ name: 'web', product: null })
    expect(overridesPatch(svc, { name: 'http', product: 'Other', version: '2.5' })).toEqual({
      product: 'Other',
      version: '2.5',
    })
  })
})

describe('host edit', () => {
  it('edits user-owned fields and shows the Dojo sync state and last edited by', async () => {
    const calls = mockApi((_, body) => ({
      ...detail,
      ...body,
      edited_by: 'operator',
      edited_at: '2026-11-21T16:30:00Z',
      dojo_sync: 'synced',
    }))
    renderDetail()
    fireEvent.click(await screen.findByRole('button', { name: 'Edit' }))
    const form = screen.getByRole('form', { name: 'Edit host' })
    fireEvent.change(within(form).getByLabelText('Owner'), { target: { value: ' net team ' } })
    fireEvent.change(within(form).getByLabelText('Criticality'), { target: { value: 'critical' } })
    fireEvent.change(within(form).getByLabelText('Notes'), { target: { value: 'new note' } })
    const tag = within(form).getByLabelText('Add tag')
    fireEvent.change(tag, { target: { value: 'Lab' } })
    fireEvent.keyDown(tag, { key: 'Enter' })
    fireEvent.change(tag, { target: { value: 'bad tag' } })
    fireEvent.keyDown(tag, { key: 'Enter' })
    expect(within(form).getByText(/Invalid tag/)).toBeInTheDocument()
    fireEvent.change(tag, { target: { value: '' } })
    fireEvent.click(within(form).getByRole('button', { name: 'Remove tag dmz' }))
    fireEvent.click(within(form).getByRole('button', { name: 'Save' }))

    expect(await screen.findByText('Dojo synced')).toBeInTheDocument()
    const patch = calls.find((c) => c.method === 'PATCH')
    expect(patch?.url).toBe('/api/hosts/172.30.0.10')
    expect(patch?.body).toEqual({ owner: 'net team', criticality: 'critical', notes: 'new note', user_tags: ['lab'] })
    expect(screen.queryByRole('form', { name: 'Edit host' })).toBeNull()
    expect(screen.getByLabelText('Notes')).toHaveTextContent('new note')
    expect(screen.getByText('net team')).toBeInTheDocument()
    expect(screen.getByText(/operator/)).toBeInTheDocument()
  })

  it('shows a pending sync and keeps the form on errors', async () => {
    let patches = 0
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (_, init) => {
      if (init?.method !== 'PATCH') return json(detail)
      patches++
      return patches === 1
        ? json({ error: { code: 'invalid', message: 'bad owner' } }, 400)
        : json({ ...detail, dojo_sync: 'pending' })
    })
    renderDetail()
    fireEvent.click(await screen.findByRole('button', { name: 'Edit' }))
    fireEvent.click(screen.getByRole('button', { name: 'Save' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('bad owner')
    fireEvent.click(screen.getByRole('button', { name: 'Save' }))
    expect(await screen.findByText('Dojo pending')).toBeInTheDocument()
  })
})

describe('service overrides', () => {
  it('shows the edited marker with the scan value', async () => {
    mockApi(() => undefined)
    renderDetail()
    const marker = await screen.findByText('edited')
    expect(marker).toHaveAttribute('title', 'Scan value: nginx')
  })

  it('overrides a field and resets another to the scan value', async () => {
    const calls = mockApi(() => ({
      ...svc,
      name: 'web',
      product: 'nginx',
      overridden: ['name'],
      overrides: { name: 'web' },
    }))
    renderDetail()
    fireEvent.click(await screen.findByRole('button', { name: 'Edit 80/tcp' }))
    fireEvent.change(screen.getByLabelText('80/tcp name'), { target: { value: 'web' } })
    const resets = screen.getAllByRole('button', { name: 'Reset to scan value' })
    // name (now differs) and product (overridden) can be reset
    expect(resets).toHaveLength(2)
    fireEvent.click(resets[1]!)
    expect(screen.getByLabelText('80/tcp product')).toHaveValue('nginx')
    fireEvent.click(screen.getByRole('button', { name: 'Save' }))
    await waitFor(() => expect(screen.queryByLabelText('80/tcp name')).toBeNull())
    const patch = calls.find((c) => c.method === 'PATCH')
    expect(patch?.url).toBe('/api/services/7')
    expect(patch?.body).toEqual({ overrides: { name: 'web', product: null } })
    expect(screen.getByText('web')).toBeInTheDocument()
    expect(screen.getByText('nginx')).toBeInTheDocument()
    expect(screen.getAllByText('edited')).toHaveLength(1)
  })

  it('closes without a request when nothing changed', async () => {
    const calls = mockApi(() => undefined)
    renderDetail()
    fireEvent.click(await screen.findByRole('button', { name: 'Edit 80/tcp' }))
    fireEvent.click(screen.getByRole('button', { name: 'Save' }))
    expect(screen.queryByLabelText('80/tcp name')).toBeNull()
    expect(calls.some((c) => c.method === 'PATCH')).toBe(false)
  })
})
