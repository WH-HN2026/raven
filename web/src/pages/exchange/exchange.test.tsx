import { cleanup, fireEvent, screen, waitFor, within } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { json, renderAs } from '../../test-utils'
import { ExchangePage } from './index'
import { kindFromName } from './ui'

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
})

const run = {
  id: 42,
  profile_id: 1,
  status: 'done',
  created_at: '2026-11-21T14:00:00Z',
  hosts_total: 3,
  hosts_up: 2,
  batches_total: 1,
  batches_done: 1,
  batches_failed: 0,
  stats: {
    source: 'import',
    import_kind: 'nmap-xml',
    candidates: 5,
    not_included: 1,
    excluded: 1,
    rejected: 0,
    services_open: 7,
    warnings: ['8.8.8.8: not in scope'],
    dojo_push: { ok: 2, failed: 0 },
  },
}

function mockFetch(importResponse: Response) {
  return vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
    const url = String(input)
    if (url.startsWith('/api/profiles'))
      return json({ items: [{ id: 1, name: 'default' }, { id: 2, name: 'lab' }], total: 2 })
    if (url.startsWith('/api/import/results')) return importResponse
    return json({})
  })
}

function pickFile(name: string, body = '<nmaprun/>') {
  const input = screen.getByLabelText('File') as HTMLInputElement
  fireEvent.change(input, { target: { files: [new File([body], name)] } })
}

describe('kindFromName', () => {
  it.each([
    ['scan.xml', 'nmap-xml'],
    ['r.NESSUS', 'nessus'],
    ['n.jsonl', 'nuclei-jsonl'],
    ['n.ndjson', 'nuclei-jsonl'],
    ['asi-services.csv', 'results-csv'],
    ['asi.json', 'results-json'],
    ['notes.txt', undefined],
  ])('%s → %s', (name, kind) => expect(kindFromName(name)).toBe(kind))
})

describe('ExchangePage import', () => {
  it('uploads the file with kind and profile and shows the run result', async () => {
    const fetchSpy = mockFetch(json(run, 202))
    renderAs('editor', <ExchangePage />, { path: '/exchange' })
    await screen.findByRole('option', { name: 'lab' })

    pickFile('lab.xml')
    expect(screen.getByRole('option', { name: 'Auto-detect (nmap XML)' })).toBeInTheDocument()
    fireEvent.change(screen.getByLabelText('Profile'), { target: { value: '2' } })
    fireEvent.click(screen.getByRole('button', { name: 'Import' }))

    const result = await screen.findByRole('region', { name: 'Import result' })
    expect(within(result).getByRole('link', { name: 'Run #42' })).toHaveAttribute('href', '/runs/42')
    expect(within(result).getByText('Hosts imported').parentElement).toHaveTextContent('3')
    expect(within(result).getByText('Open services').parentElement).toHaveTextContent('7')
    expect(within(result).getByText('Excluded').parentElement).toHaveTextContent('1')
    expect(within(result).getByText('8.8.8.8: not in scope')).toBeInTheDocument()
    expect(within(result).getByText('2 ok')).toBeInTheDocument()

    const call = fetchSpy.mock.calls.find(([u]) => String(u).startsWith('/api/import/results'))!
    const init = call[1]!
    expect(init.method).toBe('POST')
    expect((init.headers as Record<string, string>)['X-ASI-CSRF']).toBe('1')
    const form = init.body as FormData
    expect((form.get('file') as File).name).toBe('lab.xml')
    expect(form.get('profile')).toBe('2')
    expect(form.get('kind')).toBeNull() // auto-detect → server decides
  })

  it('sends an explicit kind', async () => {
    const fetchSpy = mockFetch(json(run, 202))
    renderAs('editor', <ExchangePage />, { path: '/exchange' })
    pickFile('export.txt', 'ip\n172.30.0.10')
    fireEvent.change(screen.getByLabelText('File format'), { target: { value: 'results-csv' } })
    fireEvent.click(screen.getByRole('button', { name: 'Import' }))
    await screen.findByRole('region', { name: 'Import result' })
    const call = fetchSpy.mock.calls.find(([u]) => String(u).startsWith('/api/import/results'))!
    expect((call[1]!.body as FormData).get('kind')).toBe('results-csv')
  })

  it('shows the API error', async () => {
    mockFetch(json({ error: { code: 'bad_request', message: 'invalid import/export request: host 2: bad ip' } }, 400))
    renderAs('editor', <ExchangePage />, { path: '/exchange' })
    pickFile('bad.json', '{}')
    fireEvent.click(screen.getByRole('button', { name: 'Import' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('host 2: bad ip')
    expect(screen.queryByRole('region', { name: 'Import result' })).toBeNull()
  })

  it('disables Import until a file is picked', () => {
    mockFetch(json(run, 202))
    renderAs('editor', <ExchangePage />, { path: '/exchange' })
    expect(screen.getByRole('button', { name: 'Import' })).toBeDisabled()
  })
})

describe('ExchangePage export', () => {
  it('links the chosen kind and format', async () => {
    mockFetch(json(run, 202))
    renderAs('viewer', <ExchangePage />, { path: '/exchange' })
    const link = screen.getByRole('link', { name: 'Download' })
    expect(link).toHaveAttribute('href', '/api/export/hosts?format=csv')
    expect(link).toHaveAttribute('download')
    fireEvent.change(screen.getByLabelText('Data'), { target: { value: 'findings' } })
    fireEvent.click(screen.getByRole('button', { name: 'JSON' }))
    await waitFor(() => expect(link).toHaveAttribute('href', '/api/export/findings?format=json'))
  })
})
