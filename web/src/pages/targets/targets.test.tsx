import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import type { ReactNode } from 'react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import type { Schemas } from '../../api/client'
import { AuthContext } from '../../auth/AuthContext'
import type { Permission } from '../../auth/permissions'
import { ManualForm, parseLines, toTextareaErrors } from './ManualForm'
import { TargetsPage } from './index'
import { UploadPanel } from './UploadPanel'

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
})

function wrap(ui: ReactNode, permissions: Permission[] = ['read', 'targets:write', 'import', 'scope:write', 'scope:global']) {
  const me: Schemas['Me'] = { user: { id: 1, username: 'u', role: 'admin' }, permissions }
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <AuthContext.Provider value={{ me, setMe: () => {} }}>{ui}</AuthContext.Provider>
    </QueryClientProvider>,
  )
}

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })

describe('parseLines / toTextareaErrors', () => {
  it('skips blank lines and maps item indexes back to textarea lines', () => {
    const lines = parseLines('10.0.0.1\n\n  bad!  \n10.0.0.0/24\n')
    expect(lines).toEqual([
      { line: 1, value: '10.0.0.1' },
      { line: 3, value: 'bad!' },
      { line: 4, value: '10.0.0.0/24' },
    ])
    expect(toTextareaErrors([{ line: 2, message: 'invalid' }], lines)).toEqual([{ line: 3, message: 'invalid' }])
  })
})

describe('ManualForm', () => {
  it('posts one item per line and shows per-line errors from the 400 response', async () => {
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      json(
        {
          error: { code: 'invalid_targets', message: 'not an IP, CIDR or domain' },
          errors: [{ line: 2, message: 'not an IP, CIDR or domain' }],
        },
        400,
      ),
    )
    wrap(<ManualForm />)
    fireEvent.change(screen.getByLabelText(/Targets \(one per line/), {
      target: { value: '10.0.0.1\n\nbad value!\nexample.lab' },
    })
    fireEvent.change(screen.getByLabelText(/Tags/), { target: { value: 'lab, web' } })
    fireEvent.click(screen.getByRole('button', { name: 'Add targets' }))

    const alert = await screen.findByRole('alert')
    expect(alert).toHaveTextContent('Nothing was added')
    expect(alert).toHaveTextContent('Line 3 (bad value!): not an IP, CIDR or domain')

    const [url, init] = fetchMock.mock.calls[0]!
    expect(url).toBe('/api/targets')
    expect((init?.headers as Record<string, string>)['X-ASI-CSRF']).toBe('1')
    expect(JSON.parse(init?.body as string)).toEqual({
      targets: [
        { value: '10.0.0.1', tags: ['lab', 'web'] },
        { value: 'bad value!', tags: ['lab', 'web'] },
        { value: 'example.lab', tags: ['lab', 'web'] },
      ],
    })
  })
})

describe('UploadPanel', () => {
  it('previews with dry_run, shows line errors, then imports without dry_run', async () => {
    const parsed = {
      targets: [
        { kind: 'cidr', value: '10.0.0.0/24', tags: ['lab'], note: 'main' },
        { kind: 'domain', value: 'wordpress.lab', tags: [] },
      ],
      errors: [{ line: 4, message: 'loopback addresses are not allowed' }],
      source: 'csv',
    }
    const fetchMock = vi
      .spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(json({ ...parsed, dry_run: true, created: 0 }))
      .mockResolvedValueOnce(json({ ...parsed, dry_run: false, created: 2 }))
    wrap(<UploadPanel />)

    const file = new File(['value,tags\n10.0.0.0/24,lab\nwordpress.lab\n127.0.0.1\n'], 'targets.csv', {
      type: 'text/csv',
    })
    fireEvent.change(screen.getByLabelText('File'), { target: { files: [file] } })

    const alert = await screen.findByRole('alert')
    expect(alert).toHaveTextContent('Line 4: loopback addresses are not allowed')
    const table = screen.getByRole('table')
    expect(within(table).getByText('10.0.0.0/24')).toBeInTheDocument()
    expect(within(table).getByText('wordpress.lab')).toBeInTheDocument()
    expect(fetchMock.mock.calls[0]![0]).toBe('/api/targets/upload?dry_run=true')
    const body = fetchMock.mock.calls[0]![1]?.body as FormData
    expect((body.get('file') as File).name).toBe('targets.csv')

    fireEvent.click(screen.getByRole('button', { name: 'Import 2 valid entries' }))
    expect(await screen.findByRole('status')).toHaveTextContent('Imported 2 targets (1 bad lines skipped)')
    expect(fetchMock.mock.calls[1]![0]).toBe('/api/targets/upload')
    expect((fetchMock.mock.calls[1]![1]?.headers as Record<string, string>)['X-ASI-CSRF']).toBe('1')
  })
})

describe('TargetsPage permissions', () => {
  it('shows read-only tables to a viewer', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) =>
      String(input).startsWith('/api/scope')
        ? json({ items: [{ id: 5, kind: 'cidr', value: '10.9.0.0/16', list: 'exclude', note: '' }], total: 1 })
        : json({
            items: [{ id: 1, kind: 'ip', value: '10.0.0.7', source: 'manual', tags: ['lab'], note: '' }],
            total: 1,
          }),
    )
    wrap(<TargetsPage />, ['read', 'export'])
    expect(await screen.findByText('10.0.0.7')).toBeInTheDocument()
    expect(await screen.findByText('10.9.0.0/16')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /Delete|Add|Import/ })).not.toBeInTheDocument()
    expect(screen.queryByLabelText('File')).not.toBeInTheDocument()
    await waitFor(() => expect(screen.getByText(/Exclusions always win/)).toBeInTheDocument())
  })
})
