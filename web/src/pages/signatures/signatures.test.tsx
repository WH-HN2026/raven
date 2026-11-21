import { cleanup, fireEvent, screen, waitFor, within } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import type { Schemas } from '../../api/client'
import { json, renderAs } from '../../test-utils'
import { parseMeta, parseValidationError } from './meta'
import { SignatureEditorPage } from './SignatureEditor'
import { SignaturesList } from './SignaturesList'

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
})

const yaml = `id: raven-admin-path
info:
  name: "Admin page at /admin"
  author: raven
  severity: low
  tags: raven,panel,admin
http:
  - method: GET
    path:
      - "{{BaseURL}}/admin"
`

const builtin: Schemas['Signature'] = {
  id: 7,
  name: 'raven-admin-path',
  template_yaml: yaml,
  enabled: true,
  valid: true,
  validation_error: '',
  builtin: true,
  created_by: null,
  created_at: '2026-11-21T10:00:00Z',
}
const custom: Schemas['Signature'] = {
  ...builtin,
  id: 9,
  name: 'my-check',
  template_yaml: yaml.replace('raven-admin-path', 'my-check'),
  builtin: false,
  created_by: 1,
}

/** fetch mock routed by "METHOD /path". */
function mockApi(routes: Record<string, () => Response>) {
  return vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
    const key = `${init?.method ?? 'GET'} ${String(input).split('?')[0]}`
    const r = routes[key]
    if (!r) throw new Error('unexpected ' + key)
    return r()
  })
}

describe('parseMeta / parseValidationError', () => {
  it('reads the template header', () => {
    expect(parseMeta(yaml)).toEqual({
      id: 'raven-admin-path',
      name: 'Admin page at /admin',
      severity: 'low',
      tags: ['raven', 'panel', 'admin'],
    })
    expect(parseMeta('id: x\ninfo:\n  severity: HIGH\n  tags:\n    - a\n    - "b"\nhttp: []\n')).toEqual({
      id: 'x',
      name: '',
      severity: 'high',
      tags: ['a', 'b'],
    })
  })
  it('splits a stored validation_error into line issues', () => {
    expect(parseValidationError('line 8: method POST is not allowed; line 10: path must start with {{BaseURL}}; x')).toEqual([
      { line: 8, message: 'method POST is not allowed' },
      { line: 10, message: 'path must start with {{BaseURL}}; x' },
    ])
    expect(parseValidationError('')).toEqual([])
  })
})

describe('list', () => {
  it('shows severity, tags, source, validation and enabled toggles', async () => {
    const invalid = { ...custom, id: 10, name: 'bad-one', valid: false, enabled: false, validation_error: 'line 8: nope' }
    const fetchMock = mockApi({
      'GET /api/signatures': () => json({ items: [builtin, invalid], total: 2 }),
      'PUT /api/signatures/7': () => json({ ...builtin, enabled: false }),
    })
    renderAs('editor', <SignaturesList />, { path: '/signatures' })
    await screen.findByText('bad-one')
    const table = screen.getByRole('table', { name: 'Signatures' })
    const rows = within(table).getAllByRole('row')
    expect(rows[1]).toHaveTextContent('Admin page at /admin')
    expect(rows[1]).toHaveTextContent('low')
    expect(rows[1]).toHaveTextContent('panel')
    expect(rows[1]).toHaveTextContent('Built-in')
    expect(rows[1]).toHaveTextContent('Valid')
    expect(rows[2]).toHaveTextContent('Invalid')
    // an invalid, disabled signature can't be enabled
    expect(within(rows[2]!).getByRole('checkbox')).toBeDisabled()

    fireEvent.click(within(rows[1]!).getByRole('checkbox', { name: 'Enabled raven-admin-path' }))
    await waitFor(() => expect(fetchMock.mock.calls.some(([u, i]) => u === '/api/signatures/7' && i?.method === 'PUT')).toBe(true))
    const put = fetchMock.mock.calls.find(([u, i]) => u === '/api/signatures/7' && i?.method === 'PUT')!
    expect(JSON.parse(put[1]!.body as string)).toEqual({ enabled: false })
  })
})

describe('editor', () => {
  it('validates and lists issues with line numbers that jump to the line', async () => {
    mockApi({
      'POST /api/signatures/validate': () =>
        json({
          valid: false,
          errors: ['line 8: method POST is not allowed'],
          issues: [
            { line: 8, message: 'method POST is not allowed' },
            { line: 0, message: 'no matchers' },
          ],
          id: 'my-signature',
          name: 'My signature',
          severity: 'info',
          tags: ['custom'],
        }),
    })
    renderAs('editor', <SignatureEditorPage />, { path: '/signatures/new', route: '/signatures/:id' })
    expect(screen.getByRole('heading', { level: 1 })).toHaveTextContent('New signature')
    fireEvent.click(screen.getByRole('button', { name: 'Validate' }))

    const issues = await screen.findByRole('alert', { name: 'Validation issues' })
    expect(issues).toHaveTextContent('Line 8: method POST is not allowed')
    expect(issues).toHaveTextContent('Template: no matchers')
    const gutter8 = document.querySelector('[data-line="8"]')!
    expect(gutter8).toHaveAttribute('data-issue', 'true')

    fireEvent.click(within(issues).getByRole('button', { name: 'Line 8' }))
    const ta = screen.getByLabelText('Template YAML') as HTMLTextAreaElement
    expect(ta.value.slice(ta.selectionStart, ta.selectionEnd)).toBe('  - method: GET')
    expect(gutter8.className).toContain('bg-rose')
  })

  it('creates a signature and shows the stored issues when it was saved invalid', async () => {
    const saved = { ...custom, id: 11, valid: false, enabled: false, validation_error: 'line 3: bad severity' }
    const fetchMock = mockApi({
      'POST /api/signatures': () => json(saved, 201),
      'GET /api/signatures/11': () => json(saved),
    })
    renderAs('editor', <SignatureEditorPage />, { path: '/signatures/new', route: '/signatures/:id' })
    fireEvent.click(screen.getByRole('button', { name: 'Create' }))
    const issues = await screen.findByRole('alert', { name: 'Validation issues' })
    expect(issues).toHaveTextContent('Line 3: bad severity')
    expect(JSON.parse(fetchMock.mock.calls[0]![1]!.body as string).template_yaml).toContain('id: my-signature')
  })

  it('shows a built-in read-only: no Save or Delete, textarea read-only', async () => {
    mockApi({ 'GET /api/signatures/7': () => json(builtin) })
    renderAs('admin', <SignatureEditorPage />, { path: '/signatures/7', route: '/signatures/:id' })
    expect(await screen.findByRole('heading', { level: 1, name: /Admin page at \/admin/ })).toBeInTheDocument()
    expect(screen.getByLabelText('Template YAML')).toHaveAttribute('readonly')
    expect(screen.queryByRole('button', { name: 'Save' })).toBeNull()
    expect(screen.queryByRole('button', { name: 'Delete' })).toBeNull()
    expect(screen.getByRole('button', { name: 'Validate' })).toBeInTheDocument()
    expect(screen.getByRole('checkbox', { name: 'Enabled raven-admin-path' })).toBeChecked()
  })

  it('disables Test with "Not available yet" when the API answers 501', async () => {
    mockApi({
      'GET /api/signatures/9': () => json(custom),
      'POST /api/signatures/9/test': () => json({ error: { code: 'not_implemented', message: 'not implemented' } }, 501),
    })
    renderAs('editor', <SignatureEditorPage />, { path: '/signatures/9', route: '/signatures/:id' })
    fireEvent.change(await screen.findByLabelText('Lab URL'), { target: { value: 'http://172.30.0.10/' } })
    fireEvent.click(screen.getByRole('button', { name: 'Test' }))
    expect(await screen.findByText('Not available yet')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Test' })).toBeDisabled()
    expect(screen.getByLabelText('Lab URL')).toBeDisabled()
  })

  it('deletes a custom signature', async () => {
    vi.spyOn(window, 'confirm').mockReturnValue(true)
    const fetchMock = mockApi({
      'GET /api/signatures/9': () => json(custom),
      'DELETE /api/signatures/9': () => new Response(null, { status: 204 }),
    })
    renderAs('editor', <SignatureEditorPage />, { path: '/signatures/9', route: '/signatures/:id' })
    fireEvent.click(await screen.findByRole('button', { name: 'Delete' }))
    await waitFor(() => expect(fetchMock.mock.calls.some(([, i]) => i?.method === 'DELETE')).toBe(true))
  })
})
