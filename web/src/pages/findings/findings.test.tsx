import { cleanup, fireEvent, screen, waitFor, within } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { json, renderAs } from '../../test-utils'
import { FindingsPage } from './FindingsPage'
import {
  apiQuery,
  emptyFilters,
  filtersFromParams,
  paramsFromFilters,
  statusFlags,
  statusOf,
  triagePatch,
  type Finding,
  type Status,
} from './ui'

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
})

const finding: Finding = {
  id: 7,
  asset_id: 3,
  ip: '172.30.0.10',
  title: 'Telnet service exposed',
  severity: 'High',
  active: true,
  verified: false,
  false_p: false,
  risk_accepted: false,
  is_mitigated: false,
  tags: ['raven'],
  scanner: 'nmap',
  date: '2026-11-21',
  dojo_url: 'http://dojo.local/finding/7',
}

describe('filter helpers', () => {
  it('round-trips filters through the query string, severities in order, empty values dropped', () => {
    const p = paramsFromFilters(
      { ...emptyFilters, severity: ['Low', 'Critical'], active: 'true', asset: ' 42 ', ip: ' 172.30.0.0/24 ', scanner: 'nmap' },
      50,
      7,
    )
    expect(p.toString()).toBe('severity=Critical%2CLow&active=true&asset=42&ip=172.30.0.0%2F24&scanner=nmap&offset=50&id=7')
    expect(filtersFromParams(p)).toEqual({
      ...emptyFilters,
      severity: ['Critical', 'Low'],
      active: 'true',
      asset: '42',
      ip: '172.30.0.0/24',
      scanner: 'nmap',
    })
  })
  it('drops unknown severities and active values', () => {
    expect(filtersFromParams(new URLSearchParams('severity=high,bogus&active=maybe&verified=true'))).toMatchObject({
      severity: ['High'],
      active: '',
      verified: 'true',
    })
  })
  it('builds the API query', () => {
    expect(
      apiQuery({ ...emptyFilters, active: 'false', false_p: 'true', out_of_scope: 'false', asset: ' 7 ', q: ' tel ' }, 0),
    ).toEqual({
      severity: undefined,
      active: false,
      verified: undefined,
      false_p: true,
      out_of_scope: false,
      risk_accepted: undefined,
      duplicate: undefined,
      is_mitigated: undefined,
      asset: '7',
      ip: undefined,
      q: 'tel',
      scanner: undefined,
      limit: 50,
      offset: 0,
    })
  })
})

describe('triage status', () => {
  it('derives the status from the flags', () => {
    expect(statusOf(finding)).toBe('active')
    expect(statusOf({ ...finding, verified: true })).toBe('verified')
    expect(statusOf({ ...finding, active: false, false_p: true })).toBe('false_p')
    expect(statusOf({ ...finding, active: false, risk_accepted: true })).toBe('risk_accepted')
    expect(statusOf({ ...finding, active: false, is_mitigated: true })).toBe('mitigated')
    expect(statusOf({ ...finding, active: false })).toBe('inactive')
  })
  it('only offers combinations NormalizePatch accepts', () => {
    for (const s of ['active', 'verified', 'false_p', 'risk_accepted', 'mitigated'] as Status[]) {
      const f = statusFlags(s)
      expect(f.false_p && f.verified).toBe(false)
      expect(f.active && (f.false_p || f.risk_accepted || f.is_mitigated)).toBe(false)
      expect(statusOf(f)).toBe(s)
    }
  })
  it('patches only what changes', () => {
    expect(triagePatch(finding, 'active', 'High')).toBeNull()
    expect(triagePatch(finding, 'active', 'Low')).toEqual({ severity: 'Low' })
    expect(triagePatch(finding, 'false_p', 'High')).toEqual({ active: false, false_p: true })
    expect(triagePatch({ ...finding, active: false, false_p: true }, 'verified', 'High')).toEqual({
      active: true,
      verified: true,
      false_p: false,
    })
  })
})

function urls(spy: { mock: { calls: unknown[][] } }) {
  return spy.mock.calls.map((c) => String(c[0]))
}

describe('Findings page', () => {
  it('sends the URL filters to the API and keeps the form in the URL', async () => {
    const spy = vi.spyOn(globalThis, 'fetch').mockImplementation(async () => json({ items: [finding], total: 1 }))
    renderAs('viewer', <FindingsPage />, { path: '/findings?severity=high&active=true', route: '/findings' })
    expect(await screen.findByText('Telnet service exposed')).toBeInTheDocument()
    expect(urls(spy)).toContain('/api/findings?severity=High&active=true&limit=50&offset=0')

    fireEvent.change(screen.getByLabelText('IP or CIDR'), { target: { value: '172.30.0.0/24' } })
    fireEvent.change(screen.getByLabelText('Source'), { target: { value: 'nuclei' } })
    await waitFor(() =>
      expect(urls(spy)).toContain(
        '/api/findings?severity=High&active=true&ip=172.30.0.0%2F24&scanner=nuclei&limit=50&offset=0',
      ),
    )
    // Severity cards toggle the multi-select.
    fireEvent.click(screen.getByRole('button', { name: /^Critical/ }))
    await waitFor(() =>
      expect(urls(spy)).toContain(
        '/api/findings?severity=Critical%2CHigh&active=true&ip=172.30.0.0%2F24&scanner=nuclei&limit=50&offset=0',
      ),
    )
    // Status filter sends expanded flags (e.g. false_p) and asset
    fireEvent.change(screen.getByLabelText('Status'), { target: { value: 'false_p' } })
    fireEvent.change(screen.getByLabelText('Asset'), { target: { value: '42' } })
    await waitFor(() =>
      expect(urls(spy)).toContain(
        '/api/findings?severity=Critical%2CHigh&false_p=true&asset=42&ip=172.30.0.0%2F24&scanner=nuclei&limit=50&offset=0',
      ),
    )
  })

  it('rejects a malformed IP filter', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(async () => json({ items: [], total: 0 }))
    renderAs('viewer', <FindingsPage />, { path: '/findings' })
    expect(await screen.findByText('No findings yet.')).toBeInTheDocument()
    const input = screen.getByLabelText('IP or CIDR')
    fireEvent.change(input, { target: { value: 'not an ip' } })
    expect(input).toHaveAttribute('aria-invalid', 'true')
  })

  it.each([700, 1400])('places the selected detail at %ipx', async (width) => {
    vi.spyOn(window, 'matchMedia').mockImplementation((media) =>
      Object.assign(new EventTarget(), { media, matches: width >= 1140 }) as MediaQueryList,
    )
    const second = { ...finding, id: 8, title: 'Test finding 8' }
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({ items: [finding, second], total: 2 }))
    renderAs('viewer', <FindingsPage />, { path: '/findings', route: '/findings' })
    const trigger = await screen.findByRole('link', { name: second.title })
    const row = trigger.closest('tr')!
    expect(trigger).toHaveAttribute('aria-expanded', 'false')
    expect(screen.queryByRole('heading', { name: second.title })).toBeNull()

    fireEvent.click(trigger)
    const heading = await screen.findByRole('heading', { name: second.title })
    const panel = screen.getByRole('complementary', { name: 'Selected finding' })
    expect(panel).toContainElement(heading)
    expect(trigger).toHaveAttribute('aria-expanded', 'true')
    expect(trigger).toHaveAttribute('aria-controls', panel.id)
    if (width < 1140) {
      expect(row.nextElementSibling).toContainElement(panel)
    } else {
      expect(row.closest('section')?.nextElementSibling).toBe(panel)
      expect(panel).toHaveClass('sticky')
    }
  })

  it('links to the host and to Dojo in a new tab', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(async () => json({ items: [finding], total: 1 }))
    renderAs('viewer', <FindingsPage />, { path: '/findings?id=7', route: '/findings' })
    const panel = await screen.findByRole('complementary', { name: 'Selected finding' })
    expect(await within(panel).findByRole('heading', { name: 'Telnet service exposed' })).toBeInTheDocument()
    const dojo = within(panel).getByRole('link', { name: 'open ↗' })
    expect(dojo).toHaveAttribute('href', 'http://dojo.local/finding/7')
    expect(dojo).toHaveAttribute('target', '_blank')
    expect(within(panel).getByRole('link', { name: '172.30.0.10' })).toHaveAttribute('href', '/hosts/172.30.0.10')
  })

  it('saves triage and a note, then refetches', async () => {
    const spy = vi.spyOn(globalThis, 'fetch').mockImplementation(async (_url, init) => {
      if (init?.method === 'PATCH') return json({ ...finding, active: false, false_p: true, severity: 'Low' })
      if (init?.method === 'POST') return new Response(null, { status: 204 })
      return json({ items: [finding], total: 1 })
    })
    renderAs('operator', <FindingsPage />, { path: '/findings?id=7', route: '/findings' })
    const form = await screen.findByRole('form', { name: 'Triage' })
    fireEvent.change(within(form).getByLabelText('Status'), { target: { value: 'false_p' } })
    fireEvent.change(within(form).getByLabelText('Severity'), { target: { value: 'Low' } })
    fireEvent.change(within(form).getByLabelText('Add a note'), { target: { value: ' checked by hand ' } })
    const gets = urls(spy).length
    fireEvent.click(within(form).getByRole('button', { name: 'Save to DefectDojo' }))
    expect(await within(form).findByRole('status')).toHaveTextContent('Saved')

    const calls = spy.mock.calls.filter((c) => c[1]?.method && c[1].method !== 'GET')
    expect(calls.map((c) => [c[1]?.method, String(c[0]), c[1]?.body])).toEqual([
      ['PATCH', '/api/findings/7', JSON.stringify({ severity: 'Low', active: false, false_p: true })],
      ['POST', '/api/findings/7/notes', JSON.stringify({ text: 'checked by hand' })],
    ])
    await waitFor(() => expect(urls(spy).length).toBeGreaterThan(gets + 2))
  })

  it('shows the API error message', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (_url, init) => {
      if (init?.method === 'PATCH')
        return json({ error: { code: 'bad_request', message: "invalid edit: an active finding can't be mitigated" } }, 400)
      return json({ items: [finding], total: 1 })
    })
    renderAs('admin', <FindingsPage />, { path: '/findings?id=7', route: '/findings' })
    const form = await screen.findByRole('form', { name: 'Triage' })
    const save = within(form).getByRole('button', { name: 'Save to DefectDojo' })
    expect(save).toBeDisabled()
    fireEvent.change(within(form).getByLabelText('Status'), { target: { value: 'mitigated' } })
    fireEvent.click(save)
    expect(await within(form).findByRole('alert')).toHaveTextContent("an active finding can't be mitigated")
  })

  it('shows the list error', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(async () =>
      json({ error: { code: 'bad_request', message: 'ip must be an IP address or CIDR' } }, 400),
    )
    renderAs('viewer', <FindingsPage />, { path: '/findings?ip=x', route: '/findings' })
    expect(await screen.findByText(/Cannot load findings: ip must be an IP address or CIDR/)).toBeInTheDocument()
  })

  it('shows pagination controls both above and below the findings table', async () => {
    const spy = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      const url = String(input)
      if (url.includes('limit=1')) return json({ items: [finding], total: 120 })
      if (url.includes('offset=50')) return json({ items: [{ ...finding, id: 8, title: 'Page 2 finding' }], total: 120 })
      return json({ items: [finding], total: 120 })
    })
    renderAs('viewer', <FindingsPage />, { path: '/findings', route: '/findings' })
    expect(await screen.findByText('Telnet service exposed')).toBeInTheDocument()

    const table = screen.getByRole('table')
    const ranges = screen.getAllByText('1–50 of 120')
    const prevButtons = screen.getAllByRole('button', { name: 'Previous' })
    const nextButtons = screen.getAllByRole('button', { name: 'Next' })
    expect(ranges).toHaveLength(2)
    expect(prevButtons).toHaveLength(2)
    expect(nextButtons).toHaveLength(2)
    expect(prevButtons[0]).toBeDisabled()
    expect(prevButtons[1]).toBeDisabled()
    expect(nextButtons[0]).toBeEnabled()
    expect(nextButtons[1]).toBeEnabled()
    // First Pagination sits before the table, second sits after it.
    expect(ranges[0]!.compareDocumentPosition(table) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy()
    expect(table.compareDocumentPosition(ranges[1]!) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy()

    // Clicking the top Next button advances to page 2.
    fireEvent.click(nextButtons[0]!)
    expect(await screen.findByText('Page 2 finding')).toBeInTheDocument()
    expect(screen.getAllByText('51–100 of 120')).toHaveLength(2)
    expect(urls(spy)).toContain('/api/findings?limit=50&offset=50')

    // Clicking the bottom Previous button returns to page 1.
    fireEvent.click(screen.getAllByRole('button', { name: 'Previous' })[1]!)
    expect(await screen.findByText('Telnet service exposed')).toBeInTheDocument()
    expect(screen.getAllByText('1–50 of 120')).toHaveLength(2)
  })
})
