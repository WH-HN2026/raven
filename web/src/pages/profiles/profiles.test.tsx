import { cleanup, fireEvent, screen, waitFor, within } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { json, renderAs } from '../../test-utils'
import { profile, route } from './fixture'
import { ProfileEditorPage } from './ProfileEditor'
import { ProfilesPage } from './ProfilesPage'
import {
  checkPorts,
  cronToFrequency,
  describeCron,
  describeWindow,
  frequencyToCron,
  nextWindow,
  wallTime,
  windowToISO,
} from './ui'
import { dojoSchedule, uiSchedule } from './fixture'

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
})

describe('checkPorts (mirrors nmap.CheckPorts)', () => {
  it.each([
    ['22,80,443', null],
    ['1-1024,8000-8100', null],
    ['65535', null],
    ['', 'digits, commas'],
    ['22, 80', 'digits, commas'],
    ['T:22', 'digits, commas'],
    ['0', 'out of range'],
    ['70000', 'out of range'],
    ['100-20', 'reversed'],
  ])('%j', (spec, want) => {
    const got = checkPorts(spec)
    if (want === null) expect(got).toBeNull()
    else expect(got).toContain(want)
  })
})

describe('cron', () => {
  it.each([
    ['* * * * *', 'every minute'],
    ['*/15 * * * *', 'every 15 min'],
    ['0 * * * *', 'every hour'],
    ['0 */6 * * *', 'every 6 h'],
    ['30 2 * * *', 'daily at 02:30'],
    ['5 * * * *', 'hourly at :05'],
  ])('%s round-trips and reads as %s', (cron, label) => {
    expect(frequencyToCron(cronToFrequency(cron))).toBe(cron)
    expect(describeCron(cron)).toBe(label)
  })
})

describe('windows', () => {
  it('converts wall time in a timezone', () => {
    // Warsaw is UTC+1 in winter, UTC+2 in summer.
    expect(new Date(wallTime('Europe/Warsaw', 2026, 11, 21, 22, 0)).toISOString()).toBe('2026-11-21T21:00:00.000Z')
    expect(new Date(wallTime('Europe/Warsaw', 2026, 7, 1, 22, 0)).toISOString()).toBe('2026-07-01T20:00:00.000Z')
  })
  it('puts the end of an overnight window on the next day', () => {
    const now = Date.parse('2026-11-21T12:00:00Z')
    expect(windowToISO('22:00', '06:00', 'Europe/Warsaw', now)).toEqual({
      window_start: '2026-11-21T21:00:00.000Z',
      window_end: '2026-11-22T05:00:00.000Z',
    })
    expect(windowToISO('', '06:00', 'UTC', now)).toBeNull()
  })
  it('describes and finds the next window', () => {
    expect(describeWindow(uiSchedule)).toBe('22:00–06:00 daily')
    expect(nextWindow(uiSchedule, Date.parse('2026-11-21T12:00:00Z'))).toBe('Sat 21 Nov, 22:00')
    expect(nextWindow(uiSchedule, Date.parse('2026-11-22T03:00:00Z'))).toBe('open now')
    expect(nextWindow(dojoSchedule, Date.parse('2026-11-21T12:00:00Z'))).toBe('Sat 5 Jan, 01:00')
    expect(nextWindow(dojoSchedule, Date.parse('2031-01-01T00:00:00Z'))).toBe('ended')
  })
})

type Call = { url: string; method: string; body: unknown }

function mockApi(override?: (c: Call) => Response | undefined) {
  const calls: Call[] = []
  vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
    const c = { url: String(input), method: init?.method ?? 'GET', body: init?.body ? JSON.parse(String(init.body)) : undefined }
    calls.push(c)
    return override?.(c) ?? json(route(c.url))
  })
  return calls
}

describe('ProfilesPage', () => {
  it('lists profiles and schedules with source badges', async () => {
    const customProfile = { ...profile, id: 4, name: 'nmap-only', stages: ['nmap'] as const }
    mockApi((c) => (c.url.startsWith('/api/profiles') ? json({ items: [profile, customProfile], total: 2 }) : undefined))
    renderAs('editor', <ProfilesPage />, { path: '/profiles' })
    expect(await screen.findByRole('link', { name: 'lab-quick' })).toHaveAttribute('href', '/profiles/3')
    expect(screen.getByRole('columnheader', { name: 'Workflow' })).toBeInTheDocument()
    expect(screen.getByRole('columnheader', { name: 'Batch duration' })).toBeInTheDocument()
    const rows = await screen.findAllByRole('row')
    const defaultRow = rows.find((r) => within(r).queryByRole('link', { name: 'lab-quick' }))!
    const customRow = rows.find((r) => within(r).queryByRole('link', { name: 'nmap-only' }))!
    expect(within(defaultRow).getByText('Default')).toBeInTheDocument()
    expect(within(customRow).getByText('nmap')).toBeInTheDocument()
    const ui = rows.find((r) => within(r).queryByText('#7'))!
    const dojo = rows.find((r) => within(r).queryByText('#8'))!
    expect(within(ui).getByText('Nightly lab')).toBeInTheDocument()
    expect(within(ui).getByText('UI')).toBeInTheDocument()
    expect(within(ui).getByText('every 6 h')).toBeInTheDocument()
    expect(within(ui).getByRole('button', { name: 'Edit schedule 7' })).toBeInTheDocument()
    expect(within(dojo).getByText('Q4 planned audit')).toBeInTheDocument()
    expect(within(dojo).getByText(/^Dojo .118$/)).toBeInTheDocument()
    expect(within(dojo).getByRole('link', { name: /open/ })).toHaveAttribute('href', 'http://dojo.local/engagement/118')
    expect(within(dojo).getByText('Read-only')).toBeInTheDocument()
    expect(within(dojo).queryByRole('button')).toBeNull()
  })

  it('creates a schedule with a window and timezone', async () => {
    const calls = mockApi((c) => (c.method === 'POST' ? json({ ...c.body as object, id: 9, source: 'ui' }, 201) : undefined))
    renderAs('editor', <ProfilesPage />, { path: '/profiles' })
    fireEvent.click(await screen.findByRole('button', { name: 'New schedule' }))
    const form = screen.getByRole('form', { name: 'New schedule' })
    await within(form).findByRole('option', { name: 'lab-quick' })
    fireEvent.change(within(form).getByLabelText('Name'), { target: { value: 'Overnight sweep' } })
    fireEvent.change(within(form).getByLabelText('Profile'), { target: { value: '3' } })
    fireEvent.change(within(form).getByLabelText('Repeats'), { target: { value: 'daily' } })
    fireEvent.change(within(form).getByLabelText('Time'), { target: { value: '23:15' } })
    fireEvent.change(within(form).getByLabelText('Window start'), { target: { value: '22:00' } })
    fireEvent.change(within(form).getByLabelText('Window end'), { target: { value: '06:00' } })
    fireEvent.change(within(form).getByLabelText('Timezone'), { target: { value: 'UTC' } })
    fireEvent.click(within(form).getByRole('button', { name: 'Create schedule' }))
    await waitFor(() => expect(calls.some((c) => c.method === 'POST')).toBe(true))
    const post = calls.find((c) => c.method === 'POST')!
    expect(post.url).toBe('/api/schedules')
    const body = post.body as Record<string, string>
    expect(body).toMatchObject({ name: 'Overnight sweep', profile_id: 3, cron: '15 23 * * *', timezone: 'UTC', enabled: true })
    expect(body.window_start).toMatch(/T22:00:00\.000Z$/)
    expect(body.window_end).toMatch(/T06:00:00\.000Z$/)
    expect(Date.parse(body.window_end!) - Date.parse(body.window_start!)).toBe(8 * 3600_000)
  })

  it('rejects a half-set window client-side', async () => {
    const calls = mockApi()
    renderAs('editor', <ProfilesPage />, { path: '/profiles' })
    fireEvent.click(await screen.findByRole('button', { name: 'New schedule' }))
    const form = screen.getByRole('form', { name: 'New schedule' })
    await within(form).findByRole('option', { name: 'lab-quick' })
    fireEvent.change(within(form).getByLabelText('Name'), { target: { value: 'Overnight sweep' } })
    fireEvent.change(within(form).getByLabelText('Profile'), { target: { value: '3' } })
    fireEvent.change(within(form).getByLabelText('Window start'), { target: { value: '22:00' } })
    fireEvent.click(within(form).getByRole('button', { name: 'Create schedule' }))
    expect(await within(form).findByRole('alert')).toHaveTextContent('Set both window start and end')
    expect(calls.some((c) => c.method === 'POST')).toBe(false)
  })
})

describe('ProfileEditorPage', () => {
  it('shows a bad port spec without calling the API', async () => {
    const calls = mockApi()
    renderAs('editor', <ProfileEditorPage />, { path: '/profiles/new', route: '/profiles/new' })
    fireEvent.change(await screen.findByLabelText('Name'), { target: { value: 'x' } })
    fireEvent.change(screen.getByLabelText('Ports'), { target: { value: '22,abc' } })
    fireEvent.click(screen.getByRole('button', { name: 'Create profile' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('digits, commas and ranges')
    expect(calls.some((c) => c.method === 'POST')).toBe(false)
  })

  it('shows a server 400', async () => {
    mockApi((c) =>
      c.method === 'POST' ? json({ error: { code: 'bad_request', message: 'invalid input: unsupported nuclei tag "x"' } }, 400) : undefined,
    )
    renderAs('editor', <ProfileEditorPage />, { path: '/profiles/new', route: '/profiles/new' })
    fireEvent.change(await screen.findByLabelText('Name'), { target: { value: 'x' } })
    fireEvent.change(screen.getByLabelText('Ports'), { target: { value: '80' } })
    fireEvent.click(screen.getByRole('button', { name: 'Create profile' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('unsupported nuclei tag')
  })

  it('edits rates and tags of an existing profile', async () => {
    const calls = mockApi((c) => (c.method === 'PUT' ? json({ ...(c.body as object), id: 3 }) : undefined))
    renderAs('editor', <ProfileEditorPage />, { path: '/profiles/3', route: '/profiles/:id' })
    const rate = await screen.findByLabelText('nmap max rate (pps)')
    expect(rate).toHaveValue(300)
    fireEvent.change(rate, { target: { value: '150' } })
    fireEvent.click(screen.getByLabelText('panel'))
    fireEvent.click(screen.getByLabelText('ssl'))
    fireEvent.click(screen.getByRole('button', { name: 'Save profile' }))
    expect(await screen.findByRole('status')).toHaveTextContent('Saved')
    const put = calls.find((c) => c.method === 'PUT')!
    expect(put.url).toBe('/api/profiles/3')
    expect(put.body).toMatchObject({ name: 'lab-quick', nmap_max_rate: 150, nuclei_tags: ['tech', 'panel'], stages: ['nmap', 'httpx', 'nuclei'] })
  })

  it('submits edited workflow stages and shows stage 400 errors', async () => {
    const calls = mockApi((c) => {
      if (c.method === 'POST') return json({ error: { code: 'bad_request', message: 'invalid input: stage nuclei requires httpx' } }, 400)
      if (c.method === 'PUT') return json({ ...(c.body as object), id: 3 })
    })
    renderAs('editor', <ProfileEditorPage />, { path: '/profiles/3', route: '/profiles/:id' })
    const nuclei = await screen.findByRole('switch', { name: 'nuclei' })
    fireEvent.click(nuclei)
    fireEvent.click(screen.getByRole('button', { name: 'Save profile' }))
    expect(await screen.findByRole('status')).toHaveTextContent('Saved')
    expect(calls.find((c) => c.method === 'PUT')?.body).toMatchObject({ stages: ['nmap', 'httpx'] })

    cleanup()
    renderAs('editor', <ProfileEditorPage />, { path: '/profiles/new', route: '/profiles/new' })
    fireEvent.change(await screen.findByLabelText('Name'), { target: { value: 'bad-wf' } })
    fireEvent.change(screen.getByLabelText('Ports'), { target: { value: '80' } })
    fireEvent.click(screen.getByRole('button', { name: 'Create profile' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('stage nuclei requires httpx')
  })

  it.each([[null, 61], ['2.5', 150]])('saves batch duration in seconds when the minute value is %s', async (minutes, seconds) => {
    const calls = mockApi((c) => {
      if (c.method === 'PUT') return json({ ...profile, ...(c.body as object) })
      if (c.url.startsWith('/api/profiles')) return json({ items: [{ ...profile, target_batch_seconds: 61 }], total: 1 })
    })
    renderAs('editor', <ProfileEditorPage />, { path: '/profiles/3', route: '/profiles/:id' })
    const batch = await screen.findByLabelText('Batch duration (min)')
    expect(batch).toHaveValue(1.02)
    if (minutes !== null) fireEvent.change(batch, { target: { value: minutes } })
    const enabled = screen.getByRole('switch', { name: 'Profile enabled' })
    expect(enabled).toBeChecked()
    fireEvent.click(enabled)
    fireEvent.click(screen.getByRole('button', { name: 'Save profile' }))

    expect(await screen.findByRole('status')).toHaveTextContent('Saved')
    expect(calls.find((c) => c.method === 'PUT')?.body).toMatchObject({ target_batch_seconds: seconds, enabled: false })
  })

  it('adds a profile exclude with profile_id', async () => {
    const calls = mockApi((c) => (c.method === 'POST' ? json({ id: 12, kind: 'ip', ...(c.body as object) }, 201) : undefined))
    renderAs('editor', <ProfileEditorPage />, { path: '/profiles/3', route: '/profiles/:id' })
    expect(await screen.findByText('172.30.0.99')).toBeInTheDocument()
    expect(calls.some((c) => c.url.startsWith('/api/scope?') && c.url.includes('profile_id=3'))).toBe(true)
    const excl = screen.getByRole('button', { name: 'Add exclusion' }).closest('form')!
    fireEvent.change(within(excl).getByLabelText('Value'), { target: { value: '172.30.0.20' } })
    fireEvent.click(within(excl).getByRole('button', { name: 'Add exclusion' }))
    await waitFor(() => expect(calls.some((c) => c.method === 'POST')).toBe(true))
    expect(calls.find((c) => c.method === 'POST')!.body).toEqual({ value: '172.30.0.20', list: 'exclude', profile_id: 3 })
  })

  it('deletes after confirming', async () => {
    const calls = mockApi((c) => (c.method === 'DELETE' ? new Response(null, { status: 204 }) : undefined))
    renderAs('editor', <ProfileEditorPage />, { path: '/profiles/3', route: '/profiles/:id' })
    fireEvent.click(await screen.findByRole('button', { name: 'Delete profile' }))
    expect(calls.some((c) => c.method === 'DELETE')).toBe(false)
    fireEvent.click(screen.getByRole('button', { name: 'Confirm delete' }))
    await waitFor(() => expect(calls.some((c) => c.method === 'DELETE' && c.url === '/api/profiles/3')).toBe(true))
  })
})
