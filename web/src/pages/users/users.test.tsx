import { cleanup, fireEvent, screen, within } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import type { Schemas } from '../../api/client'
import { Guard, navItems } from '../../components/Layout'
import { appRoutes } from '../../routes'
import { ROLES, ROLE_PERMS, json, renderAs } from '../../test-utils'
import { routes } from './index'

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
})

const users: Schemas['User'][] = [
  { id: 1, username: 'me', role: 'admin', disabled: false, created_at: '2026-11-21T10:00:00Z' },
  { id: 2, username: 'eve', role: 'editor', disabled: false, created_at: '2026-11-21T10:00:00Z' },
]

const tokens: Schemas['ApiToken'][] = [
  {
    id: 10,
    user_id: 2,
    username: 'eve',
    role: 'editor',
    name: 'mcp-agent',
    created_at: '2026-11-21T11:00:00Z',
    last_used_at: null,
  },
]

const page = <Guard route={routes[0]!} />

function mockUsersAndTokens(extra?: (url: string, init?: RequestInit) => Response | undefined) {
  return vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
    const url = String(input)
    if (extra) {
      const res = extra(url, init)
      if (res) return res
    }
    if (url.startsWith('/api/tokens')) return json({ items: tokens, total: tokens.length })
    return json({ items: users, total: users.length })
  })
}

describe('Users page per role', () => {
  it.each(ROLES)('%s', async (role) => {
    mockUsersAndTokens()
    renderAs(role, page, { path: '/users' })
    const isAdmin = role === 'admin'
    expect(navItems(appRoutes, ROLE_PERMS[role]).some((r) => r.path === '/users')).toBe(isAdmin)
    if (isAdmin) {
      const usersTable = await screen.findByRole('table', { name: 'Users' })
      expect(await within(usersTable).findByText('eve')).toBeInTheDocument()
      expect(screen.getByRole('button', { name: 'Add user' })).toBeInTheDocument()
      expect(within(usersTable).getAllByRole('button', { name: 'Delete' })).toHaveLength(2)
      const tokensTable = await screen.findByRole('table', { name: 'API tokens' })
      expect(await within(tokensTable).findByText('mcp-agent')).toBeInTheDocument()
      expect(screen.getByRole('button', { name: 'Issue token' })).toBeInTheDocument()
    } else {
      expect(screen.getByText('No access.')).toBeInTheDocument()
      expect(screen.queryByRole('button')).toBeNull()
      expect(screen.queryByRole('table')).toBeNull()
    }
  })
})

describe('Users page actions', () => {
  it('creates a user with the chosen role', async () => {
    const fetchMock = mockUsersAndTokens((url, init) =>
      url === '/api/users' && init?.method === 'POST'
        ? json({ id: 3, username: 'vic', role: 'viewer', disabled: false }, 201)
        : undefined,
    )
    renderAs('admin', page, { path: '/users' })
    const usersTable = await screen.findByRole('table', { name: 'Users' })
    await within(usersTable).findByText('eve')
    const form = screen.getByRole('form', { name: 'Add user' })
    fireEvent.change(within(form).getByLabelText('Username'), { target: { value: 'vic' } })
    fireEvent.change(within(form).getByLabelText(/Password/), { target: { value: 'short' } })
    expect(within(form).getByRole('button', { name: 'Add user' })).toBeDisabled()
    fireEvent.change(within(form).getByLabelText(/Password/), { target: { value: 'long-enough-pass' } })
    fireEvent.change(within(form).getByLabelText('Role'), { target: { value: 'viewer' } })
    fireEvent.click(within(form).getByRole('button', { name: 'Add user' }))
    expect(await screen.findByText('Created vic')).toBeInTheDocument()
    const post = fetchMock.mock.calls.find(([u, i]) => u === '/api/users' && i?.method === 'POST')!
    expect(JSON.parse(post[1]?.body as string)).toEqual({ username: 'vic', password: 'long-enough-pass', role: 'viewer' })
  })

  it('shows the 409 rule message inline when demoting yourself', async () => {
    const fetchMock = mockUsersAndTokens((url, init) =>
      url.startsWith('/api/users/') && init?.method === 'PATCH'
        ? json({ error: { code: 'not_allowed', message: 'not allowed: cannot change your own role' } }, 409)
        : undefined,
    )
    renderAs('admin', page, { path: '/users' })
    fireEvent.change(await screen.findByLabelText('Role of me'), { target: { value: 'viewer' } })
    expect(await screen.findByRole('alert')).toHaveTextContent('cannot change your own role')
    const patch = fetchMock.mock.calls.find(([, i]) => i?.method === 'PATCH')!
    expect(patch[0]).toBe('/api/users/1')
    expect(JSON.parse(patch[1]?.body as string)).toEqual({ role: 'viewer' })
    expect(screen.getByLabelText('Role of me')).toHaveValue('admin')
  })

  it('disables, resets a password and deletes after confirm', async () => {
    const fetchMock = mockUsersAndTokens((url, init) => {
      if (url.startsWith('/api/users/') && init?.method === 'DELETE') return new Response(null, { status: 204 })
      if (url.startsWith('/api/users/') && init?.method === 'PATCH') return json(users[1])
      return undefined
    })
    renderAs('admin', page, { path: '/users' })
    const usersTable = await screen.findByRole('table', { name: 'Users' })
    const row = (await within(usersTable).findByText('eve')).closest('tr')!
    fireEvent.click(within(row).getByRole('button', { name: 'Disable' }))
    await vi.waitFor(() => expect(fetchMock.mock.calls.some(([, i]) => i?.body === '{"disabled":true}')).toBe(true))

    fireEvent.click(within(row).getByRole('button', { name: 'Reset password' }))
    const reset = await screen.findByRole('form', { name: 'Reset password of eve' })
    fireEvent.change(within(reset).getByLabelText(/New password/), { target: { value: 'another-long-pass' } })
    fireEvent.click(within(reset).getByRole('button', { name: 'Save password' }))
    expect(await screen.findByText('Password reset')).toBeInTheDocument()
    expect(fetchMock.mock.calls.some(([, i]) => i?.body === '{"password":"another-long-pass"}')).toBe(true)

    fireEvent.click(within(row).getByRole('button', { name: 'Delete' }))
    expect(fetchMock.mock.calls.some(([, i]) => i?.method === 'DELETE')).toBe(false)
    fireEvent.click(screen.getByRole('button', { name: 'Confirm delete' }))
    await vi.waitFor(() => {
      const del = fetchMock.mock.calls.find(([, i]) => i?.method === 'DELETE')
      expect(del?.[0]).toBe('/api/users/2')
    })
  })
})

describe('API tokens actions', () => {
  it('issues a token, displays it once with copy, and revokes after confirm', async () => {
    const writeText = vi.fn().mockResolvedValue(undefined)
    Object.defineProperty(navigator, 'clipboard', { value: { writeText }, configurable: true })

    const fetchMock = mockUsersAndTokens((url, init) => {
      if (url === '/api/tokens' && init?.method === 'POST') {
        return json(
          {
            id: 11,
            user_id: 2,
            username: 'eve',
            role: 'editor',
            name: 'ci-mcp',
            created_at: '2026-11-21T12:00:00Z',
            last_used_at: null,
            token: 'rvn_once_secret_token_value',
          },
          201,
        )
      }
      if (url === '/api/tokens/10' && init?.method === 'DELETE') return new Response(null, { status: 204 })
      return undefined
    })

    renderAs('admin', page, { path: '/users' })
    const tokensTable = await screen.findByRole('table', { name: 'API tokens' })
    await within(tokensTable).findByText('mcp-agent')

    const form = screen.getByRole('form', { name: 'Issue API token' })
    fireEvent.change(within(form).getByLabelText('Token name'), { target: { value: 'ci-mcp' } })
    fireEvent.change(within(form).getByLabelText('User'), { target: { value: '2' } })
    fireEvent.click(within(form).getByRole('button', { name: 'Issue token' }))

    expect(await screen.findByTestId('issued-token')).toHaveTextContent('rvn_once_secret_token_value')
    const banner = screen.getByRole('status')
    expect(within(banner).getByText('ci-mcp')).toBeInTheDocument()
    expect(within(banner).getByText('eve (editor)')).toBeInTheDocument()
    expect(within(banner).queryByText('Shown once')).toBeNull()
    const post = fetchMock.mock.calls.find(([u, i]) => u === '/api/tokens' && i?.method === 'POST')!
    expect(JSON.parse(post[1]?.body as string)).toEqual({ name: 'ci-mcp', user_id: 2 })

    fireEvent.click(screen.getByRole('button', { name: 'Copy' }))
    await vi.waitFor(() => expect(writeText).toHaveBeenCalledWith('rvn_once_secret_token_value'))
    expect(await screen.findByRole('button', { name: 'Copied' })).toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: 'Dismiss' }))
    expect(screen.queryByTestId('issued-token')).toBeNull()

    // Revoke requires confirm.
    const row = within(tokensTable).getByText('mcp-agent').closest('tr')!
    fireEvent.click(within(row).getByRole('button', { name: 'Revoke' }))
    expect(fetchMock.mock.calls.some(([u, i]) => u === '/api/tokens/10' && i?.method === 'DELETE')).toBe(false)
    fireEvent.click(screen.getByRole('button', { name: 'Confirm revoke' }))
    await vi.waitFor(() => {
      expect(fetchMock.mock.calls.some(([u, i]) => u === '/api/tokens/10' && i?.method === 'DELETE')).toBe(true)
    })
  })
})
