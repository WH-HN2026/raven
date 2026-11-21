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

const page = <Guard route={routes[0]!} />

describe('Users page per role', () => {
  it.each(ROLES)('%s', async (role) => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({ items: users, total: 2 }))
    renderAs(role, page, { path: '/users' })
    const isAdmin = role === 'admin'
    expect(navItems(appRoutes, ROLE_PERMS[role]).some((r) => r.path === '/users')).toBe(isAdmin)
    if (isAdmin) {
      expect(await screen.findByText('eve')).toBeInTheDocument()
      expect(screen.getByRole('button', { name: 'Add user' })).toBeInTheDocument()
      expect(screen.getAllByRole('button', { name: 'Delete' })).toHaveLength(2)
    } else {
      expect(screen.getByText('No access.')).toBeInTheDocument()
      expect(screen.queryByRole('button')).toBeNull()
      expect(screen.queryByRole('table')).toBeNull()
    }
  })
})

describe('Users page actions', () => {
  it('creates a user with the chosen role', async () => {
    const fetchMock = vi
      .spyOn(globalThis, 'fetch')
      .mockImplementation(async (_input, init) =>
        init?.method === 'POST'
          ? json({ id: 3, username: 'vic', role: 'viewer', disabled: false }, 201)
          : json({ items: users, total: 2 }),
      )
    renderAs('admin', page, { path: '/users' })
    await screen.findByText('eve')
    const form = screen.getByRole('form', { name: 'Add user' })
    fireEvent.change(within(form).getByLabelText('Username'), { target: { value: 'vic' } })
    fireEvent.change(within(form).getByLabelText(/Password/), { target: { value: 'short' } })
    expect(within(form).getByRole('button', { name: 'Add user' })).toBeDisabled()
    fireEvent.change(within(form).getByLabelText(/Password/), { target: { value: 'long-enough-pass' } })
    fireEvent.change(within(form).getByLabelText('Role'), { target: { value: 'viewer' } })
    fireEvent.click(within(form).getByRole('button', { name: 'Add user' }))
    expect(await screen.findByText('Created vic')).toBeInTheDocument()
    const post = fetchMock.mock.calls.find(([, i]) => i?.method === 'POST')!
    expect(post[0]).toBe('/api/users')
    expect(JSON.parse(post[1]?.body as string)).toEqual({ username: 'vic', password: 'long-enough-pass', role: 'viewer' })
  })

  it('shows the 409 rule message inline when demoting yourself', async () => {
    const fetchMock = vi
      .spyOn(globalThis, 'fetch')
      .mockImplementation(async (_input, init) =>
        init?.method === 'PATCH'
          ? json({ error: { code: 'not_allowed', message: 'not allowed: cannot change your own role' } }, 409)
          : json({ items: users, total: 2 }),
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
    const fetchMock = vi
      .spyOn(globalThis, 'fetch')
      .mockImplementation(async (_input, init) =>
        init?.method === 'DELETE'
          ? new Response(null, { status: 204 })
          : init?.method === 'PATCH'
            ? json(users[1])
            : json({ items: users, total: 2 }),
      )
    renderAs('admin', page, { path: '/users' })
    const row = (await screen.findByText('eve')).closest('tr')!
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
