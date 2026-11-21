import { cleanup, fireEvent, screen } from '@testing-library/react'
import { Route, Routes } from 'react-router'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { Layout } from '../../components/Layout'
import { ROLES, json, renderAs } from '../../test-utils'
import { ProfilePage, routes } from './index'

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
})

function fill(current: string, next: string, repeat = next) {
  fireEvent.change(screen.getByLabelText('Current password'), { target: { value: current } })
  fireEvent.change(screen.getByLabelText(/^New password/), { target: { value: next } })
  fireEvent.change(screen.getByLabelText('Repeat new password'), { target: { value: repeat } })
}

describe('ProfilePage', () => {
  it.each(ROLES)('opens the signed-in user profile from the top bar (%s)', async (role) => {
    renderAs(
      role,
      <Routes>
        <Route element={<Layout routes={routes} />}>
          <Route index element={<h1>Dashboard</h1>} />
          {routes.map((route) => (
            <Route key={route.path} path={route.path} element={route.element} />
          ))}
        </Route>
      </Routes>,
      { route: '*' },
    )

    fireEvent.click(screen.getByRole('link', { name: 'me' }))

    expect(await screen.findByRole('heading', { name: 'Profile' })).toBeInTheDocument()
    expect(screen.getByText('Username').nextElementSibling).toHaveTextContent('me')
    expect(screen.getByText('Role').nextElementSibling).toHaveTextContent(role)
    expect(screen.getByRole('form', { name: 'Change password' })).toBeInTheDocument()
    expect(screen.queryByRole('navigation', { name: 'Breadcrumb' })).not.toBeInTheDocument()
  })

  it.each(ROLES)('every role can change its own password (%s)', async (role) => {
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(null, { status: 204 }))
    renderAs(role, <ProfilePage />, { path: '/account' })
    const submit = screen.getByRole('button', { name: 'Change password' })
    fill('old-password', 'short')
    expect(submit).toBeDisabled()
    fill('old-password', 'new-long-password', 'different-password')
    expect(screen.getByRole('alert')).toHaveTextContent('Passwords do not match')
    expect(submit).toBeDisabled()
    fill('old-password', 'new-long-password')
    fireEvent.click(submit)
    expect(await screen.findByText('Password changed')).toBeInTheDocument()
    const [url, init] = fetchMock.mock.calls[0]!
    expect(url).toBe('/api/auth/me/password')
    expect(init?.method).toBe('PATCH')
    expect(JSON.parse(init?.body as string)).toEqual({
      current_password: 'old-password',
      new_password: 'new-long-password',
    })
  })

  it('shows a wrong current password inline', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      json({ error: { code: 'wrong_password', message: 'current password is wrong' } }, 400),
    )
    renderAs('viewer', <ProfilePage />, { path: '/account' })
    fill('bad-password', 'new-long-password')
    fireEvent.click(screen.getByRole('button', { name: 'Change password' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('current password is wrong')
  })
})
