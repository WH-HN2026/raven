import { cleanup, fireEvent, screen } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { ROLES, json, renderAs } from '../../test-utils'
import { AccountPage } from './index'

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
})

function fill(current: string, next: string, repeat = next) {
  fireEvent.change(screen.getByLabelText('Current password'), { target: { value: current } })
  fireEvent.change(screen.getByLabelText(/^New password/), { target: { value: next } })
  fireEvent.change(screen.getByLabelText('Repeat new password'), { target: { value: repeat } })
}

describe('AccountPage', () => {
  it.each(ROLES)('every role can change its own password (%s)', async (role) => {
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(null, { status: 204 }))
    renderAs(role, <AccountPage />, { path: '/account' })
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
    renderAs('viewer', <AccountPage />, { path: '/account' })
    fill('bad-password', 'new-long-password')
    fireEvent.click(screen.getByRole('button', { name: 'Change password' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('current password is wrong')
  })
})
