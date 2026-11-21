import { cleanup, screen, waitFor } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import type { Role } from '../../auth/permissions'
import { ROLES, json, renderAs } from '../../test-utils'
import { aggressiveProfile, route } from './fixture'
import { ProfileEditorPage } from './ProfileEditor'
import { ProfilesPage } from './ProfilesPage'

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
})

// profiles:write, schedules:write and scope:write are editor+.
const canWrite: Record<Role, boolean> = { viewer: false, operator: false, editor: true, admin: true }

const has = (name: string | RegExp) => screen.queryAllByRole('button', { name }).length > 0

describe('ProfilesPage controls per role', () => {
  it.each(ROLES)('%s', async (role) => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => json(route(String(input))))
    renderAs(role, <ProfilesPage />, { path: '/profiles' })
    expect(await screen.findByText(/^Dojo .118$/)).toBeInTheDocument()
    const w = canWrite[role]
    expect(screen.queryByRole('link', { name: 'New profile' }) !== null).toBe(w)
    expect(has('New schedule')).toBe(w)
    expect(has('Edit schedule 7')).toBe(w)
    expect(has('Delete schedule 7')).toBe(w)
    // Dojo schedules are never editable.
    expect(has('Edit schedule 8')).toBe(false)
    expect(has('Delete schedule 8')).toBe(false)
  })
})

describe('ProfileEditorPage controls per role', () => {
  it.each(ROLES)('%s', async (role) => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => json(route(String(input))))
    renderAs(role, <ProfileEditorPage />, { path: '/profiles/3', route: '/profiles/:id' })
    expect(await screen.findByText('172.30.0.99')).toBeInTheDocument()
    const w = canWrite[role]
    await waitFor(() => expect(screen.getByLabelText('Ports')).toHaveValue('22,80,443,8000-8100'))
    await screen.findByRole('switch', { name: 'nmap' })
    if (w) expect(screen.getByLabelText('Ports')).toBeEnabled()
    else {
      expect(screen.getByLabelText('Ports')).toBeDisabled()
      for (const sw of screen.getAllByRole('switch')) {
        expect(sw).toBeDisabled()
      }
    }
    expect(has('Save profile')).toBe(w)
    expect(has('Delete profile')).toBe(w)
    expect(has('Add exclusion')).toBe(w)
    expect(has('Add to include')).toBe(w)
    expect(has(/Delete 172\.30\.0\.99/)).toBe(w)
  })

  it.each(ROLES)('aggressive profile as %s', async (role) => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      const url = String(input)
      if (url.startsWith('/api/profiles')) return json({ items: [aggressiveProfile], total: 1 })
      return json(route(url))
    })
    renderAs(role, <ProfileEditorPage />, { path: '/profiles/4', route: '/profiles/:id' })
    expect(await screen.findByText('Aggressive')).toBeInTheDocument()
    expect(await screen.findByText('172.30.0.99')).toBeInTheDocument()
    const isAdmin = role === 'admin'
    await waitFor(() => expect(screen.getByLabelText('Ports')).toHaveValue('22,80,443,8000-8100'))
    if (isAdmin) expect(screen.getByLabelText('Ports')).toBeEnabled()
    else expect(screen.getByLabelText('Ports')).toBeDisabled()
    expect(has('Save profile')).toBe(isAdmin)
    expect(has('Delete profile')).toBe(isAdmin)
    expect(has('Add exclusion')).toBe(isAdmin)
    expect(has('Add to include')).toBe(isAdmin)
    expect(has(/Delete 172\.30\.0\.99/)).toBe(isAdmin)
    expect(screen.queryByText('Admin only') !== null).toBe(role === 'editor')
  })
})
