import { cleanup, screen } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import type { Role } from '../../auth/permissions'
import { json, renderAs, ROLES } from '../../test-utils'
import { DashboardPage } from './DashboardPage'
import { dashboard } from './fixture'

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
})

// Dashboard tables are sortable for all roles. The "Start scan" link
// is shown to roles with runs:control.
const canRun: Record<Role, boolean> = { viewer: false, operator: false, editor: true, admin: true }

describe('Dashboard per role', () => {
  it.each(ROLES)('as %s', async (role) => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json(dashboard))
    renderAs(role, <DashboardPage />)
    expect(await screen.findByRole('heading', { name: 'Changes since run #41' })).toBeInTheDocument()
    for (const name of ['Active findings by severity', 'New devices', 'Top web technologies', 'CVE matches', 'Unstable hosts', 'Recent runs']) {
      expect(screen.getByRole('heading', { name })).toBeInTheDocument()
    }
    expect(screen.queryAllByRole('button').filter((b) => !b.closest('th[aria-sort]'))).toEqual([])
    expect(screen.queryByRole('link', { name: 'Start scan' }) !== null).toBe(canRun[role])
  })
})
