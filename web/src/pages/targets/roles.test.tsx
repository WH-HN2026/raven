import { cleanup, screen, waitFor } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { ROLES, json, renderAs } from '../../test-utils'
import type { Role } from '../../auth/permissions'
import { TargetsPage } from './index'

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
})

// What each role may do on /targets: targets:write / import (editor+), scope:write+scope:global (admin).
const expected: Record<Role, { addTargets: boolean; upload: boolean; deleteTarget: boolean; scope: boolean }> = {
  viewer: { addTargets: false, upload: false, deleteTarget: false, scope: false },
  operator: { addTargets: false, upload: false, deleteTarget: false, scope: false },
  editor: { addTargets: true, upload: true, deleteTarget: true, scope: false },
  admin: { addTargets: true, upload: true, deleteTarget: true, scope: true },
}

describe('TargetsPage controls per role', () => {
  it.each(ROLES)('%s', async (role) => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) =>
      String(input).startsWith('/api/scope')
        ? json({ items: [{ id: 5, kind: 'cidr', value: '10.9.0.0/16', list: 'exclude', note: '' }], total: 1 })
        : json({ items: [{ id: 1, kind: 'ip', value: '10.0.0.7', source: 'manual', tags: [], note: '' }], total: 1 }),
    )
    renderAs(role, <TargetsPage />, { path: '/targets' })
    expect(await screen.findByText('10.0.0.7')).toBeInTheDocument()
    expect(await screen.findByText('10.9.0.0/16')).toBeInTheDocument()
    const e = expected[role]
    const has = (name: string | RegExp) => screen.queryAllByRole('button', { name }).length > 0

    expect(has('Add targets')).toBe(e.addTargets)
    expect(has('Upload CSV / JSON') || screen.queryByLabelText('File') !== null).toBe(e.upload)
    expect(has('Delete 10.0.0.7')).toBe(e.deleteTarget)
    expect(has(/Delete 10\.9\.0\.0\/16/)).toBe(e.scope)
    expect(has('Add exclusion')).toBe(e.scope)
    expect(has('Add to include')).toBe(e.scope)
    await waitFor(() => expect(screen.queryByText('Admin only') !== null).toBe(!e.scope))
  })
})
