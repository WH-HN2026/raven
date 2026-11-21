import { cleanup, screen } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import type { Role } from '../../auth/permissions'
import { ROLES, json, renderAs } from '../../test-utils'
import { ExchangePage } from './index'

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
})

// import: editor+; export: every role.
const canImport: Record<Role, boolean> = { viewer: false, operator: false, editor: true, admin: true }

describe('ExchangePage controls per role', () => {
  it.each(ROLES)('%s', async (role) => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(async () => json({ items: [], total: 0 }))
    renderAs(role, <ExchangePage />, { path: '/exchange' })
    expect(await screen.findByRole('link', { name: 'Download' })).toBeInTheDocument()
    expect(screen.queryByText('Import scan results') !== null).toBe(canImport[role])
    expect(screen.queryByLabelText('File') !== null).toBe(canImport[role])
    expect(screen.queryByRole('button', { name: 'Import' }) !== null).toBe(canImport[role])
  })
})
