import { cleanup, screen } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import type { Schemas } from '../../api/client'
import type { Role } from '../../auth/permissions'
import { ROLES, json, renderAs } from '../../test-utils'
import { SignatureEditorPage } from './SignatureEditor'
import { SignaturesList } from './SignaturesList'

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
})

const sig: Schemas['Signature'] = {
  id: 9,
  name: 'my-check',
  template_yaml: 'id: my-check\ninfo:\n  name: My check\n  severity: info\n',
  enabled: true,
  valid: true,
  validation_error: '',
  builtin: false,
  created_by: 1,
  created_at: '2026-11-21T10:00:00Z',
}

// signatures:write = editor and admin.
const writes = (role: Role) => role === 'editor' || role === 'admin'

describe('Signatures controls per role', () => {
  it.each(ROLES)('list as %s', async (role) => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({ items: [sig], total: 1 }))
    renderAs(role, <SignaturesList />, { path: '/signatures' })
    expect(await screen.findByText('My check')).toBeInTheDocument()
    expect(screen.queryAllByRole('checkbox')).toHaveLength(writes(role) ? 1 : 0)
    expect(screen.queryByRole('link', { name: 'New signature' }) !== null).toBe(writes(role))
  })

  it.each(ROLES)('custom signature as %s', async (role) => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json(sig))
    renderAs(role, <SignatureEditorPage />, { path: '/signatures/9', route: '/signatures/:id' })
    expect(await screen.findByRole('heading', { level: 1, name: /My check/ })).toBeInTheDocument()
    const buttons = screen.queryAllByRole('button').map((b) => b.textContent)
    if (writes(role)) {
      expect(buttons).toEqual(['Validate', 'Save', 'Delete', 'Test'])
      expect(screen.getByLabelText('Template YAML')).not.toHaveAttribute('readonly')
    } else {
      expect(buttons).toEqual([])
      expect(screen.getByLabelText('Template YAML')).toHaveAttribute('readonly')
      expect(screen.queryByRole('checkbox')).toBeNull()
    }
  })
})
