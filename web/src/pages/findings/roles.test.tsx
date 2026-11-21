import { cleanup, screen } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import type { Role } from '../../auth/permissions'
import { json, renderAs } from '../../test-utils'
import { FindingsPage } from './FindingsPage'
import type { Finding } from './ui'

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
})

const finding: Finding = {
  id: 7,
  ip: '172.30.0.10',
  title: 'Telnet service exposed',
  severity: 'High',
  active: true,
  dojo_url: 'http://dojo.local/finding/7',
}

// Triage (status, severity, notes) needs findings:edit: operator and up.
const cases: [Role, boolean][] = [
  ['viewer', false],
  ['operator', true],
  ['editor', true],
  ['admin', true],
]

describe('Findings controls per role', () => {
  it.each(cases)('as %s, triage form shown: %s', async (role, canTriage) => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(async () => json({ items: [finding], total: 1 }))
    renderAs(role, <FindingsPage />, { path: '/findings?id=7', route: '/findings' })
    expect(await screen.findByRole('heading', { name: 'Telnet service exposed' })).toBeInTheDocument()
    expect(!!screen.queryByRole('form', { name: 'Triage' })).toBe(canTriage)
    expect(!!screen.queryByRole('button', { name: 'Save to DefectDojo' })).toBe(canTriage)
    expect(!!screen.queryByRole('textbox', { name: 'Add a note' })).toBe(canTriage)
  })
})
