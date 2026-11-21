import { cleanup, screen } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { Guard } from './components/Layout'
import { appRoutes } from './routes'
import { json, renderAs } from './test-utils'

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
})

// Sweep: a viewer sees no mutation control on any page in the nav (pages with
// their own roles.test.tsx check every role in detail).
const MUTATION = /^(add|create|new|delete|remove|edit|save|start|stop|import|upload|run|disable|enable|reset password|change|triage)\b/i

describe('viewer sees no mutation controls', () => {
  it.each(appRoutes.filter((r) => r.nav && !r.path.includes(':')).map((r) => [r.path, r] as const))(
    '%s',
    async (_path, route) => {
      vi.spyOn(globalThis, 'fetch').mockImplementation(async () => json({ items: [], total: 0 }))
      renderAs('viewer', <Guard route={route} />, { path: route.path })
      await screen.findAllByRole('heading', { level: 1 })
      await new Promise((r) => setTimeout(r, 0))
      const names = screen.queryAllByRole('button').map((b) => b.textContent?.trim() ?? '')
      expect(names.filter((n) => MUTATION.test(n))).toEqual([])
      expect(screen.queryByRole('form')).toBeNull()
    },
  )
})
