import { describe, expect, it } from 'vitest'
import { appRoutes } from '../routes'
import { navItems } from './Layout'

const viewer = ['read', 'export']
const admin = [...viewer, 'users:admin']

describe('navItems', () => {
  it('shows every area to admin', () => {
    expect(navItems(appRoutes, admin).map((r) => r.nav?.label)).toContain('Users')
    expect(navItems(appRoutes, admin)).toHaveLength(appRoutes.filter((r) => r.nav).length)
  })
  it('hides admin-only pages from viewer', () => {
    const labels = navItems(appRoutes, viewer).map((r) => r.nav?.label)
    expect(labels).not.toContain('Users')
    expect(labels).toContain('Hosts')
    expect(labels[0]).toBe('Dashboard')
  })
})
