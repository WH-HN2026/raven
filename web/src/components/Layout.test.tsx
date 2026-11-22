import { cleanup, render, screen } from '@testing-library/react'
import { afterEach, describe, expect, it } from 'vitest'
import { appRoutes } from '../routes'
import { Brand, navItems } from './Layout'

afterEach(cleanup)

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

describe('Brand', () => {
  it('renders the AGH logo, RAVEN wordmark SVG, and subtitle', () => {
    render(<Brand />)
    expect(screen.getByRole('img', { name: 'AGH' })).toBeInTheDocument()
    const wordmark = screen.getByRole('img', { name: 'RAVEN' })
    expect(wordmark).toHaveAttribute('src', expect.stringContaining('raven-logo-white.svg'))
    expect(screen.getByText('Recon of Assets, Versions, Exposures & Networks')).toBeInTheDocument()
  })
})
