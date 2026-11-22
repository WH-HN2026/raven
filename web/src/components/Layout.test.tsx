import { cleanup, fireEvent, render, screen, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { appRoutes } from '../routes'
import { Brand, TopBar, navItems } from './Layout'

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

describe('TopBar', () => {
  it('renders brand, account controls, and all 11 admin tabs in a single-row non-wrapping nav', () => {
    const onLogout = vi.fn()
    const items = navItems(appRoutes, admin)
    render(
      <MemoryRouter initialEntries={['/hosts']}>
        <TopBar
          items={items}
          user={{ id: 1, username: 'admin', role: 'admin', created_at: '2026-01-01T00:00:00Z' }}
          onLogout={onLogout}
        />
      </MemoryRouter>,
    )

    expect(screen.getByRole('img', { name: 'AGH' })).toBeInTheDocument()
    expect(screen.getByRole('img', { name: 'RAVEN' })).toBeInTheDocument()
    expect(screen.getByText('Recon of Assets, Versions, Exposures & Networks')).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'admin' })).toHaveAttribute('href', '/account')
    expect(screen.getByText('admin', { selector: 'span' })).toBeInTheDocument()

    const nav = screen.getByRole('navigation', { name: 'Main' })
    expect(nav.className).toContain('flex-nowrap')
    expect(nav.className).toContain('overflow-x-auto')
    expect(nav.className).not.toContain('flex-wrap')

    const links = within(nav).getAllByRole('link')
    expect(links).toHaveLength(11)
    expect(links.map((l) => l.textContent)).toContain('Import/Export')
    expect(links.map((l) => l.textContent)).toContain('Users')

    for (const link of links) {
      expect(link.className).toContain('shrink-0')
      expect(link.className).toContain('whitespace-nowrap')
      expect(link.className).toContain('h-12')
    }

    const activeLink = within(nav).getByRole('link', { name: 'Hosts' })
    expect(activeLink.className).toContain('border-b-red')
    expect(activeLink.className).toContain('font-medium')

    const inactiveLink = within(nav).getByRole('link', { name: 'Dashboard' })
    expect(inactiveLink.className).toContain('border-b-transparent')

    fireEvent.click(screen.getByRole('button', { name: 'Log out' }))
    expect(onLogout).toHaveBeenCalledTimes(1)
  })

  it('renders 10 viewer tabs without Users', () => {
    const items = navItems(appRoutes, viewer)
    render(
      <MemoryRouter initialEntries={['/']}>
        <TopBar
          items={items}
          user={{ id: 2, username: 'viewer', role: 'viewer', created_at: '2026-01-01T00:00:00Z' }}
          onLogout={() => {}}
        />
      </MemoryRouter>,
    )

    const nav = screen.getByRole('navigation', { name: 'Main' })
    const links = within(nav).getAllByRole('link')
    expect(links).toHaveLength(10)
    expect(links.map((l) => l.textContent)).not.toContain('Users')
    expect(links.map((l) => l.textContent)).toContain('Import/Export')
  })
})
