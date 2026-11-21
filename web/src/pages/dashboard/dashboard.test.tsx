import { cleanup, screen, within } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { json, renderAs } from '../../test-utils'
import { diffRows } from '../changes/ui'
import { DashboardPage } from './DashboardPage'
import { dashboard } from './fixture'
import { changeText, findingsLink, hostsLink, pct, severityBars, unstablePattern, type Dashboard } from './ui'

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
})

function at<T>(a: T[], i: number): T {
  const v = a[i]
  if (v === undefined) throw new Error('missing item ' + i)
  return v
}

describe('dashboard helpers', () => {
  it('scales bars to the largest value', () => {
    expect(pct(0, 10)).toBe('0%')
    expect(pct(5, 0)).toBe('0%')
    expect(pct(10, 10)).toBe('100%')
    expect(pct(1, 1000)).toBe('2%')
    expect(pct(7, 14)).toBe('50%')
  })

  it('splits Info off the severity bars', () => {
    const { bars, info } = severityBars(dashboard.findings)
    expect(info).toBe(31)
    expect(bars.map((b) => [b.severity, b.key, b.count, b.width])).toEqual([
      ['Critical', 'critical', 2, '14%'],
      ['High', 'high', 14, '100%'],
      ['Medium', 'medium', 0, '0%'],
      ['Low', 'low', 7, '50%'],
    ])
  })

  it('builds pre-filtered links', () => {
    expect(findingsLink('High')).toBe('/findings?active=true&severity=High')
    expect(findingsLink()).toBe('/findings?active=true')
    expect(hostsLink({ state: 'unstable' })).toBe('/hosts?state=unstable')
    expect(hostsLink({ tech: 'Apache HTTP Server' })).toBe('/hosts?tech=Apache+HTTP+Server')
  })

  it('describes each change in one line', () => {
    const c = dashboard.changes as NonNullable<Dashboard['changes']>
    const rows = diffRows(c)
    expect(rows.map(changeText)).toEqual(['Host up · 8080', 'version: 2.4.49 → 2.4.50', 'Host down · was 22'])
  })

  it('describes the unstable pattern', () => {
    expect(unstablePattern(at(dashboard.unstable_hosts, 0))).toBe('up in 3 of last 5 runs')
    expect(unstablePattern(at(dashboard.unstable_hosts, 1))).toMatch(/^last seen /)
  })
})

describe('DashboardPage', () => {
  it('renders every block with links into the other pages', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json(dashboard))
    renderAs('viewer', <DashboardPage />)

    expect(await screen.findByRole('heading', { name: 'Changes since run #41' })).toBeInTheDocument()
    expect(screen.getByText('1,204')).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Compare runs' })).toHaveAttribute('href', '/changes?from=41&to=42')

    const changes = screen.getByRole('table', { name: 'Changes' })
    expect(within(changes).getByText('version: 2.4.49 → 2.4.50')).toBeInTheDocument()

    const sev = screen.getByRole('list', { name: 'Active findings by severity' })
    expect(within(sev).getByRole('link', { name: /^high$/i })).toHaveAttribute('href', '/findings?active=true&severity=High')
    expect(screen.getByText(/31 informational/)).toBeInTheDocument()

    const devices = screen.getByRole('list', { name: 'New devices' })
    expect(within(devices).getByRole('link', { name: '172.30.0.12' })).toHaveAttribute('href', '/hosts/172.30.0.12')
    expect(within(devices).getByText('jenkins.lab · 8080/tcp')).toBeInTheDocument()

    const tech = screen.getByRole('list', { name: 'Top web technologies' })
    expect(within(tech).getByRole('link', { name: 'Nginx' })).toHaveAttribute('href', '/hosts?tech=Nginx')

    const cve = screen.getByRole('table', { name: 'CVE matches' })
    expect(within(cve).getByText('9.8')).toBeInTheDocument()

    const unstable = screen.getByRole('list', { name: 'Unstable hosts' })
    expect(within(unstable).getByText('up in 3 of last 5 runs')).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'All unstable (3)' })).toHaveAttribute('href', '/hosts?state=unstable')

    const runs = screen.getByRole('table', { name: 'Recent runs' })
    expect(within(runs).getByRole('link', { name: '#42' })).toHaveAttribute('href', '/runs/42')
    expect(within(runs).getByText('1 min 30 s')).toBeInTheDocument()
    expect(within(runs).getByText('2/2 batches')).toBeInTheDocument()
  })

  it('handles an empty installation', async () => {
    const empty: Dashboard = {
      findings: { by_severity: dashboard.findings.by_severity.map((s) => ({ ...s, count: 0 })), total: 0 },
      hosts: { active: 0, unstable: 0, inactive: 0, services_open: 0 },
      changes: null,
      new_hosts: [],
      new_hosts_total: 0,
      unstable_hosts: [],
      technologies: [],
      cve_matches: [],
      cve_total: 0,
      runs: [],
      latest_run: null,
    }
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json(empty))
    renderAs('viewer', <DashboardPage />)
    expect(await screen.findByText('No two finished runs to compare')).toBeInTheDocument()
    expect(screen.getByText('No runs')).toBeInTheDocument()
    expect(screen.getByText('No CVE matches')).toBeInTheDocument()
    expect(screen.getByText('No unstable or inactive hosts')).toBeInTheDocument()
  })

  it('shows an API error', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(json({ error: { code: 'internal', message: 'dashboard failed' } }, 500))
    renderAs('viewer', <DashboardPage />)
    expect(await screen.findByText(/Cannot load dashboard: dashboard failed/)).toBeInTheDocument()
  })
})
