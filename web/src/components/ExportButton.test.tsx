import { cleanup, screen } from '@testing-library/react'
import { afterEach, describe, expect, it } from 'vitest'
import { ROLES, renderAs } from '../test-utils'
import { ExportButton, exportHref } from './ExportButton'

afterEach(cleanup)

describe('exportHref', () => {
  it('keeps only the filters the kind honours', () => {
    const p = new URLSearchParams('state=up&port=443&tech=nginx&tag=&q=10.0.0.0/24&offset=50&id=3')
    expect(exportHref('hosts', 'csv', p)).toBe('/api/export/hosts?format=csv&state=up&port=443&tech=nginx&q=10.0.0.0%2F24')
  })
  it('passes findings severity as the page has it', () => {
    const p = new URLSearchParams('severity=Critical,High&active=true&offset=50')
    expect(exportHref('findings', 'json', p)).toBe('/api/export/findings?format=json&severity=Critical%2CHigh&active=true')
  })
  it('changes from/to, targets no filters', () => {
    const p = new URLSearchParams('from=3&to=7&q=x')
    expect(exportHref('changes', 'csv', p)).toBe('/api/export/changes?format=csv&from=3&to=7')
    expect(exportHref('targets', 'json', p)).toBe('/api/export/targets?format=json')
  })
})

describe('ExportButton', () => {
  it.each(ROLES)('%s gets CSV and JSON links with the URL filters', (role) => {
    renderAs(role, <ExportButton kind="hosts" />, { path: '/hosts?state=gone&offset=50', route: '/hosts' })
    expect(screen.getByRole('link', { name: 'Export CSV' })).toHaveAttribute(
      'href',
      '/api/export/hosts?format=csv&state=gone',
    )
    expect(screen.getByRole('link', { name: 'Export JSON' })).toHaveAttribute('download')
  })
})
