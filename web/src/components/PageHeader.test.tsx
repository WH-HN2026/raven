import { cleanup, screen, within } from '@testing-library/react'
import { afterEach, describe, expect, it } from 'vitest'
import { renderAs } from '../test-utils'
import { PageHeader } from './PageHeader'

afterEach(cleanup)

describe('PageHeader', () => {
  it('omits the breadcrumb for a top-level page', () => {
    renderAs('viewer', <PageHeader title="Hosts" />)

    expect(screen.getByRole('heading', { name: 'Hosts' })).toBeInTheDocument()
    expect(screen.queryByRole('navigation', { name: 'Breadcrumb' })).not.toBeInTheDocument()
  })

  it('links the supplied parent and marks the current page', () => {
    renderAs('viewer', <PageHeader title="Run #12" crumbs={[{ label: 'Runs', to: '/runs' }, { label: 'Run #12' }]} />)

    const breadcrumb = screen.getByRole('navigation', { name: 'Breadcrumb' })
    expect(within(breadcrumb).getByRole('link', { name: 'Runs' })).toHaveAttribute('href', '/runs')
    expect(within(breadcrumb).getByText('Run #12')).toHaveAttribute('aria-current', 'page')
    expect(breadcrumb).toHaveTextContent(/^Runs \/ Run #12$/)
  })
})
