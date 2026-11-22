import { cleanup, fireEvent, render, screen } from '@testing-library/react'
import { afterEach, describe, expect, it } from 'vitest'
import { COLLAPSE_AT, CollapsibleText } from './CollapsibleText'

afterEach(cleanup)

describe('CollapsibleText', () => {
  it('renders short text unchanged, without a toggle', () => {
    render(<CollapsibleText text="nginx 1.25" />)
    expect(screen.getByText('nginx 1.25')).toBeInTheDocument()
    expect(screen.queryByRole('button')).toBeNull()
  })

  it('collapses long text and toggles it on click', () => {
    const long = 'SF-Port3001-TCP:V=7.99%I=7%D=' + 'x'.repeat(200) + 'END'
    render(<CollapsibleText text={long} />)
    const btn = screen.getByRole('button', { name: 'Banner: show all' })
    expect(btn).toHaveAttribute('aria-expanded', 'false')
    expect(btn.textContent).toContain(long.slice(0, COLLAPSE_AT) + '…')
    expect(btn.textContent).not.toContain('END')

    fireEvent.click(btn)
    expect(btn).toHaveAttribute('aria-expanded', 'true')
    expect(btn).toHaveAccessibleName('Banner: show less')
    expect(btn.textContent).toContain(long)

    fireEvent.click(btn)
    expect(btn).toHaveAttribute('aria-expanded', 'false')
    expect(btn.textContent).not.toContain('END')
  })
})
