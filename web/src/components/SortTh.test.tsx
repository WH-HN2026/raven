import { cleanup, fireEvent, render, screen, within } from '@testing-library/react'
import { MemoryRouter, useLocation } from 'react-router'
import { afterEach, describe, expect, it } from 'vitest'
import { SortTh, sortRows, useTableSort } from './SortTh'

afterEach(cleanup)

const items = [
  { name: 'Zulu', count: 2 },
  { name: 'Alpha', count: 10 },
]

function Example() {
  const sort = useTableSort(['name', 'count'], { offset: 'offset' })
  const rows = sortRows(items, sort, { name: (row) => row.name, count: (row) => row.count })
  return (
    <>
      <output>{useLocation().search}</output>
      <table>
        <thead>
          <tr>
            <SortTh sort={sort} col="name">Name</SortTh>
            <SortTh sort={sort} col="count">Count</SortTh>
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => <tr key={row.name}><td>{row.name}</td><td>{row.count}</td></tr>)}
        </tbody>
      </table>
    </>
  )
}

describe('SortTh', () => {
  it('toggles ascending and descending, sets aria-sort and keeps the URL filters', () => {
    render(
      <MemoryRouter initialEntries={['/?q=test&offset=50']}>
        <Example />
      </MemoryRouter>,
    )
    const name = screen.getByRole('columnheader', { name: 'Name' })
    const count = screen.getByRole('columnheader', { name: 'Count' })
    const button = within(name).getByRole('button', { name: 'Name' })
    const firstRow = () => within(screen.getAllByRole('row')[1]!).getAllByRole('cell')[0]
    expect(name).toHaveAttribute('aria-sort', 'none')
    expect(within(name).getByText('↕')).toHaveAttribute('aria-hidden', 'true')

    fireEvent.click(button)
    expect(name).toHaveAttribute('aria-sort', 'ascending')
    expect(count).toHaveAttribute('aria-sort', 'none')
    expect(screen.getByRole('status')).toHaveTextContent('?q=test&sort=name&dir=asc')
    expect(firstRow()).toHaveTextContent('Alpha')

    fireEvent.click(button)
    expect(name).toHaveAttribute('aria-sort', 'descending')
    expect(screen.getByRole('status')).toHaveTextContent('?q=test&sort=name&dir=desc')
    expect(firstRow()).toHaveTextContent('Zulu')
  })

  it('initializes from the URL and compares numbers numerically', () => {
    render(
      <MemoryRouter initialEntries={['/?sort=count&dir=desc']}>
        <Example />
      </MemoryRouter>,
    )
    expect(screen.getByRole('columnheader', { name: 'Count' })).toHaveAttribute('aria-sort', 'descending')
    expect(screen.getAllByRole('row')[1]).toHaveTextContent('Alpha')
    fireEvent.click(screen.getByRole('button', { name: 'Count' }))
    expect(screen.getAllByRole('row')[1]).toHaveTextContent('Zulu')
  })
})
