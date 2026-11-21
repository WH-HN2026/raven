import type { ReactNode } from 'react'
import { useSearchParams } from 'react-router'
import { Th } from './ui'

type Direction = 'asc' | 'desc'

export interface TableSort<C extends string> {
  column: C | undefined
  dir: Direction
  query: { sort?: C; dir?: Direction }
  toggle: (column: C) => void
}

export function useTableSort<C extends string>(
  columns: readonly C[],
  options: { initial?: C; direction?: Direction; prefix?: string; offset?: string; legacyOrder?: boolean } = {},
): TableSort<C> {
  const [params, setParams] = useSearchParams()
  const { initial, direction = 'asc', prefix = '', offset, legacyOrder } = options
  const sortKey = prefix + 'sort'
  const dirKey = prefix + 'dir'
  const explicit = columns.find((c) => c === params.get(sortKey))
  const column = explicit ?? initial
  const rawDir = params.get(dirKey) ?? (legacyOrder ? params.get('order') : null)
  const dir = rawDir === 'asc' || rawDir === 'desc' ? rawDir : explicit ? 'asc' : direction

  return {
    column,
    dir,
    query: { sort: explicit ?? (rawDir ? column : undefined), dir: explicit || rawDir ? dir : undefined },
    toggle: (next) =>
      setParams((current) => {
        const updated = new URLSearchParams(current)
        updated.set(sortKey, next)
        updated.set(dirKey, next === column && dir === 'asc' ? 'desc' : 'asc')
        if (legacyOrder) updated.delete('order')
        if (offset) updated.delete(offset)
        return updated
      }),
  }
}

export function SortTh<C extends string>({
  col,
  sort,
  children,
  className,
}: {
  col: NoInfer<C>
  sort: TableSort<C>
  children: ReactNode
  className?: string
}) {
  const dir = sort.column === col ? sort.dir : undefined
  return (
    <Th scope="col" className={className} aria-sort={dir === 'asc' ? 'ascending' : dir === 'desc' ? 'descending' : 'none'}>
      <button
        type="button"
        onClick={() => sort.toggle(col)}
        className="inline-flex items-center gap-1 whitespace-nowrap text-inherit uppercase hover:text-ink focus-visible:outline-red"
      >
        {children}
        <span aria-hidden="true">{dir === 'asc' ? '↑' : dir === 'desc' ? '↓' : '↕'}</span>
      </button>
    </Th>
  )
}

const collator = new Intl.Collator(undefined, { numeric: true, sensitivity: 'base' })
export type SortValue = string | number | boolean | null | undefined

export function sortRows<Row, C extends string>(
  rows: readonly Row[],
  sort: TableSort<C>,
  values: Record<C, (row: Row) => SortValue>,
): readonly Row[] {
  if (sort.column === undefined) return rows
  const valueOf = values[sort.column]
  return rows
    .map((row) => ({ row, value: valueOf(row) }))
    .sort((a, b) => {
      if (a.value == null) return b.value == null ? 0 : 1
      if (b.value == null) return -1
      const cmp =
        typeof a.value === 'number' && typeof b.value === 'number'
          ? a.value - b.value
          : collator.compare(String(a.value), String(b.value))
      return sort.dir === 'asc' ? cmp : -cmp
    })
    .map(({ row }) => row)
}

export function useListOffset(): [number, (offset: number) => void] {
  const [params, setParams] = useSearchParams()
  const n = Number(params.get('offset') ?? 0)
  const offset = Number.isSafeInteger(n) && n > 0 ? n : 0
  return [offset, (next) => setParams((current) => {
    const updated = new URLSearchParams(current)
    if (next > 0) updated.set('offset', String(next))
    else updated.delete('offset')
    return updated
  })]
}
