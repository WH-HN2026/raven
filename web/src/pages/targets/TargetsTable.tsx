import { SortTh, useTableSort, useListOffset } from '../../components/SortTh'
import { keepPreviousData, useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useEffect } from 'react'
import { api } from '../../api/client'
import { useCan } from '../../auth/hooks'
import {
  Alert,
  Button,
  EmptyRow,
  ErrorText,
  Pagination,
  SectionHeading,
  Table,
  Td,
  Th,
  THeadRow,
  Tr,
} from '../../components/ui'
import { targetsKey } from './ui'

const PAGE = 50

export function TargetsTable() {
  const qc = useQueryClient()
  const canWrite = useCan('targets:write')
  const [offset, setOffset] = useListOffset()
  const sort = useTableSort(['value', 'kind', 'source', 'tags', 'note', 'created_at'], { offset: 'offset' })
  const q = useQuery({
    queryKey: [...targetsKey, offset, sort.query],
    queryFn: () => api.get('/targets', { query: { limit: PAGE, offset, ...sort.query } }),
    placeholderData: keepPreviousData,
  })
  const del = useMutation({
    mutationFn: (id: number) => api.delete('/targets/{id}', { params: { id } }),
    onSuccess: () => qc.invalidateQueries({ queryKey: targetsKey }),
  })

  const total = q.data?.total ?? 0
  const items = q.data?.items ?? []
  // Step back a page if the last row of the last page was deleted.
  useEffect(() => {
    if (q.isSuccess && !q.isFetching && offset >= total && offset > 0) {
      setOffset(Math.floor(Math.max(0, total - 1) / PAGE) * PAGE)
    }
  }, [q.isSuccess, q.isFetching, offset, total, setOffset])

  return (
    <section className="flex flex-col gap-4">
      <SectionHeading>Targets · {total} entr{total === 1 ? 'y' : 'ies'}</SectionHeading>
      {q.error && <ErrorText>Cannot load targets: {q.error.message}</ErrorText>}
      {del.error && <Alert>Delete failed: {del.error.message}</Alert>}
      <div className="bg-white px-5 pt-1 pb-2">
        <Table minWidth={860}>
          <thead>
            <THeadRow>
              <SortTh sort={sort} col="value">Target</SortTh>
              <SortTh sort={sort} col="kind">Type</SortTh>
              <SortTh sort={sort} col="source">Source</SortTh>
              <SortTh sort={sort} col="tags">Tags</SortTh>
              <SortTh sort={sort} col="note">Note</SortTh>
              <SortTh sort={sort} col="created_at">Created</SortTh>
              {canWrite && <Th className="text-right">Actions</Th>}
            </THeadRow>
          </thead>
          <tbody>
            {items.map((t) => (
              <Tr key={t.id}>
                <Td className="font-mono font-medium">{t.value}</Td>
                <Td>{t.kind}</Td>
                <Td className="text-muted">{t.source}</Td>
                <Td className="text-muted">{t.tags.join(', ')}</Td>
                <Td className="text-muted">{t.note}</Td>
                <Td className="whitespace-nowrap text-muted">
                  {t.created_at ? new Date(t.created_at).toLocaleString() : ''}
                </Td>
                {canWrite && (
                  <Td className="text-right whitespace-nowrap">
                    <Button
                      variant="danger"
                      size="sm"
                      aria-label={`Delete ${t.value}`}
                      disabled={del.isPending && del.variables === t.id}
                      onClick={() => del.mutate(t.id)}
                    >
                      Delete
                    </Button>
                  </Td>
                )}
              </Tr>
            ))}
            {q.isSuccess && items.length === 0 && <EmptyRow colSpan={canWrite ? 7 : 6}>No targets</EmptyRow>}
          </tbody>
        </Table>
        <Pagination offset={offset} pageSize={PAGE} total={total} onChange={setOffset} />
      </div>
    </section>
  )
}
