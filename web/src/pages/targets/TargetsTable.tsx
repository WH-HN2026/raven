import { keepPreviousData, useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'
import { api } from '../../api/client'
import { useCan } from '../../auth/hooks'
import { btnDanger, btnSecondary, card, td, th, targetsKey } from './ui'

const PAGE = 50

export function TargetsTable() {
  const qc = useQueryClient()
  const canWrite = useCan('targets:write')
  const [offset, setOffset] = useState(0)
  const q = useQuery({
    queryKey: [...targetsKey, offset],
    queryFn: () => api.get('/targets', { query: { limit: PAGE, offset } }),
    placeholderData: keepPreviousData,
  })
  const del = useMutation({
    mutationFn: (id: number) => api.delete('/targets/{id}', { params: { id } }),
    onSuccess: () => qc.invalidateQueries({ queryKey: targetsKey }),
  })

  const total = q.data?.total ?? 0
  const items = q.data?.items ?? []
  // Step back a page if the last row of the last page was deleted.
  if (q.data && items.length === 0 && offset > 0 && !q.isFetching) setOffset(Math.max(0, offset - PAGE))

  return (
    <section className={card}>
      <div className="mb-3 flex items-baseline gap-3">
        <h2 className="text-lg font-semibold text-ink">Targets</h2>
        <span className="text-sm text-muted">{total} total</span>
      </div>
      {q.error && <p className="text-sm text-danger">Cannot load targets: {q.error.message}</p>}
      {del.error && (
        <p role="alert" className="mb-2 rounded bg-accent-light px-3 py-2 text-sm text-accent-dark">
          Delete failed: {del.error.message}
        </p>
      )}
      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr>
              <th className={th}>Value</th>
              <th className={th}>Kind</th>
              <th className={th}>Source</th>
              <th className={th}>Tags</th>
              <th className={th}>Note</th>
              <th className={th}>Created</th>
              {canWrite && <th className={th}>{/* actions */}</th>}
            </tr>
          </thead>
          <tbody>
            {items.map((t) => (
              <tr key={t.id}>
                <td className={td + ' font-mono'}>{t.value}</td>
                <td className={td}>{t.kind}</td>
                <td className={td}>{t.source}</td>
                <td className={td}>
                  <div className="flex flex-wrap gap-1">
                    {t.tags.map((tag) => (
                      <span key={tag} className="rounded bg-brand-light px-1.5 py-0.5 text-xs text-brand-dark">
                        {tag}
                      </span>
                    ))}
                  </div>
                </td>
                <td className={td + ' text-graphite'}>{t.note}</td>
                <td className={td + ' whitespace-nowrap text-muted'}>
                  {t.created_at ? new Date(t.created_at).toLocaleString() : ''}
                </td>
                {canWrite && (
                  <td className={td + ' text-right'}>
                    <button
                      className={btnDanger}
                      aria-label={`Delete ${t.value}`}
                      disabled={del.isPending && del.variables === t.id}
                      onClick={() => del.mutate(t.id)}
                    >
                      Delete
                    </button>
                  </td>
                )}
              </tr>
            ))}
            {q.isSuccess && items.length === 0 && (
              <tr>
                <td className={td + ' text-muted'} colSpan={canWrite ? 7 : 6}>
                  No targets yet.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
      {total > PAGE && (
        <div className="mt-3 flex items-center gap-2 text-sm text-graphite">
          <button className={btnSecondary} disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - PAGE))}>
            Previous
          </button>
          <span>
            {offset + 1}–{Math.min(offset + PAGE, total)} of {total}
          </span>
          <button className={btnSecondary} disabled={offset + PAGE >= total} onClick={() => setOffset(offset + PAGE)}>
            Next
          </button>
        </div>
      )}
    </section>
  )
}
