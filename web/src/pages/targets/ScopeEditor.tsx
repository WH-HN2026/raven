import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useState, type FormEvent } from 'react'
import { ApiError, api, type Schemas } from '../../api/client'
import { useCan } from '../../auth/hooks'
import { btnDanger, btnPrimary, card, input, td, th, scopeKey } from './ui'

type List = Schemas['ScopeEntryInput']['list']
type Kind = Schemas['TargetKind']

// TODO(W7): profile-specific scope entries (GET/POST /scope with profile_id) once profiles exist.

/** Global include list and global blacklist. Editing needs scope:write + scope:global (admin). */
export function ScopeEditor() {
  const canWrite = useCan('scope:write')
  const canGlobal = useCan('scope:global')
  const canEdit = canWrite && canGlobal
  // Global lists are small; one page of up to 1000 covers them.
  const q = useQuery({ queryKey: scopeKey, queryFn: () => api.get('/scope', { query: { limit: 1000 } }) })
  const items = q.data?.items ?? []

  return (
    <section className={card + ' space-y-4'}>
      <div>
        <h2 className="text-lg font-semibold text-ink">Global scope</h2>
        <p className="mt-1 text-sm text-graphite">
          Every run scans its targets intersected with the include list (if the include list is empty, the targets
          themselves are in scope), then removes everything on the blacklist.{' '}
          <b className="text-accent-dark">Exclusions always win</b>: an address on the blacklist is never scanned, even
          if it is also included. Domain entries match their resolved IPs and any host name under the domain.
        </p>
      </div>
      {q.error && <p className="text-sm text-danger">Cannot load scope: {q.error.message}</p>}
      <div className="grid gap-4 lg:grid-cols-2">
        <ScopeList
          list="include"
          title="Include list"
          hint="Only these networks/domains may be scanned."
          items={items.filter((e) => e.list === 'include')}
          canEdit={canEdit}
        />
        <ScopeList
          list="exclude"
          title="Blacklist (exclude)"
          hint="Never scanned. Wins over everything."
          items={items.filter((e) => e.list === 'exclude')}
          canEdit={canEdit}
        />
      </div>
    </section>
  )
}

function ScopeList({
  list,
  title,
  hint,
  items,
  canEdit,
}: {
  list: List
  title: string
  hint: string
  items: Schemas['ScopeEntry'][]
  canEdit: boolean
}) {
  const qc = useQueryClient()
  const [value, setValue] = useState('')
  const [kind, setKind] = useState<Kind | ''>('')
  const [note, setNote] = useState('')

  const add = useMutation({
    mutationFn: () =>
      api.post('/scope', {
        body: { value: value.trim(), list, profile_id: null, ...(kind ? { kind } : {}), ...(note.trim() ? { note: note.trim() } : {}) },
      }),
    onSuccess: () => {
      setValue('')
      setNote('')
      setKind('')
      void qc.invalidateQueries({ queryKey: scopeKey })
    },
  })
  const del = useMutation({
    mutationFn: (id: number) => api.delete('/scope/{id}', { params: { id } }),
    onSuccess: () => qc.invalidateQueries({ queryKey: scopeKey }),
  })

  const onSubmit = (e: FormEvent) => {
    e.preventDefault()
    if (value.trim()) add.mutate()
  }
  const addErr = add.error
  const addMsg =
    addErr instanceof ApiError && addErr.status === 409 ? 'This entry is already on the list.' : addErr?.message
  const exclude = list === 'exclude'

  return (
    <div className={'rounded border p-3 ' + (exclude ? 'border-accent' : 'border-line')}>
      <h3 className={'font-semibold ' + (exclude ? 'text-accent-dark' : 'text-ink')}>{title}</h3>
      <p className="mb-2 text-xs text-muted">{hint}</p>
      <table className="w-full text-sm">
        <thead>
          <tr>
            <th className={th}>Value</th>
            <th className={th}>Kind</th>
            <th className={th}>Note</th>
            {canEdit && <th className={th}>{/* actions */}</th>}
          </tr>
        </thead>
        <tbody>
          {items.map((e) => (
            <tr key={e.id}>
              <td className={td + ' font-mono'}>{e.value}</td>
              <td className={td}>{e.kind}</td>
              <td className={td + ' text-graphite'}>{e.note}</td>
              {canEdit && (
                <td className={td + ' text-right'}>
                  <button
                    className={btnDanger}
                    aria-label={`Delete ${e.value} from ${title}`}
                    disabled={del.isPending && del.variables === e.id}
                    onClick={() => del.mutate(e.id)}
                  >
                    Delete
                  </button>
                </td>
              )}
            </tr>
          ))}
          {items.length === 0 && (
            <tr>
              <td className={td + ' text-muted'} colSpan={canEdit ? 4 : 3}>
                Empty.
              </td>
            </tr>
          )}
        </tbody>
      </table>
      {del.error && <p className="mt-2 text-sm text-danger">Delete failed: {del.error.message}</p>}
      {canEdit && (
        <form onSubmit={onSubmit} className="mt-3 flex flex-wrap items-end gap-2">
          <label className="block min-w-36 flex-1">
            <span className="text-xs text-graphite">Value</span>
            <input
              className={input + ' mt-0.5 w-full font-mono'}
              placeholder="10.0.0.0/8 or example.lab"
              value={value}
              onChange={(e) => setValue(e.target.value)}
            />
          </label>
          <label className="block">
            <span className="text-xs text-graphite">Kind</span>
            <select
              className={input + ' mt-0.5 block'}
              value={kind}
              onChange={(e) => setKind(e.target.value as Kind | '')}
            >
              <option value="">Auto</option>
              <option value="ip">IP</option>
              <option value="cidr">CIDR</option>
              <option value="domain">Domain</option>
            </select>
          </label>
          <label className="block min-w-32 flex-1">
            <span className="text-xs text-graphite">Note</span>
            <input className={input + ' mt-0.5 w-full'} value={note} onChange={(e) => setNote(e.target.value)} />
          </label>
          <button type="submit" className={btnPrimary} disabled={add.isPending || !value.trim()}>
            {exclude ? 'Add to blacklist' : 'Add to include list'}
          </button>
        </form>
      )}
      {addMsg && (
        <p role="alert" className="mt-2 rounded bg-accent-light px-3 py-2 text-sm text-accent-dark">
          {addMsg}
        </p>
      )}
    </div>
  )
}
