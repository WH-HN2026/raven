import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useState, type FormEvent } from 'react'
import { api, type Schemas } from '../../api/client'
import { useCan } from '../../auth/hooks'
import { AdminOnly, Alert, Button, ErrorText, Field, SectionHeading, inputClass } from '../../components/ui'
import { scopeKey } from './ui'

type List = Schemas['ScopeEntryInput']['list']
type Kind = Schemas['TargetKind']

/** Global include list and global blacklist. Editing needs scope:write + scope:global (admin). */
export function ScopeEditor() {
  const canWrite = useCan('scope:write')
  const canGlobal = useCan('scope:global')
  const canEdit = canWrite && canGlobal
  // Global lists are small; one page of up to 1000 covers them.
  const q = useQuery({ queryKey: scopeKey, queryFn: () => api.get('/scope', { query: { limit: 1000 } }) })
  const items = q.data?.items ?? []

  return (
    <>
      {q.error && <ErrorText>Cannot load scope: {q.error.message}</ErrorText>}
      <ScopeList
        list="include"
        title="Include"
        items={items.filter((e) => e.list === 'include')}
        canEdit={canEdit}
      />
      <div className="flex flex-col gap-3">
        <ScopeList
          list="exclude"
          title="Exclude (never scan)"
          items={items.filter((e) => e.list === 'exclude')}
          canEdit={canEdit}
        />
        {!canEdit && <AdminOnly />}
      </div>
    </>
  )
}

/** One include or exclude list; `profileId` adds entries to that profile instead of the global lists. */
export function ScopeList({
  list,
  title,
  items,
  canEdit,
  profileId = null,
}: {
  list: List
  title: string
  items: Schemas['ScopeEntry'][]
  canEdit: boolean
  profileId?: number | null
}) {
  const qc = useQueryClient()
  const [value, setValue] = useState('')
  const [kind, setKind] = useState<Kind | ''>('')
  const [note, setNote] = useState('')

  const add = useMutation({
    mutationFn: () =>
      api.post('/scope', {
        body: { value: value.trim(), list, profile_id: profileId, ...(kind ? { kind } : {}), ...(note.trim() ? { note: note.trim() } : {}) },
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
  const exclude = list === 'exclude'

  return (
    <div className="flex flex-col gap-3">
      <SectionHeading square={exclude ? 'red' : 'green'}>{title}</SectionHeading>
      <ul aria-label={title} className={'m-0 list-none border-t-2 p-0 ' + (exclude ? 'border-red' : 'border-black')}>
        {items.map((e) => (
          <li key={e.id} className="flex flex-wrap items-baseline gap-4 border-b border-line py-3">
            <span className="flex-[0_0_170px] font-mono font-medium break-all">{e.value}</span>
            <span className="flex-[1_1_160px] font-light">{e.note}</span>
            <span className="text-[13px] text-muted">{e.kind}</span>
            {canEdit && (
              <Button
                variant="danger"
                size="sm"
                aria-label={`Delete ${e.value} from ${title}`}
                disabled={del.isPending && del.variables === e.id}
                onClick={() => del.mutate(e.id)}
              >
                Delete
              </Button>
            )}
          </li>
        ))}
        {items.length === 0 && <li className="border-b border-line py-3 text-muted">Empty</li>}
      </ul>
      {del.error && <Alert>Delete failed: {del.error.message}</Alert>}
      {canEdit && (
        <form onSubmit={onSubmit} className="flex flex-wrap items-end gap-3">
          <Field label="Value" className="flex-[1_1_160px]">
            <input
              className={inputClass + ' font-mono'}
              placeholder="10.0.0.0/8"
              value={value}
              onChange={(e) => setValue(e.target.value)}
            />
          </Field>
          <Field label="Kind">
            <select className={inputClass} value={kind} onChange={(e) => setKind(e.target.value as Kind | '')}>
              <option value="">Auto</option>
              <option value="ip">IP</option>
              <option value="cidr">CIDR</option>
              <option value="domain">Domain</option>
            </select>
          </Field>
          <Field label="Note" className="flex-[1_1_140px]">
            <input className={inputClass} value={note} onChange={(e) => setNote(e.target.value)} />
          </Field>
          <Button type="submit" variant={exclude ? 'danger' : 'primary'} disabled={add.isPending || !value.trim()}>
            {exclude ? 'Add exclusion' : 'Add to include'}
          </Button>
        </form>
      )}
      {add.error && <Alert>{add.error.message}</Alert>}
    </div>
  )
}
