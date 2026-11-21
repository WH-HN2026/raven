// Host edit (W10): user-owned host fields and per-service overrides.
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { useState, type FormEvent, type ReactNode } from 'react'
import { api, type Schemas } from '../../api/client'
import { useCan } from '../../auth/hooks'
import {
  Alert,
  Badge,
  Button,
  Chip,
  Field,
  SectionHeading,
  Td,
  inputClass,
  textareaClass,
  type BadgeTone,
} from '../../components/ui'
import { hostsKey } from './ui'

type HostDetail = Schemas['HostDetail']
type Service = Schemas['Service']
type Criticality = Schemas['HostPatch']['criticality']
export type DojoSync = Schemas['HostEditResult']['dojo_sync']
export type ServiceField = 'name' | 'product' | 'version'
export const serviceFields: ServiceField[] = ['name', 'product', 'version']

const criticalities: NonNullable<Criticality>[] = ['', 'low', 'medium', 'high', 'critical']
const tagRe = /^[a-z0-9][a-z0-9._/-]*$/

export const detailKey = (ip: string) => [...hostsKey, 'detail', ip] as const

/** Normalizes a typed tag (lowercase, trimmed); null when invalid. */
export function normalizeTag(s: string): string | null {
  const t = s.trim().toLowerCase()
  return t.length > 0 && t.length <= 64 && tagRe.test(t) ? t : null
}

const syncTone: Record<DojoSync, BadgeTone> = { synced: 'new', pending: 'rose', failed: 'red' }

export function DojoSyncBadge({ state }: { state: DojoSync }) {
  return <Badge tone={syncTone[state]}>Dojo {state}</Badge>
}

/** The "Host details" panel: read view, plus an edit form for hosts:edit. */
export function HostDetailsPanel({ h }: { h: HostDetail }) {
  const canEdit = useCan('hosts:edit')
  const [editing, setEditing] = useState(false)
  const [sync, setSync] = useState<DojoSync | null>(null)
  return (
    <section className="flex flex-col gap-4 bg-band p-6">
      <SectionHeading
        size="sm"
        aside={
          canEdit &&
          !editing && (
            <Button size="sm" onClick={() => setEditing(true)}>
              Edit
            </Button>
          )
        }
      >
        Host details
      </SectionHeading>
      {sync && (
        <div>
          <DojoSyncBadge state={sync} />
        </div>
      )}
      {editing ? (
        <HostForm
          h={h}
          onDone={(s) => {
            setEditing(false)
            if (s) setSync(s)
          }}
        />
      ) : (
        <HostView h={h} />
      )}
    </section>
  )
}

function HostView({ h }: { h: HostDetail }) {
  return (
    <>
      <dl className="m-0 grid grid-cols-[120px_1fr] gap-x-3 gap-y-2 text-sm">
        <DItem label="Owner">{h.owner || '—'}</DItem>
        <DItem label="Criticality">{h.criticality ? <span className="capitalize">{h.criticality}</span> : '—'}</DItem>
        <DItem label="Tags">
          {h.user_tags.length ? (
            <span className="flex flex-wrap gap-1.5">
              {h.user_tags.map((t) => (
                <Chip key={t} variant="filled">
                  {t}
                </Chip>
              ))}
            </span>
          ) : (
            '—'
          )}
        </DItem>
        <DItem label="Open services">{h.open_service_count}</DItem>
        <DItem label="Missed runs">{h.miss_count}</DItem>
        <DItem label="Dojo asset">{h.dojo_asset_id ?? '—'}</DItem>
      </dl>
      {h.notes && (
        <p aria-label="Notes" className="m-0 border-t border-line pt-3 text-sm whitespace-pre-wrap">
          {h.notes}
        </p>
      )}
    </>
  )
}

function DItem({ label, children }: { label: string; children: ReactNode }) {
  return (
    <>
      <dt className="text-muted">{label}</dt>
      <dd className="m-0 min-w-0 break-words">{children}</dd>
    </>
  )
}

function HostForm({ h, onDone }: { h: HostDetail; onDone: (sync: DojoSync | null) => void }) {
  const qc = useQueryClient()
  const [owner, setOwner] = useState(h.owner)
  const [criticality, setCriticality] = useState<Criticality>(h.criticality)
  const [notes, setNotes] = useState(h.notes)
  const [tags, setTags] = useState<string[]>(h.user_tags)
  const save = useMutation({
    mutationFn: (body: Schemas['HostPatch']) => api.patch('/hosts/{ip}', { params: { ip: h.ip }, body }),
    onSuccess: (res) => {
      const { dojo_sync, ...detail } = res
      qc.setQueryData(detailKey(h.ip), detail)
      void qc.invalidateQueries({ queryKey: hostsKey, predicate: (q) => q.queryKey[1] !== 'detail' })
      onDone(dojo_sync)
    },
  })
  const submit = (e: FormEvent) => {
    e.preventDefault()
    save.mutate({ owner: owner.trim(), criticality, notes, user_tags: tags })
  }
  return (
    <form aria-label="Edit host" onSubmit={submit} className="flex flex-col gap-4">
      <Field label="Owner">
        <input className={inputClass} value={owner} maxLength={200} onChange={(e) => setOwner(e.target.value)} />
      </Field>
      <Field label="Criticality">
        <select
          className={inputClass}
          value={criticality}
          onChange={(e) => setCriticality(e.target.value as Criticality)}
        >
          {criticalities.map((c) => (
            <option key={c} value={c}>
              {c ? c.charAt(0).toUpperCase() + c.slice(1) : '—'}
            </option>
          ))}
        </select>
      </Field>
      <TagEditor tags={tags} onChange={setTags} />
      <Field label="Notes">
        <textarea className={textareaClass} rows={4} value={notes} onChange={(e) => setNotes(e.target.value)} />
      </Field>
      {save.error && <Alert>Cannot save: {save.error.message}</Alert>}
      <div className="flex justify-end">
        <Button size="lg" onClick={() => onDone(null)} disabled={save.isPending}>
          Cancel
        </Button>
        <Button type="submit" variant="primary" size="lg" disabled={save.isPending}>
          Save
        </Button>
      </div>
    </form>
  )
}

/** Chip editor: Enter or comma adds the typed tag, × removes one, Backspace on empty removes the last. */
export function TagEditor({ tags, onChange }: { tags: string[]; onChange: (t: string[]) => void }) {
  const [draft, setDraft] = useState('')
  const [bad, setBad] = useState(false)
  const add = () => {
    if (!draft.trim()) return true
    const t = normalizeTag(draft)
    if (!t) {
      setBad(true)
      return false
    }
    if (!tags.includes(t)) onChange([...tags, t].sort())
    setDraft('')
    setBad(false)
    return true
  }
  return (
    <div className="flex flex-col gap-1.5">
      <span className="text-[13px] font-medium">Tags</span>
      <div className="flex flex-wrap items-center gap-1.5 border border-line-strong bg-white p-[7px]">
        {tags.map((t) => (
          <span key={t} className="inline-flex items-center gap-1 bg-rose py-0.5 pr-1 pl-2 text-[13px]">
            {t}
            <button
              type="button"
              aria-label={`Remove tag ${t}`}
              className="border-0 bg-transparent px-1 text-ink hover:text-red"
              onClick={() => onChange(tags.filter((x) => x !== t))}
            >
              ×
            </button>
          </span>
        ))}
        <input
          aria-label="Add tag"
          aria-invalid={bad}
          placeholder="Add tag…"
          className="h-7 min-w-20 flex-1 border-0 text-sm outline-none aria-[invalid=true]:text-red"
          value={draft}
          onChange={(e) => {
            setDraft(e.target.value)
            setBad(false)
          }}
          onKeyDown={(e) => {
            if (e.key === 'Enter' || e.key === ',') {
              e.preventDefault()
              add()
            } else if (e.key === 'Backspace' && draft === '' && tags.length > 0) {
              onChange(tags.slice(0, -1))
            }
          }}
          onBlur={add}
        />
      </div>
      {bad && <span className="text-[13px] text-red">Invalid tag: a-z 0-9 . _ / -</span>}
    </div>
  )
}

/**
 * The overrides patch for a service edit: only keys whose override changes;
 * a value equal to the scan value (or empty) clears the override.
 */
export function overridesPatch(s: Service, draft: Record<ServiceField, string>) {
  const patch: Partial<Record<ServiceField, string | null>> = {}
  for (const f of serviceFields) {
    const v = draft[f].trim()
    const want = v === '' || v === s.scan[f] ? null : v
    const cur = s.overridden.includes(f) ? s[f] : null
    if (want !== cur) patch[f] = want
  }
  return patch
}

/** Inline edit cells for one service row (name, product, version), with Save/Cancel. */
export function ServiceEditCells({ s, ip, onDone }: { s: Service; ip: string; onDone: () => void }) {
  const qc = useQueryClient()
  const [draft, setDraft] = useState<Record<ServiceField, string>>({ name: s.name, product: s.product, version: s.version })
  const save = useMutation({
    mutationFn: (overrides: ReturnType<typeof overridesPatch>) =>
      api.patch('/services/{id}', { params: { id: s.id }, body: { overrides } }),
    onSuccess: (svc) => {
      qc.setQueryData<HostDetail>(detailKey(ip), (d) =>
        d ? { ...d, services: d.services.map((x) => (x.id === svc.id ? svc : x)) } : d,
      )
      onDone()
    },
  })
  const submit = () => {
    const patch = overridesPatch(s, draft)
    if (Object.keys(patch).length === 0) onDone()
    else save.mutate(patch)
  }
  return (
    <>
      {serviceFields.map((f) => (
        <Td key={f} className={f === 'name' ? '' : 'font-mono text-[13px]'}>
          <div className="flex min-w-32 flex-col gap-1">
            <input
              aria-label={`${s.port}/${s.proto} ${f}`}
              className={inputClass + ' h-9' + (f === 'name' ? '' : ' font-mono')}
              value={draft[f]}
              placeholder={s.scan[f]}
              onChange={(e) => setDraft({ ...draft, [f]: e.target.value })}
              onKeyDown={(e) => {
                if (e.key === 'Enter') submit()
                if (e.key === 'Escape') onDone()
              }}
            />
            {draft[f] !== s.scan[f] && (
              <button
                type="button"
                className="self-start border-0 bg-transparent p-0 font-sans text-xs text-ink underline decoration-red underline-offset-[3px] hover:text-red"
                title={`Scan value: ${s.scan[f] || '—'}`}
                onClick={() => setDraft({ ...draft, [f]: s.scan[f] })}
              >
                Reset to scan value
              </button>
            )}
          </div>
        </Td>
      ))}
      <Td colSpan={4}>
        <div className="flex flex-wrap items-center gap-2">
          <Button size="sm" variant="primary" onClick={submit} disabled={save.isPending}>
            Save
          </Button>
          <Button size="sm" onClick={onDone} disabled={save.isPending}>
            Cancel
          </Button>
          {save.error && <span className="text-[13px] text-red">{save.error.message}</span>}
        </div>
      </Td>
    </>
  )
}
