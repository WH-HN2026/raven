import { keepPreviousData, useQuery, useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'
import { Link, useSearchParams } from 'react-router'
import { ApiError, api } from '../../api/client'
import { PageHeader } from '../../components/PageHeader'
import {
  Alert,
  Badge,
  Chip,
  EmptyRow,
  ErrorText,
  FilterBar,
  Field,
  KeyNumber,
  KeyNumbers,
  Section,
  SectionHeading,
  Table,
  Td,
  Th,
  THeadRow,
  ToggleGroup,
  Tr,
  inputClass,
} from '../../components/ui'
import {
  type ChangeFilter,
  type ChangeKind,
  type DiffRow,
  type DiffRun,
  type Fingerprint,
  type RunDiff,
  changesKey,
  counts,
  diffRows,
  fieldText,
  otherRunLabel,
  runLabel,
  runParam,
  shownFields,
} from './ui'

const RUNS_LIMIT = 1000

function runsQuery(profileId: number) {
  return {
    queryKey: [...changesKey, 'runs', profileId],
    queryFn: () => api.get('/runs', { query: { profile_id: profileId, limit: RUNS_LIMIT } }),
  }
}

export function ChangesPage() {
  const [params, setParams] = useSearchParams()
  const from = runParam(params, 'from')
  const to = runParam(params, 'to')
  const qc = useQueryClient()

  const diff = useQuery({
    queryKey: [...changesKey, 'diff', from, to],
    queryFn: () => api.get('/changes', { query: { from: from ?? undefined, to: to ?? undefined } }),
    placeholderData: keepPreviousData,
    retry: (n, err) => !(err instanceof ApiError && err.status < 500) && n < 2,
  })
  // Ignore a body that is not a diff (e.g. a stubbed fetch).
  const d = diff.error || !diff.data?.to ? undefined : diff.data

  const profiles = useQuery({
    queryKey: [...changesKey, 'profiles'],
    queryFn: () => api.get('/profiles', { query: { limit: 1000 } }),
  })
  const [pickedProfile, setPickedProfile] = useState<number | null>(null)
  const profileId = pickedProfile ?? d?.to.profile_id ?? profiles.data?.items[0]?.id ?? null
  const runs = useQuery({ ...runsQuery(profileId ?? 0), enabled: profileId !== null })
  const done = (runs.data?.items ?? []).filter((r) => r.status === 'done')

  const curFrom = from ?? d?.from.id ?? null
  const curTo = to ?? d?.to.id ?? null

  function setRuns(f: number | null, t: number | null) {
    const next = new URLSearchParams(params)
    for (const [k, v] of [
      ['from', f],
      ['to', t],
    ] as const) {
      if (v === null) next.delete(k)
      else next.set(k, String(v))
    }
    setParams(next)
  }

  async function pickProfile(id: number) {
    setPickedProfile(id)
    const list = await qc.fetchQuery(runsQuery(id))
    const latest = list.items.find((r) => r.status === 'done')
    // Latest done run of the profile; the API picks the one before it.
    setRuns(null, latest ? latest.id : null)
  }

  // Options: the profile's done runs, plus the selected ones if they're not among them.
  function options(selected: number | null, known: DiffRun | undefined) {
    const opts = done.map((r) => ({ id: r.id, label: runLabel(r) }))
    if (selected !== null && !opts.some((o) => o.id === selected)) {
      opts.unshift({ id: selected, label: known && known.id === selected ? runLabel(known) : `Run #${selected}` })
    }
    return opts
  }

  const err = diff.error
  return (
    <>
      <PageHeader title="Changes" crumbs={[{ label: 'Changes' }]} />
      <FilterBar onSubmit={(e) => e.preventDefault()}>
        <Field label="Profile" className="flex-[0_1_280px]">
          <select
            className={inputClass}
            value={profileId ?? ''}
            onChange={(e) => void pickProfile(Number(e.target.value))}
            disabled={!profiles.data}
          >
            {(profiles.data?.items ?? []).map((p) => (
              <option key={p.id} value={p.id}>
                {p.name}
              </option>
            ))}
          </select>
        </Field>
        <Field label="From (baseline)" className="flex-[0_1_320px]">
          <select
            className={inputClass}
            value={curFrom ?? ''}
            onChange={(e) => setRuns(Number(e.target.value), curTo)}
          >
            {curFrom === null && <option value="">—</option>}
            {options(curFrom, d?.from).map((o) => (
              <option key={o.id} value={o.id}>
                {o.label}
              </option>
            ))}
          </select>
        </Field>
        <span aria-hidden className="pb-2.5 text-xl">
          →
        </span>
        <Field label="To" className="flex-[0_1_320px]">
          <select className={inputClass} value={curTo ?? ''} onChange={(e) => setRuns(curFrom, Number(e.target.value))}>
            {curTo === null && <option value="">—</option>}
            {options(curTo, d?.to).map((o) => (
              <option key={o.id} value={o.id}>
                {o.label}
              </option>
            ))}
          </select>
        </Field>
      </FilterBar>

      {err ? (
        <Section>
          {err instanceof ApiError && err.status === 400 ? (
            <Alert>Cannot compare: {err.message}</Alert>
          ) : err instanceof ApiError && err.status === 404 ? (
            <Alert>No runs to compare: {err.message}</Alert>
          ) : (
            <ErrorText>Cannot load changes: {err.message}</ErrorText>
          )}
        </Section>
      ) : !d ? (
        <Section>
          <p className="m-0 text-muted">Loading…</p>
        </Section>
      ) : (
        <Diff d={d} />
      )}
    </>
  )
}

function Diff({ d }: { d: RunDiff }) {
  const [filter, setFilter] = useState<ChangeFilter>('all')
  const c = counts(d)
  const s = d.summary
  const rows = diffRows(d).filter((r) => filter === 'all' || r.kind === filter)
  return (
    <>
      <Section label="Summary">
        <KeyNumbers>
          <KeyNumber label="New" value={c.new} edge="green" note={`${s.hosts_new} hosts, ${s.services_new} services`} />
          <KeyNumber label="Changed" value={c.changed} edge="rose" note={`${s.services_changed} services`} />
          <KeyNumber label="Gone" value={c.gone} edge="black" note={`${s.hosts_gone} hosts, ${s.services_gone} services`} />
        </KeyNumbers>
      </Section>
      <Section band className="flex flex-col gap-5 pb-16">
        <SectionHeading
          aside={
            <ToggleGroup<ChangeFilter>
              label="Show"
              value={filter}
              onChange={setFilter}
              options={[
                { value: 'all', label: `All ${c.all}` },
                { value: 'new', label: `New ${c.new}` },
                { value: 'changed', label: `Changed ${c.changed}` },
                { value: 'gone', label: `Gone ${c.gone}` },
              ]}
            />
          }
        >
          Run #{d.from.id} → run #{d.to.id}
        </SectionHeading>
        {d.truncated && <Alert>Lists truncated: showing part of the changes; counts are complete.</Alert>}
        <div className="bg-white px-6 py-2">
          <Table minWidth={900} label="Changes">
            <thead>
              <THeadRow>
                <Th>Change</Th>
                <Th>Host</Th>
                <Th>Service</Th>
                <Th>Field</Th>
                <Th>Run #{d.from.id}</Th>
                <Th>Run #{d.to.id}</Th>
              </THeadRow>
            </thead>
            <tbody>
              {rows.map((r) => (
                <DiffTableRow key={r.key} r={r} />
              ))}
              {rows.length === 0 && <EmptyRow colSpan={6}>No changes</EmptyRow>}
            </tbody>
          </Table>
        </div>
      </Section>
    </>
  )
}

const kindBadge: Record<ChangeKind, { tone: 'new' | 'changed' | 'gone'; label: string }> = {
  new: { tone: 'new', label: '+ New' },
  changed: { tone: 'changed', label: '~ Changed' },
  gone: { tone: 'gone', label: '− Gone' },
}

function DiffTableRow({ r }: { r: DiffRow }) {
  const b = kindBadge[r.kind]
  const hostCell = (
    <Td>
      <Link className="font-mono text-[13px]" to={`/hosts/${r.ip}`}>
        {r.ip}
      </Link>
      <div>
        <Link className="text-[13px] text-muted" to={`/changes/hosts/${r.ip}`}>
          Timeline
        </Link>
      </div>
    </Td>
  )
  if (r.type === 'host') {
    const h = r.host
    const up = `up${h.ports.length > 0 ? ` · ${h.ports.join(', ')}` : ''}`
    const other = otherRunLabel(h.other_run)
    return (
      <Tr>
        <Td>
          <Badge tone={b.tone}>{b.label}</Badge>
        </Td>
        {hostCell}
        <Td className="text-muted">all</Td>
        <Td>host</Td>
        <Td>{r.kind === 'new' ? other : up}</Td>
        <Td>{r.kind === 'new' ? up : other}</Td>
      </Tr>
    )
  }
  const s = r.service
  const changed = r.kind === 'changed' ? s.fields : []
  return (
    <Tr>
      <Td>
        <Badge tone={b.tone}>{b.label}</Badge>
      </Td>
      {hostCell}
      <Td className="font-mono text-[13px] whitespace-nowrap">
        {s.port}/{s.proto}
      </Td>
      <Td>{r.kind === 'changed' ? s.fields.join(', ') : 'service'}</Td>
      <Td>
        <FingerprintCell fp={s.before} changed={changed} />
      </Td>
      <Td>
        <FingerprintCell fp={s.after} changed={changed} />
      </Td>
    </Tr>
  )
}

/** A service fingerprint, one field per line; changed fields are highlighted. */
export function FingerprintCell({ fp, changed }: { fp: Fingerprint | null | undefined; changed: string[] }) {
  if (!fp) return <span className="text-muted">—</span>
  const fields = shownFields(fp, changed)
  if (fields.length === 0) return <span className="text-muted">—</span>
  return (
    <dl className="m-0 flex flex-col gap-0.5">
      {fields.map((f) => {
        const hit = changed.includes(f)
        const text = fieldText(fp, f)
        return (
          <div key={f} className="flex gap-2" data-changed={hit || undefined}>
            <dt className="w-[86px] flex-none text-[13px] text-muted">{f}</dt>
            <dd className={'m-0 min-w-0 break-words ' + (hit ? 'bg-rose px-1 font-medium' : '')}>
              {f === 'technologies' && fp.technologies.length > 0 ? (
                <span className="flex flex-wrap gap-1">
                  {fp.technologies.map((t) => (
                    <Chip key={t}>{t}</Chip>
                  ))}
                </span>
              ) : (
                text || '—'
              )}
            </dd>
          </div>
        )
      })}
    </dl>
  )
}
