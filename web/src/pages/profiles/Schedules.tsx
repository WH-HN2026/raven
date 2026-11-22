import { SortTh, useTableSort } from '../../components/SortTh'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useMemo, useState, type FormEvent } from 'react'
import { ApiError, api } from '../../api/client'
import { useCan } from '../../auth/hooks'
import {
  Alert,
  Badge,
  Button,
  EmptyRow,
  ErrorText,
  Field,
  Section,
  SectionHeading,
  Table,
  Td,
  Th,
  THeadRow,
  Tr,
  inputClass,
} from '../../components/ui'
import {
  clockIn,
  cronToFrequency,
  describeCron,
  describeWindow,
  frequencyToCron,
  nextWindow,
  schedulesKey,
  timezones,
  windowToISO,
  type Frequency,
  type Schedule,
  useProfiles,
} from './ui'

function SourceBadge({ s }: { s: Schedule }) {
  if (s.source !== 'dojo') return <Badge tone="done">UI</Badge>
  return (
    <span className="inline-flex flex-wrap items-center gap-2">
      <Badge tone="rose" title={s.dojo_engagement_id ? `Dojo engagement ${s.dojo_engagement_id}` : undefined}>
        Dojo{s.dojo_engagement_id ? ` #${s.dojo_engagement_id}` : ''}
      </Badge>
      {s.dojo_url && (
        <a href={s.dojo_url} target="_blank" rel="noopener noreferrer" className="text-xs whitespace-nowrap">
          open ↗
        </a>
      )}
    </span>
  )
}

export function Schedules() {
  const canWrite = useCan('schedules:write')
  const canAggressive = useCan('scan:aggressive')
  const profiles = useProfiles()
  const profilesById = new Map((profiles.data?.items ?? []).map((p) => [p.id, p]))
  const sort = useTableSort(['name', 'profile', 'source', 'repeats', 'window', 'next_window', 'timezone', 'enabled'], { prefix: 'schedule_' })
  const q = useQuery({ queryKey: [...schedulesKey, sort.query], queryFn: () => api.get('/schedules', { query: { limit: 1000, ...sort.query } }) })
  const items = q.data?.items ?? []
  // null = closed, 'new' = create form, a schedule = edit form.
  const [editing, setEditing] = useState<Schedule | 'new' | null>(null)

  return (
    <Section band className="flex flex-col gap-4 pb-16">
      <SectionHeading
        aside={
          canWrite &&
          editing === null && (
            <Button variant="primary" size="sm" onClick={() => setEditing('new')}>
              New schedule
            </Button>
          )
        }
      >
        Schedules · {q.data?.total ?? 0}
      </SectionHeading>
      {canWrite && editing !== null && (
        <ScheduleForm
          key={editing === 'new' ? 'new' : editing.id}
          schedule={editing === 'new' ? null : editing}
          onDone={() => setEditing(null)}
        />
      )}
      {q.error && <ErrorText>Cannot load schedules: {q.error.message}</ErrorText>}
      <Table minWidth={960} label="Schedules">
        <thead>
          <THeadRow>
            <SortTh sort={sort} col="name">Schedule</SortTh>
            <SortTh sort={sort} col="profile">Profile</SortTh>
            <SortTh sort={sort} col="source">Source</SortTh>
            <SortTh sort={sort} col="repeats">Repeats</SortTh>
            <SortTh sort={sort} col="window">Window</SortTh>
            <SortTh sort={sort} col="next_window">Next window</SortTh>
            <SortTh sort={sort} col="timezone">Timezone</SortTh>
            <SortTh sort={sort} col="enabled">Enabled</SortTh>
            {canWrite && <Th className="text-right">Actions</Th>}
          </THeadRow>
        </thead>
        <tbody>
          {items.map((s) => (
            <Tr key={s.id}>
              <Td>
                {s.name ? (
                  <div className="flex flex-col gap-0.5">
                    <span className="font-medium">{s.name}</span>
                    <span className="font-mono text-xs text-muted">#{s.id}</span>
                  </div>
                ) : (
                  <span className="text-xl leading-none font-light">#{s.id}</span>
                )}
              </Td>
              <Td>{profilesById.get(s.profile_id)?.name ?? `profile ${s.profile_id}`}</Td>
              <Td>
                <SourceBadge s={s} />
              </Td>
              <Td className="whitespace-nowrap">{s.source === 'dojo' ? 'once (planned)' : describeCron(s.cron)}</Td>
              <Td className="whitespace-nowrap">{describeWindow(s)}</Td>
              <Td className="whitespace-nowrap">{nextWindow(s)}</Td>
              <Td className="whitespace-nowrap text-muted">{s.timezone}</Td>
              <Td>
                {s.source === 'dojo' ? (
                  <Badge tone="outline">Read-only</Badge>
                ) : s.enabled ? (
                  <Badge tone="new">On</Badge>
                ) : (
                  <Badge tone="gone">Off</Badge>
                )}
              </Td>
              {canWrite && (
                <Td className="text-right whitespace-nowrap">
                  {s.source === 'ui' && (!profilesById.get(s.profile_id)?.aggressive || canAggressive) && (
                    <div className="flex justify-end gap-2">
                      <Button size="sm" aria-label={`Edit schedule ${s.id}`} onClick={() => setEditing(s)}>
                        Edit
                      </Button>
                      <DeleteSchedule s={s} onDeleted={() => setEditing(null)} />
                    </div>
                  )}
                </Td>
              )}
            </Tr>
          ))}
          {q.data && items.length === 0 && <EmptyRow colSpan={canWrite ? 9 : 8}>No schedules</EmptyRow>}
        </tbody>
      </Table>
    </Section>
  )
}

function DeleteSchedule({ s, onDeleted }: { s: Schedule; onDeleted: () => void }) {
  const qc = useQueryClient()
  const [confirming, setConfirming] = useState(false)
  const del = useMutation({
    mutationFn: () => api.delete('/schedules/{id}', { params: { id: s.id } }),
    onSuccess: () => {
      setConfirming(false)
      onDeleted()
      void qc.invalidateQueries({ queryKey: schedulesKey })
    },
  })
  if (!confirming)
    return (
      <Button variant="danger" size="sm" aria-label={`Delete schedule ${s.id}`} onClick={() => setConfirming(true)}>
        Delete
      </Button>
    )
  return (
    <div role="dialog" aria-label={`Confirm delete schedule ${s.id}`} className="flex flex-col items-end gap-2">
      <div className="flex gap-2">
        <Button size="sm" onClick={() => setConfirming(false)} disabled={del.isPending}>
          Cancel
        </Button>
        <Button variant="primary" size="sm" onClick={() => del.mutate()} disabled={del.isPending}>
          Confirm delete
        </Button>
      </div>
      {del.error && <Alert>{del.error.message}</Alert>}
    </div>
  )
}

const KINDS: { value: Frequency['kind']; label: string }[] = [
  { value: 'minutes', label: 'Every N minutes' },
  { value: 'hours', label: 'Every N hours' },
  { value: 'daily', label: 'Daily at' },
  { value: 'cron', label: 'Cron' },
]

function ScheduleForm({ schedule, onDone }: { schedule: Schedule | null; onDone: () => void }) {
  const qc = useQueryClient()
  const canAggressive = useCan('scan:aggressive')
  const profiles = useProfiles()
  const selectableProfiles = (profiles.data?.items ?? []).filter((p) => !p.aggressive || canAggressive)
  const zones = useMemo(() => timezones(), [])
  const initial = cronToFrequency(schedule?.cron ?? '0 * * * *')
  const tz0 = schedule?.timezone ?? 'Europe/Warsaw'

  const [name, setName] = useState(schedule?.name ?? '')
  const [profileId, setProfileId] = useState<number | ''>(schedule?.profile_id ?? '')
  const [kind, setKind] = useState<Frequency['kind']>(initial.kind)
  const [n, setN] = useState(initial.kind === 'minutes' || initial.kind === 'hours' ? String(initial.n) : '1')
  const [time, setTime] = useState(initial.kind === 'daily' ? initial.time : '22:00')
  const [expr, setExpr] = useState(initial.kind === 'cron' ? initial.expr : frequencyToCron(initial))
  const [winStart, setWinStart] = useState(schedule?.window_start ? clockIn(schedule.window_start, tz0) : '')
  const [winEnd, setWinEnd] = useState(schedule?.window_end ? clockIn(schedule.window_end, tz0) : '')
  const [timezone, setTimezone] = useState(tz0)
  const [enabled, setEnabled] = useState(schedule?.enabled ?? true)
  const [clientErr, setClientErr] = useState<string | null>(null)

  const save = useMutation({
    mutationFn: () => {
      const freq: Frequency =
        kind === 'minutes' || kind === 'hours'
          ? { kind, n: Number(n) }
          : kind === 'daily'
            ? { kind, time }
            : { kind, expr }
      const win = windowToISO(winStart, winEnd, timezone)
      const body = {
        name: name.trim(),
        profile_id: Number(profileId),
        cron: frequencyToCron(freq),
        window_start: win?.window_start ?? null,
        window_end: win?.window_end ?? null,
        timezone,
        enabled,
      }
      return schedule
        ? api.put('/schedules/{id}', { params: { id: schedule.id }, body })
        : api.post('/schedules', { body })
    },
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: schedulesKey })
      onDone()
    },
  })

  const onSubmit = (e: FormEvent) => {
    e.preventDefault()
    let err: string | null = null
    if (profileId === '') err = 'Pick a profile'
    else if ((kind === 'minutes' || kind === 'hours') && !(Number.isInteger(Number(n)) && Number(n) >= 1))
      err = 'N must be a positive whole number'
    else if (kind === 'daily' && !time) err = 'Pick a time'
    else if (!winStart !== !winEnd) err = 'Set both window start and end, or neither'
    else if (winStart && winStart === winEnd) err = 'Window start and end must differ'
    setClientErr(err)
    if (!err) save.mutate()
  }

  const serverErr = save.error
  const serverMsg =
    serverErr instanceof ApiError && serverErr.status === 409 ? `Not saved: ${serverErr.message}` : serverErr?.message

  return (
    <form
      aria-label={schedule ? `Edit schedule ${schedule.id}` : 'New schedule'}
      onSubmit={onSubmit}
      className="flex flex-col gap-4 border-t-2 border-black bg-white p-5"
    >
      <div className="text-lg font-medium">{schedule ? `Edit schedule #${schedule.id}` : 'New schedule'}</div>
      <div className="flex flex-wrap items-end gap-4">
        <Field label="Name" className="flex-[1_1_220px]">
          <input
            className={inputClass}
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="Nightly lab scan"
            maxLength={200}
          />
        </Field>
        <Field label="Profile" className="flex-[1_1_200px]">
          <select
            className={inputClass}
            value={profileId}
            onChange={(e) => setProfileId(e.target.value ? Number(e.target.value) : '')}
          >
            <option value="">Select…</option>
            {selectableProfiles.map((p) => (
              <option key={p.id} value={p.id}>
                {p.name}
              </option>
            ))}
          </select>
        </Field>
        <Field label="Repeats">
          <select className={inputClass} value={kind} onChange={(e) => setKind(e.target.value as Frequency['kind'])}>
            {KINDS.map((k) => (
              <option key={k.value} value={k.value}>
                {k.label}
              </option>
            ))}
          </select>
        </Field>
        {(kind === 'minutes' || kind === 'hours') && (
          <Field label="N" className="w-[90px]">
            <input className={inputClass} type="number" min={1} value={n} onChange={(e) => setN(e.target.value)} />
          </Field>
        )}
        {kind === 'daily' && (
          <Field label="Time">
            <input className={inputClass} type="time" value={time} onChange={(e) => setTime(e.target.value)} />
          </Field>
        )}
        {kind === 'cron' && (
          <Field label="Cron" className="w-[180px]">
            <input className={inputClass + ' font-mono'} value={expr} onChange={(e) => setExpr(e.target.value)} />
          </Field>
        )}
      </div>
      <div className="flex flex-wrap items-end gap-4">
        <Field label="Window start">
          <input className={inputClass} type="time" value={winStart} onChange={(e) => setWinStart(e.target.value)} />
        </Field>
        <Field label="Window end">
          <input className={inputClass} type="time" value={winEnd} onChange={(e) => setWinEnd(e.target.value)} />
        </Field>
        <Field label="Timezone" className="flex-[0_1_260px]">
          <select className={inputClass} value={timezone} onChange={(e) => setTimezone(e.target.value)}>
            {zones.map((z) => (
              <option key={z} value={z}>
                {z}
              </option>
            ))}
          </select>
        </Field>
        <label className="flex h-[44px] items-center gap-2 text-sm font-medium">
          <input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} />
          Enabled
        </label>
      </div>
      {(clientErr || serverMsg) && <Alert>{clientErr ?? serverMsg}</Alert>}
      <div className="flex gap-2">
        <Button type="submit" variant="primary" disabled={save.isPending}>
          {schedule ? 'Save schedule' : 'Create schedule'}
        </Button>
        <Button type="button" onClick={onDone} disabled={save.isPending}>
          Cancel
        </Button>
      </div>
    </form>
  )
}
