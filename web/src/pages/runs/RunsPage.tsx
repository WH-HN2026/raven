import { keepPreviousData, useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'
import { Link, useNavigate } from 'react-router'
import { api, ApiError, type Schemas } from '../../api/client'
import { useCan } from '../../auth/hooks'
import {
  btnPrimary,
  btnSecondary,
  card,
  formatDuration,
  formatTime,
  input,
  isActive,
  pollWhile,
  profilesKey,
  ProgressBar,
  runDurationMs,
  runsKey,
  StatusBadge,
  td,
  th,
} from './ui'

const PAGE = 50

function useProfiles() {
  return useQuery({
    queryKey: profilesKey,
    queryFn: () => api.get('/profiles', { query: { limit: 1000 } }),
  })
}

export function StartRunForm() {
  const qc = useQueryClient()
  const navigate = useNavigate()
  const profiles = useProfiles()
  const enabled = (profiles.data?.items ?? []).filter((p) => p.enabled)
  const [picked, setPicked] = useState<number | null>(null)
  const profileId = picked ?? enabled[0]?.id ?? null

  const start = useMutation({
    mutationFn: (profile_id: number) => api.post('/runs', { body: { profile_id } }),
    onSuccess: (run) => {
      void qc.invalidateQueries({ queryKey: runsKey })
      void navigate(`/runs/${run.id}`)
    },
  })

  const err = start.error
  const conflict = err instanceof ApiError && err.status === 409
  // The run that blocks a new one, if it's in the cached list.
  const runs = qc.getQueryData<Schemas['RunList']>([...runsKey, 0])
  const blocking = conflict
    ? runs?.items.find((r) => r.profile_id === profileId && isActive(r.status))
    : undefined

  return (
    <section className={card}>
      <h2 className="mb-3 text-lg font-semibold text-ink">Start a run</h2>
      <form
        className="flex flex-wrap items-end gap-3"
        onSubmit={(e) => {
          e.preventDefault()
          if (profileId !== null) start.mutate(profileId)
        }}
      >
        <label className="flex flex-col gap-1 text-sm text-graphite">
          Profile
          <select
            className={input}
            value={profileId ?? ''}
            onChange={(e) => {
              setPicked(Number(e.target.value))
              start.reset()
            }}
            disabled={enabled.length === 0}
          >
            {enabled.map((p) => (
              <option key={p.id} value={p.id}>
                {p.name} (max rate {p.nmap_max_rate}/s)
              </option>
            ))}
          </select>
        </label>
        <button type="submit" className={btnPrimary} disabled={profileId === null || start.isPending}>
          {start.isPending ? 'Starting…' : 'Start run'}
        </button>
      </form>
      {profiles.error && <p className="mt-2 text-sm text-danger">Cannot load profiles: {profiles.error.message}</p>}
      {profiles.data && enabled.length === 0 && (
        <p className="mt-2 text-sm text-muted">No enabled profiles.</p>
      )}
      {err && (
        <p role="alert" className="mt-3 rounded bg-accent-light px-3 py-2 text-sm text-accent-dark">
          {conflict ? (
            <>
              This profile already has an active run
              {blocking && (
                <>
                  {' '}
                  (
                  <Link className="font-medium underline" to={`/runs/${blocking.id}`}>
                    run #{blocking.id}
                  </Link>
                  )
                </>
              )}
              .
            </>
          ) : (
            <>Cannot start the run: {err.message}</>
          )}
        </p>
      )}
    </section>
  )
}

export function RunsTable() {
  const [offset, setOffset] = useState(0)
  const profiles = useProfiles()
  const names = new Map((profiles.data?.items ?? []).map((p) => [p.id, p.name]))
  const q = useQuery({
    queryKey: [...runsKey, offset],
    queryFn: () => api.get('/runs', { query: { limit: PAGE, offset } }),
    placeholderData: keepPreviousData,
    refetchInterval: (query) => pollWhile(!!query.state.data?.items.some((r) => isActive(r.status))),
  })
  const items = q.data?.items ?? []
  const total = q.data?.total ?? 0

  return (
    <section className={card}>
      <div className="mb-3 flex items-baseline gap-3">
        <h2 className="text-lg font-semibold text-ink">Runs</h2>
        <span className="text-sm text-muted">{total} total</span>
      </div>
      {q.error && <p className="text-sm text-danger">Cannot load runs: {q.error.message}</p>}
      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr>
              <th className={th}>Run</th>
              <th className={th}>Profile</th>
              <th className={th}>Status</th>
              <th className={th}>Progress</th>
              <th className={th}>Hosts up / total</th>
              <th className={th}>Started</th>
              <th className={th}>Duration</th>
            </tr>
          </thead>
          <tbody>
            {items.map((r) => (
              <tr key={r.id} className="hover:bg-canvas">
                <td className={td}>
                  <Link className="font-medium text-brand hover:underline" to={`/runs/${r.id}`}>
                    #{r.id}
                  </Link>
                </td>
                <td className={td}>{names.get(r.profile_id) ?? `profile ${r.profile_id}`}</td>
                <td className={td}>
                  <StatusBadge status={r.status} />
                </td>
                <td className={td}>
                  <ProgressBar run={r} />
                </td>
                <td className={td + ' whitespace-nowrap'}>
                  {r.hosts_up} / {r.hosts_total}
                </td>
                <td className={td + ' whitespace-nowrap text-muted'}>{formatTime(r.started_at ?? r.created_at)}</td>
                <td className={td + ' whitespace-nowrap'}>{formatDuration(runDurationMs(r))}</td>
              </tr>
            ))}
            {q.data && items.length === 0 && (
              <tr>
                <td className={td + ' text-muted'} colSpan={7}>
                  No runs yet.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
      {total > PAGE && (
        <div className="mt-3 flex items-center gap-2 text-sm text-muted">
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

export function RunsPage() {
  const canControl = useCan('runs:control')
  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-semibold text-ink">Runs</h1>
      {canControl && <StartRunForm />}
      <RunsTable />
    </div>
  )
}
