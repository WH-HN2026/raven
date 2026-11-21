import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'
import { Link, useParams } from 'react-router'
import { api, ApiError } from '../../api/client'
import { useCan } from '../../auth/hooks'
import {
  btnDanger,
  btnSecondary,
  card,
  formatDuration,
  formatTime,
  isActive,
  pollWhile,
  profilesKey,
  ProgressBar,
  runDurationMs,
  runsKey,
  StatusBadge,
  td,
  th,
  type Run,
} from './ui'

function StopButton({ run }: { run: Run }) {
  const qc = useQueryClient()
  const [confirming, setConfirming] = useState(false)
  const stop = useMutation({
    mutationFn: () => api.post('/runs/{id}/stop', { params: { id: run.id } }),
    onSuccess: (r) => {
      qc.setQueryData([...runsKey, 'detail', run.id], r)
      void qc.invalidateQueries({ queryKey: runsKey })
      setConfirming(false)
    },
    onError: () => {
      // 409 = it finished meanwhile: refresh to show the real state.
      void qc.invalidateQueries({ queryKey: runsKey })
      setConfirming(false)
    },
  })
  const err = stop.error
  return (
    <div className="flex flex-col items-end gap-2">
      {!confirming ? (
        <button className={btnDanger} onClick={() => setConfirming(true)}>
          Stop run
        </button>
      ) : (
        <div role="dialog" aria-label="Confirm stop" className="rounded border border-accent bg-accent-light p-3 text-sm">
          <p className="mb-2 text-accent-dark">
            Stop run #{run.id}? Unfinished batches are cancelled and the run ends as <b>stopped</b>.
          </p>
          <div className="flex justify-end gap-2">
            <button className={btnSecondary} onClick={() => setConfirming(false)} disabled={stop.isPending}>
              Cancel
            </button>
            <button className={btnDanger} onClick={() => stop.mutate()} disabled={stop.isPending}>
              {stop.isPending ? 'Stopping…' : 'Confirm stop'}
            </button>
          </div>
        </div>
      )}
      {err && (
        <p role="alert" className="rounded bg-accent-light px-3 py-2 text-sm text-accent-dark">
          {err instanceof ApiError && err.status === 409 ? 'The run is no longer active.' : `Stop failed: ${err.message}`}
        </p>
      )}
    </div>
  )
}

/** Scalar stats from the run (scan list stats, totals, reason). */
function Stats({ stats }: { stats: Run['stats'] }) {
  const entries = Object.entries(stats).filter(
    ([, v]) => typeof v === 'number' || typeof v === 'string' || typeof v === 'boolean',
  )
  const warnings = Array.isArray(stats.warnings) ? (stats.warnings as unknown[]).map(String) : []
  if (entries.length === 0 && warnings.length === 0) return null
  return (
    <div>
      <dl className="grid grid-cols-2 gap-x-6 gap-y-1 text-sm sm:grid-cols-3 lg:grid-cols-4">
        {entries.map(([k, v]) => (
          <div key={k} className="flex justify-between gap-2 border-b border-line py-1">
            <dt className="text-muted">{k.replaceAll('_', ' ')}</dt>
            <dd className="font-medium text-ink">
              {k.startsWith('duration_ms') && typeof v === 'number' ? formatDuration(v) : String(v)}
            </dd>
          </div>
        ))}
      </dl>
      {warnings.length > 0 && (
        <ul className="mt-2 list-inside list-disc text-sm text-warn">
          {warnings.map((w, i) => (
            <li key={i}>{w}</li>
          ))}
        </ul>
      )}
    </div>
  )
}

export function RunDetailPage() {
  const id = Number(useParams().id)
  const canControl = useCan('runs:control')
  const profiles = useQuery({
    queryKey: profilesKey,
    queryFn: () => api.get('/profiles', { query: { limit: 1000 } }),
  })
  const runQ = useQuery({
    queryKey: [...runsKey, 'detail', id],
    queryFn: () => api.get('/runs/{id}', { params: { id } }),
    enabled: Number.isFinite(id),
    refetchInterval: (query) => pollWhile(isActive(query.state.data?.status)),
  })
  const run = runQ.data
  const active = isActive(run?.status)
  const batchesQ = useQuery({
    // The status in the key refetches the batches once more when the run settles.
    queryKey: [...runsKey, 'batches', id, run?.status],
    queryFn: () => api.get('/runs/{id}/batches', { params: { id } }),
    enabled: !!run,
    refetchInterval: pollWhile(active),
  })
  const batches = batchesQ.data?.items ?? []
  const profileName = profiles.data?.items.find((p) => p.id === run?.profile_id)?.name

  return (
    <div className="space-y-6">
      <div className="flex items-baseline gap-3">
        <Link to="/runs" className="text-sm text-brand hover:underline">
          ← Runs
        </Link>
        <h1 className="text-2xl font-semibold text-ink">Run #{Number.isFinite(id) ? id : '?'}</h1>
        {run && <StatusBadge status={run.status} />}
        {active && <span className="text-xs text-muted">live, refreshing every few seconds</span>}
      </div>
      {runQ.error && (
        <p className="text-sm text-danger">
          {runQ.error instanceof ApiError && runQ.error.status === 404
            ? 'Run not found.'
            : `Cannot load the run: ${runQ.error.message}`}
        </p>
      )}
      {run && (
        <section className={card}>
          <div className="flex flex-wrap items-start justify-between gap-4">
            <dl className="grid grid-cols-2 gap-x-8 gap-y-2 text-sm md:grid-cols-4">
              <div>
                <dt className="text-muted">Profile</dt>
                <dd className="font-medium text-ink">{profileName ?? `profile ${run.profile_id}`}</dd>
              </div>
              <div>
                <dt className="text-muted">Progress</dt>
                <dd>
                  <ProgressBar run={run} />
                </dd>
              </div>
              <div>
                <dt className="text-muted">Hosts up / total</dt>
                <dd className="font-medium text-ink">
                  {run.hosts_up} / {run.hosts_total}
                </dd>
              </div>
              <div>
                <dt className="text-muted">Duration</dt>
                <dd className="font-medium text-ink">{formatDuration(runDurationMs(run))}</dd>
              </div>
              <div>
                <dt className="text-muted">Created</dt>
                <dd>{formatTime(run.created_at)}</dd>
              </div>
              <div>
                <dt className="text-muted">Started</dt>
                <dd>{formatTime(run.started_at)}</dd>
              </div>
              <div>
                <dt className="text-muted">Finished</dt>
                <dd>{formatTime(run.finished_at)}</dd>
              </div>
            </dl>
            {canControl && active && <StopButton run={run} />}
          </div>
          <div className="mt-4">
            <Stats stats={run.stats} />
          </div>
        </section>
      )}
      {run && (
        <section className={card}>
          <div className="mb-3 flex items-baseline gap-3">
            <h2 className="text-lg font-semibold text-ink">Batches</h2>
            <span className="text-sm text-muted">{batches.length} total</span>
          </div>
          {batchesQ.error && <p className="text-sm text-danger">Cannot load batches: {batchesQ.error.message}</p>}
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr>
                  <th className={th}>Seq</th>
                  <th className={th}>Status</th>
                  <th className={th}>IPs</th>
                  <th className={th}>Hosts up</th>
                  <th className={th}>Attempts</th>
                  <th className={th}>Duration</th>
                  <th className={th}>Error</th>
                </tr>
              </thead>
              <tbody>
                {batches.map((b) => (
                  <tr key={b.id}>
                    <td className={td}>{b.seq}</td>
                    <td className={td}>
                      <StatusBadge status={b.status} />
                    </td>
                    <td className={td}>{b.host_count}</td>
                    <td className={td}>{b.hosts_up}</td>
                    <td className={td}>{b.attempts}</td>
                    <td className={td + ' whitespace-nowrap'}>{formatDuration(b.duration_ms)}</td>
                    <td className={td + ' max-w-md break-words text-danger'}>{b.error}</td>
                  </tr>
                ))}
                {batchesQ.data && batches.length === 0 && (
                  <tr>
                    <td className={td + ' text-muted'} colSpan={7}>
                      No batches (empty scan list).
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </section>
      )}
    </div>
  )
}
