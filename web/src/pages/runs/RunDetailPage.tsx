import { SortTh, sortRows, useTableSort } from '../../components/SortTh'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'
import { useParams } from 'react-router'
import { api, ApiError } from '../../api/client'
import { useCan } from '../../auth/hooks'
import { PageHeader } from '../../components/PageHeader'
import { StageChips } from '../../components/StageChips'
import {
  Alert,
  Button,
  EmptyRow,
  ErrorText,
  KeyNumber,
  KeyNumbers,
  Section,
  SectionHeading,
  Table,
  Td,
  THeadRow,
  Tr,
} from '../../components/ui'
import {
  BatchStrip,
  formatDuration,
  formatTime,
  isActive,
  pollWhile,
  profilesKey,
  ProgressBar,
  runDurationMs,
  runsKey,
  StatusBadge,
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
        <Button variant="danger" size="lg" className="border-2" onClick={() => setConfirming(true)}>
          Stop run
        </Button>
      ) : (
        <div role="dialog" aria-label="Confirm stop" className="flex flex-col gap-3 border-2 border-red bg-white p-4">
          <p className="m-0 font-medium">Stop run #{run.id}?</p>
          <div className="flex justify-end">
            <Button onClick={() => setConfirming(false)} disabled={stop.isPending}>
              Cancel
            </Button>
            <Button variant="primary" onClick={() => stop.mutate()} disabled={stop.isPending}>
              {stop.isPending ? 'Stopping…' : 'Confirm stop'}
            </Button>
          </div>
        </div>
      )}
      {err && (
        <Alert>
          {err instanceof ApiError && err.status === 409 ? 'The run is no longer active.' : `Stop failed: ${err.message}`}
        </Alert>
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
      <div className="mb-2 text-xs font-medium tracking-[0.06em] text-muted uppercase">Stats</div>
      <dl className="m-0 grid grid-cols-1 gap-x-10 border-t-2 border-black text-sm sm:grid-cols-2 lg:grid-cols-3">
        {entries.map(([k, v]) => (
          <div key={k} className="flex justify-between gap-3 border-b border-line py-2.5">
            <dt className="text-muted">{k.replaceAll('_', ' ')}</dt>
            <dd className="m-0 text-right tabular-nums">
              {k.startsWith('duration_ms') && typeof v === 'number' ? formatDuration(v) : String(v)}
            </dd>
          </div>
        ))}
      </dl>
      {warnings.length > 0 && (
        <ul className="mt-3 flex list-none flex-col gap-1 p-0 text-sm">
          {warnings.map((w, i) => (
            <li key={i} className="border-l-2 border-sev-high pl-3">
              {w}
            </li>
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
  const sort = useTableSort(['seq', 'status', 'host_count', 'hosts_up', 'attempts', 'duration_ms', 'error'], { initial: 'seq' })
  const batches = batchesQ.data?.items ?? []
  const rows = sortRows(batches, sort, {
    seq: (b) => b.seq, status: (b) => b.status, host_count: (b) => b.host_count, hosts_up: (b) => b.hosts_up,
    attempts: (b) => b.attempts, duration_ms: (b) => b.duration_ms, error: (b) => b.error,
  })
  const profileName = profiles.data?.items.find((p) => p.id === run?.profile_id)?.name

  const title = `Run #${Number.isFinite(id) ? id : '?'}`
  const pct = run && run.batches_total > 0 ? Math.round((100 * run.batches_done) / run.batches_total) : null
  return (
    <>
      <PageHeader
        title={title}
        crumbs={[{ label: 'Runs', to: '/runs' }, { label: title }]}
        badges={run && <StatusBadge status={run.status} />}
      />
      {runQ.error && (
        <Section>
          <ErrorText>
            {runQ.error instanceof ApiError && runQ.error.status === 404
              ? 'Run not found.'
              : `Cannot load the run: ${runQ.error.message}`}
          </ErrorText>
        </Section>
      )}
      {run && (
        <Section label="Run" className="flex flex-col gap-8">
          <div className="flex flex-wrap items-end justify-between gap-4">
            <div className="flex flex-wrap items-center gap-3">
              <SectionHeading>{profileName ?? `profile ${run.profile_id}`}</SectionHeading>
              <StageChips stages={run.stages} />
            </div>
            {canControl && active && <StopButton run={run} />}
          </div>
          <div>
            <div className="mb-2 flex items-baseline justify-between gap-4">
              <ProgressBar run={run} />
              {pct !== null && <span className="text-[32px] font-light">{pct}%</span>}
            </div>
            <BatchStrip batches={batches} />
          </div>
          <KeyNumbers>
            <KeyNumber size="md" label="Hosts up / total" value={`${run.hosts_up} / ${run.hosts_total}`} />
            <KeyNumber size="md" label="Duration" value={formatDuration(runDurationMs(run))} />
            <KeyNumber size="sm" label="Created" value={formatTime(run.created_at)} />
            <KeyNumber size="sm" label="Started" value={formatTime(run.started_at)} />
            <KeyNumber size="sm" label="Finished" value={formatTime(run.finished_at)} />
          </KeyNumbers>
          <Stats stats={run.stats} />
        </Section>
      )}
      {run && (
        <Section band className="flex flex-col gap-4 pb-16">
          <SectionHeading>Batches · {batches.length}</SectionHeading>
          {batchesQ.error && <ErrorText>Cannot load batches: {batchesQ.error.message}</ErrorText>}
          <div className="bg-white px-5 pt-1 pb-2">
            <Table minWidth={760}>
              <thead>
                <THeadRow>
                  <SortTh sort={sort} col="seq">Seq</SortTh>
                  <SortTh sort={sort} col="status">Status</SortTh>
                  <SortTh sort={sort} col="host_count">IPs</SortTh>
                  <SortTh sort={sort} col="hosts_up">Hosts up</SortTh>
                  <SortTh sort={sort} col="attempts">Attempts</SortTh>
                  <SortTh sort={sort} col="duration_ms">Duration</SortTh>
                  <SortTh sort={sort} col="error">Error</SortTh>
                </THeadRow>
              </thead>
              <tbody>
                {rows.map((b) => (
                  <Tr key={b.id}>
                    <Td className="tabular-nums">{b.seq}</Td>
                    <Td>
                      <StatusBadge status={b.status} />
                    </Td>
                    <Td className="tabular-nums">{b.host_count}</Td>
                    <Td className="tabular-nums">{b.hosts_up}</Td>
                    <Td className="tabular-nums">{b.attempts}</Td>
                    <Td className="whitespace-nowrap">{formatDuration(b.duration_ms)}</Td>
                    <Td className="max-w-md font-mono text-[13px] break-words text-red">{b.error}</Td>
                  </Tr>
                ))}
                {batchesQ.data && batches.length === 0 && <EmptyRow colSpan={7}>No batches</EmptyRow>}
              </tbody>
            </Table>
          </div>
        </Section>
      )}
    </>
  )
}
