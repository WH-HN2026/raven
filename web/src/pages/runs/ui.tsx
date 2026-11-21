// Shared bits of the Runs pages (theme tokens only).
import type { Schemas } from '../../api/client'
import { Badge, type BadgeTone } from '../../components/ui'

export type Run = Schemas['Run']
export type RunStatus = Schemas['RunStatus']
export type Batch = Schemas['Batch']
export type BatchStatus = Batch['status']

export const runsKey = ['runs'] as const
export const profilesKey = ['profiles'] as const

/** How often an active run is re-fetched. */
export const POLL_MS = 2500

/** pending/running runs change on their own; everything else is settled. */
export function isActive(status: RunStatus | BatchStatus | undefined): boolean {
  return status === 'pending' || status === 'running'
}

/** TanStack Query refetchInterval: poll only while active. */
export function pollWhile(active: boolean): number | false {
  return active ? POLL_MS : false
}

export function formatDuration(ms: number | null | undefined): string {
  if (ms === null || ms === undefined || ms < 0) return '—'
  if (ms < 1000) return `${ms} ms`
  const s = Math.round(ms / 1000)
  if (s < 60) return `${s} s`
  const m = Math.floor(s / 60)
  if (m < 60) return `${m} min ${s % 60} s`
  return `${Math.floor(m / 60)} h ${m % 60} min`
}

/** Wall-clock duration of a run: start → finish, or start → now while active. */
export function runDurationMs(run: Run, now = Date.now()): number | null {
  if (!run.started_at) return null
  const end = run.finished_at ? Date.parse(run.finished_at) : isActive(run.status) ? now : null
  return end === null ? null : end - Date.parse(run.started_at)
}

export function formatTime(s: string | null | undefined): string {
  return s ? new Date(s).toLocaleString() : '—'
}

const badgeTone: Record<RunStatus, BadgeTone> = {
  pending: 'neutral',
  running: 'rose',
  suspended: 'rose',
  done: 'done',
  failed: 'red',
  stopped: 'gone',
}

export function StatusBadge({ status }: { status: RunStatus | BatchStatus }) {
  return <Badge tone={badgeTone[status]}>{status}</Badge>
}

/** Batch progress: done (green) and failed (red) segments of all batches. */
export function ProgressBar({ run }: { run: Pick<Run, 'batches_done' | 'batches_failed' | 'batches_total'> }) {
  const total = run.batches_total
  const pct = (n: number) => (total > 0 ? (100 * n) / total : 0)
  const label = total > 0 ? `${run.batches_done}/${total} batches` : 'no batches'
  return (
    <div className="flex min-w-36 items-center gap-2">
      <div
        role="progressbar"
        aria-label={label}
        aria-valuemin={0}
        aria-valuemax={total}
        aria-valuenow={run.batches_done}
        className="flex h-2.5 w-24 bg-band"
      >
        <div className="bg-green" style={{ width: `${pct(run.batches_done)}%` }} />
        <div className="bg-red" style={{ width: `${pct(run.batches_failed)}%` }} />
      </div>
      <span className="text-[13px] whitespace-nowrap text-muted">
        {total > 0 ? `${run.batches_done}/${total}` : '—'}
        {run.batches_failed > 0 && <span className="font-medium text-red"> ({run.batches_failed} failed)</span>}
      </span>
    </div>
  )
}

/** One square per batch: done green, running rose, failed red, pending grey. */
export function BatchStrip({ batches }: { batches: Batch[] }) {
  if (batches.length === 0) return null
  const fill: Record<BatchStatus, string> = {
    pending: 'bg-band border-on-dark-muted',
    running: 'bg-rose border-rose',
    done: 'bg-green border-green',
    failed: 'bg-red border-red',
    stopped: 'bg-line border-line',
  }
  const done = batches.filter((b) => b.status === 'done').length
  return (
    <div
      role="img"
      aria-label={`${done} of ${batches.length} batches done`}
      className="grid gap-[3px]"
      style={{ gridTemplateColumns: `repeat(${Math.min(batches.length, 24)}, minmax(0, 1fr))` }}
    >
      {batches.map((b) => (
        <span key={b.id} title={`#${b.seq} ${b.status}`} className={'h-8 border ' + fill[b.status]} />
      ))}
    </div>
  )
}
