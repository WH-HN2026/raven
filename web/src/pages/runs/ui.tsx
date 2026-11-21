// Shared bits of the Runs pages (theme tokens only).
import type { Schemas } from '../../api/client'

export type Run = Schemas['Run']
export type RunStatus = Schemas['RunStatus']
export type Batch = Schemas['Batch']
export type BatchStatus = Batch['status']

export const card = 'rounded-lg border border-line bg-surface p-4 shadow-sm'
export const input =
  'rounded border border-line bg-surface px-3 py-1.5 text-sm focus:border-brand focus:outline-none focus:ring-2 focus:ring-brand-light'
export const btnPrimary =
  'rounded bg-brand px-3 py-1.5 text-sm font-medium text-white hover:bg-brand-dark disabled:opacity-60'
export const btnSecondary =
  'rounded border border-line bg-surface px-3 py-1.5 text-sm text-graphite hover:bg-canvas disabled:opacity-60'
export const btnDanger =
  'rounded bg-accent px-3 py-1.5 text-sm font-medium text-white hover:bg-accent-dark disabled:opacity-60'
export const th = 'border-b border-line px-3 py-2 text-left text-xs font-semibold uppercase tracking-wide text-muted'
export const td = 'border-b border-line px-3 py-2 align-top'

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

const badgeClass: Record<RunStatus, string> = {
  pending: 'bg-canvas text-graphite border-line',
  running: 'bg-brand-light text-brand-dark border-brand',
  suspended: 'bg-canvas text-warn border-warn',
  done: 'bg-brand text-white border-brand',
  failed: 'bg-accent-light text-accent-dark border-accent',
  stopped: 'bg-canvas text-muted border-line',
}

export function StatusBadge({ status }: { status: RunStatus | BatchStatus }) {
  return (
    <span
      className={`inline-flex items-center gap-1 rounded border px-1.5 py-0.5 text-xs font-medium ${badgeClass[status]}`}
    >
      {isActive(status) && <span aria-hidden className="h-1.5 w-1.5 animate-pulse rounded-full bg-current" />}
      {status}
    </span>
  )
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
        className="flex h-2 w-24 overflow-hidden rounded bg-canvas ring-1 ring-line"
      >
        <div className="bg-brand" style={{ width: `${pct(run.batches_done)}%` }} />
        <div className="bg-accent" style={{ width: `${pct(run.batches_failed)}%` }} />
      </div>
      <span className="whitespace-nowrap text-xs text-muted">
        {total > 0 ? `${run.batches_done}/${total}` : '—'}
        {run.batches_failed > 0 && <span className="text-danger"> ({run.batches_failed} failed)</span>}
      </span>
    </div>
  )
}
