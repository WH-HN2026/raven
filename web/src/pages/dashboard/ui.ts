// Pure helpers of the Dashboard page: API body → bars, rows and labels.
import type { Schemas } from '../../api/client'
import type { Severity as SeverityKey } from '../../components/ui'
import type { DiffRow } from '../changes/ui'

export type Dashboard = Schemas['Dashboard']
export type DashboardRun = Schemas['DashboardRun']
export type UnstableHost = Schemas['DashboardUnstableHost']
export type Severity = Schemas['Severity']

export const dashboardKey = ['dashboard'] as const

/** Width of a bar as a CSS percentage of the largest value (at least 2% when non-zero). */
export function pct(n: number, max: number): string {
  if (n <= 0 || max <= 0) return '0%'
  return `${Math.max(2, Math.round((n / max) * 100))}%`
}

export interface SeverityBar {
  severity: Severity
  key: SeverityKey
  count: number
  width: string
}

/** Bars for Critical…Low (scaled to the largest of them) and the Info count apart. */
export function severityBars(f: Dashboard['findings']): { bars: SeverityBar[]; info: number } {
  const ranked = f.by_severity.filter((s) => s.severity !== 'Info')
  const max = Math.max(0, ...ranked.map((s) => s.count))
  return {
    bars: ranked.map((s) => ({
      severity: s.severity,
      key: s.severity.toLowerCase() as SeverityKey,
      count: s.count,
      width: pct(s.count, max),
    })),
    info: f.by_severity.find((s) => s.severity === 'Info')?.count ?? 0,
  }
}

/** Findings list URL pre-filtered to active findings (of one severity). */
export function findingsLink(severity?: Severity): string {
  const p = new URLSearchParams({ active: 'true' })
  if (severity) p.set('severity', severity)
  return '/findings?' + p.toString()
}

/** Hosts list URL with one filter. */
export function hostsLink(filter: { state?: 'unstable' | 'inactive'; tech?: string }): string {
  const p = new URLSearchParams()
  if (filter.state) p.set('state', filter.state)
  if (filter.tech) p.set('tech', filter.tech)
  return '/hosts?' + p.toString()
}

export function changesLink(d: NonNullable<Dashboard['changes']>): string {
  return `/changes?from=${d.from.id}&to=${d.to.id}`
}

/** New / changed / gone totals of the diff summary (hosts + services). */
export function changeCounts(s: Schemas['DiffSummary']) {
  return {
    new: s.hosts_new + s.services_new,
    changed: s.services_changed,
    gone: s.hosts_gone + s.services_gone,
  }
}

function fpText(fp: Schemas['ServiceFingerprint'] | null | undefined): string {
  if (!fp) return ''
  const name = [fp.product || fp.name, fp.version].filter(Boolean).join(' ')
  return [name, fp.title].filter(Boolean).join(' · ')
}

/** One line for the "What changed" cell. */
export function changeText(r: DiffRow): string {
  if (r.type === 'host') {
    const ports = r.host.ports.join(', ')
    if (r.kind === 'new') return ports ? `Host up · ${ports}` : 'Host up'
    return ports ? `Host down · was ${ports}` : 'Host down'
  }
  const s = r.service
  if (r.kind === 'new') return fpText(s.after) || 'Port open'
  if (r.kind === 'gone') return fpText(s.before) || 'Port closed'
  return s.fields
    .map((f) => {
      const b = s.before?.[f]
      const a = s.after?.[f]
      const t = (v: unknown) => (Array.isArray(v) ? v.join(', ') : String(v ?? '')) || '—'
      return `${f}: ${t(b)} → ${t(a)}`
    })
    .join('; ')
}

/** "up in 3 of last 10 runs" or, for hosts never seen in a run, the last-seen date. */
export function unstablePattern(u: UnstableHost): string {
  if (u.seen_runs > 0) return `up in ${u.up_runs} of last ${u.seen_runs} runs`
  return `last seen ${new Date(u.last_seen).toLocaleDateString()}`
}

export function formatCount(n: number): string {
  return n.toLocaleString('en-US')
}
