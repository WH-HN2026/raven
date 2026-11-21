// Shared bits of the Findings page: URL filters, API query, triage status mapping.
import type { Schemas } from '../../api/client'
import type { BadgeTone } from '../../components/ui'

export const PAGE = 50
export const findingsKey = ['findings'] as const

export type Finding = Schemas['Finding']
export type FindingPatch = Schemas['FindingPatch']
export type Severity = Schemas['Severity']

/** Critical first (the list's sort order). */
export const severities: Severity[] = ['Critical', 'High', 'Medium', 'Low', 'Info']
export const scanners = ['nmap', 'nuclei', 'raven']

/** The list filters, as kept in the URL query string. */
export interface FindingFilters {
  severity: Severity[]
  /** '' (any) | 'true' | 'false' */
  active: string
  ip: string
  q: string
  scanner: string
}

export const emptyFilters: FindingFilters = { severity: [], active: '', ip: '', q: '', scanner: '' }

export function filtersFromParams(p: URLSearchParams): FindingFilters {
  const sev = (p.get('severity') ?? '')
    .split(',')
    .map((s) => severities.find((v) => v.toLowerCase() === s.trim().toLowerCase()))
    .filter((s): s is Severity => !!s)
  const active = p.get('active') ?? ''
  return {
    severity: severities.filter((s) => sev.includes(s)),
    active: active === 'true' || active === 'false' ? active : '',
    ip: p.get('ip') ?? '',
    q: p.get('q') ?? '',
    scanner: p.get('scanner') ?? '',
  }
}

/** Query string for the filters (empty values dropped), the page offset (0 dropped) and the selected finding. */
export function paramsFromFilters(f: FindingFilters, offset = 0, selected?: number): URLSearchParams {
  const p = new URLSearchParams()
  if (f.severity.length) p.set('severity', severities.filter((s) => f.severity.includes(s)).join(','))
  if (f.active) p.set('active', f.active)
  for (const k of ['ip', 'q', 'scanner'] as const) {
    const v = f[k].trim()
    if (v) p.set(k, v)
  }
  if (offset > 0) p.set('offset', String(offset))
  if (selected !== undefined) p.set('id', String(selected))
  return p
}

export function offsetFromParams(p: URLSearchParams): number {
  const n = Number(p.get('offset') ?? 0)
  return Number.isInteger(n) && n > 0 ? n : 0
}

export function selectedFromParams(p: URLSearchParams): number | undefined {
  const n = Number(p.get('id') ?? '')
  return Number.isInteger(n) && n > 0 ? n : undefined
}

/** The API query for the filters (severities comma-joined by the client). */
export function apiQuery(f: FindingFilters, offset: number, limit = PAGE) {
  return {
    severity: f.severity.length ? f.severity : undefined,
    active: f.active === '' ? undefined : f.active === 'true',
    ip: f.ip.trim() || undefined,
    q: f.q.trim() || undefined,
    scanner: f.scanner.trim() || undefined,
    limit,
    offset,
  }
}

// ── triage status ──

/** A triage status the UI offers: exactly the combinations NormalizePatch accepts. */
export type Status = 'active' | 'verified' | 'false_p' | 'risk_accepted' | 'mitigated' | 'inactive'

export const statusLabel: Record<Status, string> = {
  active: 'Active',
  verified: 'Verified',
  false_p: 'False positive',
  risk_accepted: 'Risk accepted',
  mitigated: 'Mitigated',
  inactive: 'Inactive',
}

/** Statuses a user can set (inactive only comes from Dojo). */
export const settableStatuses: Status[] = ['active', 'verified', 'false_p', 'risk_accepted', 'mitigated']

export const statusTone: Record<Status, BadgeTone> = {
  active: 'outline',
  verified: 'done',
  false_p: 'gone',
  risk_accepted: 'rose',
  mitigated: 'new',
  inactive: 'gone',
}

type TriageState = Pick<Finding, 'active'> &
  Partial<Pick<Finding, 'verified' | 'false_p' | 'risk_accepted' | 'is_mitigated'>>

export function statusOf(f: TriageState): Status {
  if (f.false_p) return 'false_p'
  if (f.risk_accepted) return 'risk_accepted'
  if (f.is_mitigated) return 'mitigated'
  if (f.active) return f.verified ? 'verified' : 'active'
  return 'inactive'
}

/**
 * The full triage flags of a status. Each one is a state NormalizePatch allows
 * (no active + false_p/risk_accepted/mitigated, no false_p + verified).
 */
export function statusFlags(s: Status): Required<Omit<FindingPatch, 'severity'>> {
  const none = { active: false, verified: false, false_p: false, risk_accepted: false, is_mitigated: false }
  switch (s) {
    case 'active':
      return { ...none, active: true }
    case 'verified':
      return { ...none, active: true, verified: true }
    case 'false_p':
      return { ...none, false_p: true }
    case 'risk_accepted':
      return { ...none, risk_accepted: true }
    case 'mitigated':
      return { ...none, is_mitigated: true }
    case 'inactive':
      return none
  }
}

/** The PATCH body that moves f to status/severity: only the fields that change; null = nothing to do. */
export function triagePatch(f: Finding, status: Status, severity: Severity): FindingPatch | null {
  const p: FindingPatch = {}
  if (severity !== f.severity) p.severity = severity
  if (status !== statusOf(f)) {
    const want = statusFlags(status)
    const have: Record<keyof typeof want, boolean> = {
      active: f.active,
      verified: !!f.verified,
      false_p: !!f.false_p,
      risk_accepted: !!f.risk_accepted,
      is_mitigated: !!f.is_mitigated,
    }
    for (const k of Object.keys(want) as (keyof typeof want)[]) {
      if (want[k] !== have[k]) p[k] = want[k]
    }
  }
  return Object.keys(p).length ? p : null
}

export function sevKey(s: Severity): 'critical' | 'high' | 'medium' | 'low' | 'info' {
  return s.toLowerCase() as 'critical' | 'high' | 'medium' | 'low' | 'info'
}

export function fmtDate(s: string | null | undefined): string {
  return s ? new Date(s + 'T00:00:00').toLocaleDateString() : ''
}
