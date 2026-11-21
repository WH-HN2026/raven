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
export const scanners = ['nmap', 'nuclei', 'nuclei_active', 'raven']

export const boolFlagKeys = [
  'active',
  'verified',
  'false_p',
  'out_of_scope',
  'risk_accepted',
  'duplicate',
  'is_mitigated',
] as const
export type BoolFlagKey = (typeof boolFlagKeys)[number]

/** The list filters, as kept in the URL query string. */
export interface FindingFilters {
  severity: Severity[]
  /** '' (any) | 'true' | 'false' */
  active: string
  verified: string
  false_p: string
  out_of_scope: string
  risk_accepted: string
  duplicate: string
  is_mitigated: string
  asset: string
  ip: string
  q: string
  scanner: string
}

export const emptyFilters: FindingFilters = {
  severity: [],
  active: '',
  verified: '',
  false_p: '',
  out_of_scope: '',
  risk_accepted: '',
  duplicate: '',
  is_mitigated: '',
  asset: '',
  ip: '',
  q: '',
  scanner: '',
}

function boolParam(p: URLSearchParams, key: string): string {
  const v = p.get(key) ?? ''
  return v === 'true' || v === 'false' ? v : ''
}

export function filtersFromParams(p: URLSearchParams): FindingFilters {
  const sev = (p.get('severity') ?? '')
    .split(',')
    .map((s) => severities.find((v) => v.toLowerCase() === s.trim().toLowerCase()))
    .filter((s): s is Severity => !!s)
  return {
    severity: severities.filter((s) => sev.includes(s)),
    active: boolParam(p, 'active'),
    verified: boolParam(p, 'verified'),
    false_p: boolParam(p, 'false_p'),
    out_of_scope: boolParam(p, 'out_of_scope'),
    risk_accepted: boolParam(p, 'risk_accepted'),
    duplicate: boolParam(p, 'duplicate'),
    is_mitigated: boolParam(p, 'is_mitigated'),
    asset: p.get('asset') ?? '',
    ip: p.get('ip') ?? '',
    q: p.get('q') ?? '',
    scanner: p.get('scanner') ?? '',
  }
}

/** Query string for the filters (empty values dropped), the page offset (0 dropped) and the selected finding. */
export function paramsFromFilters(f: FindingFilters, offset = 0, selected?: number): URLSearchParams {
  const p = new URLSearchParams()
  if (f.severity.length) p.set('severity', severities.filter((s) => f.severity.includes(s)).join(','))
  for (const k of boolFlagKeys) {
    if (f[k]) p.set(k, f[k])
  }
  for (const k of ['asset', 'ip', 'q', 'scanner'] as const) {
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

const optBool = (v: string) => (v === '' ? undefined : v === 'true')

/** The API query for the filters (severities comma-joined by the client). */
export function apiQuery(f: FindingFilters, offset: number, limit = PAGE) {
  return {
    severity: f.severity.length ? f.severity : undefined,
    active: optBool(f.active),
    verified: optBool(f.verified),
    false_p: optBool(f.false_p),
    out_of_scope: optBool(f.out_of_scope),
    risk_accepted: optBool(f.risk_accepted),
    duplicate: optBool(f.duplicate),
    is_mitigated: optBool(f.is_mitigated),
    asset: f.asset.trim() || undefined,
    ip: f.ip.trim() || undefined,
    q: f.q.trim() || undefined,
    scanner: f.scanner.trim() || undefined,
    limit,
    offset,
  }
}

/** Single-select status filter value for the filter bar, backed by the boolean query params. */
export type StatusFilterValue =
  | ''
  | 'active'
  | 'inactive'
  | 'verified'
  | 'false_p'
  | 'out_of_scope'
  | 'risk_accepted'
  | 'duplicate'
  | 'mitigated'

export const statusFilterOptions: { value: StatusFilterValue; label: string }[] = [
  { value: '', label: 'Any' },
  { value: 'active', label: 'Active' },
  { value: 'inactive', label: 'Inactive' },
  { value: 'verified', label: 'Verified' },
  { value: 'false_p', label: 'False positive' },
  { value: 'out_of_scope', label: 'Out of scope' },
  { value: 'risk_accepted', label: 'Risk accepted' },
  { value: 'duplicate', label: 'Duplicate' },
  { value: 'mitigated', label: 'Mitigated' },
]

export function statusFilterOf(f: FindingFilters): StatusFilterValue {
  if (f.verified === 'true') return 'verified'
  if (f.false_p === 'true') return 'false_p'
  if (f.out_of_scope === 'true') return 'out_of_scope'
  if (f.risk_accepted === 'true') return 'risk_accepted'
  if (f.duplicate === 'true') return 'duplicate'
  if (f.is_mitigated === 'true') return 'mitigated'
  if (f.active === 'true') return 'active'
  if (f.active === 'false') return 'inactive'
  return ''
}

export function withStatusFilter(f: FindingFilters, s: StatusFilterValue): FindingFilters {
  const cleared: FindingFilters = {
    ...f,
    active: '',
    verified: '',
    false_p: '',
    out_of_scope: '',
    risk_accepted: '',
    duplicate: '',
    is_mitigated: '',
  }
  switch (s) {
    case 'active':
      return { ...cleared, active: 'true' }
    case 'inactive':
      return { ...cleared, active: 'false' }
    case 'verified':
      return { ...cleared, verified: 'true' }
    case 'false_p':
      return { ...cleared, false_p: 'true' }
    case 'out_of_scope':
      return { ...cleared, out_of_scope: 'true' }
    case 'risk_accepted':
      return { ...cleared, risk_accepted: 'true' }
    case 'duplicate':
      return { ...cleared, duplicate: 'true' }
    case 'mitigated':
      return { ...cleared, is_mitigated: 'true' }
    default:
      return cleared
  }
}

// ── triage status ──

/** A triage status the UI displays; settableStatuses are the combinations NormalizePatch accepts. */
export type Status =
  | 'active'
  | 'verified'
  | 'false_p'
  | 'out_of_scope'
  | 'risk_accepted'
  | 'duplicate'
  | 'mitigated'
  | 'inactive'

export const statusLabel: Record<Status, string> = {
  active: 'Active',
  verified: 'Verified',
  false_p: 'False positive',
  out_of_scope: 'Out of scope',
  risk_accepted: 'Risk accepted',
  duplicate: 'Duplicate',
  mitigated: 'Mitigated',
  inactive: 'Inactive',
}

/** Statuses a user can set (inactive, out_of_scope, duplicate only come from Dojo). */
export const settableStatuses: Status[] = ['active', 'verified', 'false_p', 'risk_accepted', 'mitigated']

export const statusTone: Record<Status, BadgeTone> = {
  active: 'outline',
  verified: 'done',
  false_p: 'gone',
  out_of_scope: 'gone',
  risk_accepted: 'rose',
  duplicate: 'gone',
  mitigated: 'new',
  inactive: 'gone',
}

type TriageState = Pick<Finding, 'active'> &
  Partial<Pick<Finding, 'verified' | 'false_p' | 'out_of_scope' | 'risk_accepted' | 'duplicate' | 'is_mitigated'>>

export function statusOf(f: TriageState): Status {
  if (f.duplicate) return 'duplicate'
  if (f.false_p) return 'false_p'
  if (f.out_of_scope) return 'out_of_scope'
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
    case 'out_of_scope':
    case 'duplicate':
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
