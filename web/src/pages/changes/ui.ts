// Pure helpers of the Changes pages: URL params ↔ run ids, diff → table rows.
import type { Schemas } from '../../api/client'

export type RunDiff = Schemas['RunDiff']
export type DiffRun = Schemas['DiffRun']
export type HostChange = Schemas['HostChange']
export type ServiceChange = Schemas['ServiceChange']
export type Fingerprint = Schemas['ServiceFingerprint']
export type FingerprintField = keyof Fingerprint

export const changesKey = ['changes'] as const

export type ChangeKind = 'new' | 'changed' | 'gone'
export type ChangeFilter = 'all' | ChangeKind

/** Order of the fingerprint fields in the before/after cells. */
export const FINGERPRINT_FIELDS: FingerprintField[] = ['name', 'product', 'version', 'title', 'technologies']

/** Reads a positive run id from the query string (null when missing/invalid). */
export function runParam(params: URLSearchParams, name: 'from' | 'to'): number | null {
  const v = params.get(name)
  if (!v || !/^\d+$/.test(v)) return null
  const n = Number(v)
  return n >= 1 ? n : null
}

export type DiffRow =
  | { key: string; kind: ChangeKind; type: 'host'; ip: string; host: HostChange }
  | { key: string; kind: ChangeKind; type: 'service'; ip: string; service: ServiceChange }

/** Flattens a diff into one table: new, changed, gone; hosts before services. */
export function diffRows(d: RunDiff): DiffRow[] {
  const host = (kind: ChangeKind) => (h: HostChange): DiffRow => ({ key: `${kind}-h-${h.ip}`, kind, type: 'host', ip: h.ip, host: h })
  const svc = (kind: ChangeKind) => (s: ServiceChange): DiffRow => ({
    key: `${kind}-s-${s.ip}-${s.port}-${s.proto}`,
    kind,
    type: 'service',
    ip: s.ip,
    service: s,
  })
  return [
    ...d.hosts_new.map(host('new')),
    ...d.services_new.map(svc('new')),
    ...d.services_changed.map(svc('changed')),
    ...d.hosts_gone.map(host('gone')),
    ...d.services_gone.map(svc('gone')),
  ]
}

export function counts(d: RunDiff) {
  const s = d.summary
  const n = { new: s.hosts_new + s.services_new, changed: s.services_changed, gone: s.hosts_gone + s.services_gone }
  return { ...n, all: n.new + n.changed + n.gone }
}

/** A fingerprint field as text ('' when empty). */
export function fieldText(fp: Fingerprint, f: FingerprintField): string {
  const v = fp[f]
  return Array.isArray(v) ? v.join(', ') : v
}

/**
 * Fields shown in a before/after cell: the changed ones plus every non-empty one,
 * in FINGERPRINT_FIELDS order.
 */
export function shownFields(fp: Fingerprint | null | undefined, changed: string[]): FingerprintField[] {
  if (!fp) return []
  return FINGERPRINT_FIELDS.filter((f) => changed.includes(f) || fieldText(fp, f) !== '')
}

export function otherRunLabel(s: HostChange['other_run']): string {
  return s === 'not_scanned' ? 'not scanned' : 'down'
}

type RunTimes = { started_at?: string | null; finished_at?: string | null }

export function runTime(r: RunTimes): string {
  const t = r.finished_at ?? r.started_at
  return t ? new Date(t).toLocaleString() : '—'
}

export function runLabel(r: RunTimes & { id: number }): string {
  return `Run #${r.id} · ${runTime(r)}`
}
