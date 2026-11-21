// Shared bits of the Hosts pages (theme tokens only).
import type { Schemas } from '../../api/client'

export const card = 'rounded-lg border border-line bg-surface p-4 shadow-sm'
export const input =
  'rounded border border-line bg-surface px-3 py-1.5 text-sm focus:border-brand focus:outline-none focus:ring-2 focus:ring-brand-light'
export const btnPrimary =
  'rounded bg-brand px-3 py-1.5 text-sm font-medium text-white hover:bg-brand-dark disabled:opacity-60'
export const btnSecondary =
  'rounded border border-line bg-surface px-3 py-1.5 text-sm text-graphite hover:bg-canvas disabled:opacity-60'
export const th = 'border-b border-line px-3 py-2 text-left text-xs font-semibold uppercase tracking-wide text-muted'
export const td = 'border-b border-line px-3 py-2 align-top'
export const chip = 'rounded bg-brand-light px-1.5 py-0.5 text-xs text-brand-dark'
export const chipMuted = 'rounded bg-canvas px-1.5 py-0.5 text-xs text-graphite'

export const PAGE = 50
export const hostsKey = ['hosts'] as const

export type HostState = Schemas['HostState']
export const hostStates: HostState[] = ['active', 'unstable', 'inactive']

/** The list filters, as kept in the URL query string. */
export interface HostFilters {
  state: string
  port: string
  tech: string
  tag: string
  q: string
}
export const filterKeys = ['state', 'port', 'tech', 'tag', 'q'] as const

export function filtersFromParams(p: URLSearchParams): HostFilters {
  return {
    state: p.get('state') ?? '',
    port: p.get('port') ?? '',
    tech: p.get('tech') ?? '',
    tag: p.get('tag') ?? '',
    q: p.get('q') ?? '',
  }
}

/** Query string for the filters (empty values dropped) and a page offset (0 dropped). */
export function paramsFromFilters(f: HostFilters, offset = 0): URLSearchParams {
  const p = new URLSearchParams()
  for (const k of filterKeys) {
    const v = f[k].trim()
    if (v) p.set(k, v)
  }
  if (offset > 0) p.set('offset', String(offset))
  return p
}

export function offsetFromParams(p: URLSearchParams): number {
  const n = Number(p.get('offset') ?? 0)
  return Number.isInteger(n) && n > 0 ? n : 0
}

/** The API query for the filters: only set values, port as a number. */
export function apiQuery(f: HostFilters, offset: number) {
  const port = f.port.trim() === '' ? undefined : Number(f.port)
  return {
    state: (hostStates as string[]).includes(f.state) ? (f.state as HostState) : undefined,
    port: port !== undefined && Number.isInteger(port) ? port : undefined,
    tech: f.tech.trim() || undefined,
    tag: f.tag.trim() || undefined,
    q: f.q.trim() || undefined,
    limit: PAGE,
    offset,
  }
}

/** "22, 80, 443 +3" */
export function portsSummary(ports: number[], max = 8): string {
  if (ports.length <= max) return ports.join(', ')
  return ports.slice(0, max).join(', ') + ` +${ports.length - max}`
}

export function fmtTime(s: string | null | undefined): string {
  return s ? new Date(s).toLocaleString() : ''
}

export function stateClass(state: string): string {
  switch (state) {
    case 'active':
      return 'rounded bg-brand-light px-1.5 py-0.5 text-xs font-medium text-brand-dark'
    case 'unstable':
      return 'rounded border border-warn px-1.5 py-0.5 text-xs font-medium text-warn'
    default:
      return 'rounded bg-canvas px-1.5 py-0.5 text-xs font-medium text-muted'
  }
}
