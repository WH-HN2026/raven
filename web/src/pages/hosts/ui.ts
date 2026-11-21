// Shared bits of the Hosts pages (theme tokens only).
import type { Schemas } from '../../api/client'
import type { BadgeTone } from '../../components/ui'

export const PAGE = 50
export const hostsKey = ['hosts'] as const

export type HostState = Schemas['HostState']
export const hostStates: HostState[] = ['active', 'unstable', 'inactive']

export function hostFindingsLink(ip: string): string {
  return '/findings?' + new URLSearchParams({ active: 'true', ip })
}

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

/** Badge tone for a host or service state: active/open green, unstable rose, the rest grey. */
export function stateTone(state: string): BadgeTone {
  switch (state) {
    case 'active':
    case 'open':
    case 'up':
      return 'new'
    case 'unstable':
      return 'rose'
    default:
      return 'gone'
  }
}
