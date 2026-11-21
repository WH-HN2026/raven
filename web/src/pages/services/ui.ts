// Shared helpers for the Services & Technologies page.
import type { Schemas } from '../../api/client'
import type { BadgeTone, Severity } from '../../components/ui'

export const PAGE = 50
export const TECH_PAGE = 20
export const servicesKey = ['services'] as const
export const technologiesKey = ['technologies'] as const

export type ServiceItem = Schemas['ServiceItem']
export type TechnologySummary = Schemas['TechnologySummary']
export type ServiceState = 'open' | 'gone'
export type ServiceProto = 'tcp' | 'udp'
export type ServiceSort = 'ip' | 'port' | 'product' | 'version' | 'state' | 'first_seen' | 'last_seen'
export type SortOrder = 'asc' | 'desc'

export const serviceStates: ServiceState[] = ['open', 'gone']
export const serviceProtos: ServiceProto[] = ['tcp', 'udp']
export const serviceSorts: ServiceSort[] = ['ip', 'port', 'product', 'version', 'state', 'first_seen', 'last_seen']

export interface ServiceFilters {
  port: string
  proto: string
  product: string
  technology: string
  version: string
  state: string
  q: string
  sort: ServiceSort
  order: SortOrder
}

export const emptyFilters: ServiceFilters = {
  port: '',
  proto: '',
  product: '',
  technology: '',
  version: '',
  state: '',
  q: '',
  sort: 'ip',
  order: 'asc',
}

export function filtersFromParams(p: URLSearchParams): ServiceFilters {
  const sortRaw = p.get('sort') ?? 'ip'
  const sort = (serviceSorts as string[]).includes(sortRaw) ? (sortRaw as ServiceSort) : 'ip'
  const order: SortOrder = p.get('order') === 'desc' ? 'desc' : 'asc'
  const stateRaw = p.get('state') ?? ''
  const state = (serviceStates as string[]).includes(stateRaw) ? stateRaw : ''
  const protoRaw = p.get('proto') ?? p.get('protocol') ?? ''
  const proto = (serviceProtos as string[]).includes(protoRaw) ? protoRaw : ''
  return {
    port: p.get('port') ?? '',
    proto,
    product: p.get('product') ?? '',
    technology: p.get('technology') ?? p.get('tech') ?? '',
    version: p.get('version') ?? '',
    state,
    q: p.get('q') ?? '',
    sort,
    order,
  }
}

export function paramsFromFilters(f: ServiceFilters, offset = 0, techOffset = 0): URLSearchParams {
  const p = new URLSearchParams()
  for (const k of ['port', 'proto', 'product', 'technology', 'version', 'state', 'q'] as const) {
    const v = f[k].trim()
    if (v) p.set(k, v)
  }
  if (f.sort !== 'ip') p.set('sort', f.sort)
  if (f.order !== 'asc') p.set('order', f.order)
  if (offset > 0) p.set('offset', String(offset))
  if (techOffset > 0) p.set('tech_offset', String(techOffset))
  return p
}

export function offsetFromParams(p: URLSearchParams, key = 'offset'): number {
  const n = Number(p.get(key) ?? 0)
  return Number.isInteger(n) && n > 0 ? n : 0
}

export function apiQuery(f: ServiceFilters, offset: number) {
  const port = f.port.trim() === '' ? undefined : Number(f.port)
  return {
    port: port !== undefined && Number.isInteger(port) ? port : undefined,
    proto: (serviceProtos as string[]).includes(f.proto) ? (f.proto as ServiceProto) : undefined,
    product: f.product.trim() || undefined,
    technology: f.technology.trim() || undefined,
    version: f.version.trim() || undefined,
    state: (serviceStates as string[]).includes(f.state) ? (f.state as ServiceState) : undefined,
    q: f.q.trim() || undefined,
    sort: f.sort,
    order: f.order,
    limit: PAGE,
    offset,
  }
}

export function techApiQuery(f: ServiceFilters, offset: number) {
  return {
    state: (f.state === 'open' || f.state === 'gone' ? f.state : 'open') as 'open' | 'gone' | 'all',
    q: f.q.trim() || undefined,
    limit: TECH_PAGE,
    offset,
  }
}

export function sevKey(s: string): Severity | null {
  const low = s.toLowerCase()
  if (low === 'critical' || low === 'high' || low === 'medium' || low === 'low' || low === 'info') return low
  return null
}

export function stateTone(state: string): BadgeTone {
  return state === 'open' ? 'new' : 'gone'
}

export function fmtTime(s: string | null | undefined): string {
  return s ? new Date(s).toLocaleString() : ''
}
