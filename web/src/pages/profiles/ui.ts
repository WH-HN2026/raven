// Shared bits of the Profiles & schedules pages: query keys, client-side checks
// mirroring the backend (nmap.CheckPorts, scheduler.ParseCron) and timezone maths.
import { useQuery } from '@tanstack/react-query'
import { api, type Schemas } from '../../api/client'
import type { paths } from '../../api/schema'

export type Profile = Schemas['Profile']
export type Schedule = Schemas['Schedule']
export type StageName = Schemas['StageName']
export type StageInfo = Schemas['StageInfo']
export type StagesResponse = Schemas['StagesResponse']

// Same key as the Runs page uses, so its profile picker refreshes too.
export const profilesKey = ['profiles'] as const
export const schedulesKey = ['schedules'] as const
export const stagesKey = ['stages'] as const

export function useStages() {
  return useQuery({
    queryKey: stagesKey,
    queryFn: () => api.get('/stages'),
    staleTime: 5 * 60_000,
  })
}
type ProfileOrder = Pick<NonNullable<paths['/profiles']['get']['parameters']['query']>, 'sort' | 'dir'>

/** Profiles fit on one page (a handful per deployment). */
export function useProfiles(order?: ProfileOrder) {
  return useQuery({
    queryKey: order?.sort ? [...profilesKey, order] : profilesKey,
    queryFn: () => api.get('/profiles', { query: { limit: 1000, ...order } }),
  })
}

export const profileScopeKey = (id: number) => ['scope', 'profile', id] as const

/** Nuclei tags the backend allows (internal/scheduler/profiles.go). */
export const NUCLEI_TAGS = ['tech', 'panel', 'ssl', 'waf', 'favicon'] as const

/** Defaults the backend applies to a new profile. */
export const PROFILE_DEFAULTS = {
  nmap_max_rate: 300,
  nuclei_rate: 50,
  miss_threshold: 3,
  target_batch_seconds: 600,
  stages: ['nmap', 'httpx', 'nuclei'] as const,
}

/** Two decimal places preserve whole seconds when converted back and rounded. */
export function batchMinutes(seconds: number): number {
  return Number((seconds / 60).toFixed(2))
}

const PORT_SPEC = /^[0-9]+(-[0-9]+)?(,[0-9]+(-[0-9]+)?)*$/

/** Mirrors nmap.CheckPorts: digits, commas and ranges, ports 1–65535. Returns an error or null. */
export function checkPorts(spec: string): string | null {
  if (!PORT_SPEC.test(spec)) return 'port spec may contain only digits, commas and ranges like 1-1024'
  for (const part of spec.split(',')) {
    const [lo, hi] = part.split('-')
    const l = Number(lo)
    if (l < 1 || l > 65535) return `port "${lo}" out of range 1-65535`
    if (hi !== undefined) {
      const h = Number(hi)
      if (h < 1 || h > 65535) return `port "${hi}" out of range 1-65535`
      if (l > h) return `range ${part} is reversed`
    }
  }
  return null
}

// ── frequency (cron) ──

export type Frequency =
  | { kind: 'minutes'; n: number }
  | { kind: 'hours'; n: number }
  | { kind: 'daily'; time: string }
  | { kind: 'cron'; expr: string }

const pad = (n: number) => String(n).padStart(2, '0')

/** "HH:MM" → [hours, minutes]. */
function hm(s: string): [number, number] {
  const [h = '0', m = '0'] = s.split(':')
  return [Number(h), Number(m)]
}

export function frequencyToCron(f: Frequency): string {
  switch (f.kind) {
    case 'minutes':
      return f.n === 1 ? '* * * * *' : `*/${f.n} * * * *`
    case 'hours':
      return f.n === 1 ? '0 * * * *' : `0 */${f.n} * * *`
    case 'daily': {
      const [h, m] = hm(f.time)
      return `${m} ${h} * * *`
    }
    case 'cron':
      return f.expr.trim().split(/\s+/).join(' ')
  }
}

/** The editor's view of a stored cron; anything else is shown as a raw expression. */
export function cronToFrequency(cron: string | null | undefined): Frequency {
  const expr = (cron ?? '').trim().split(/\s+/).join(' ')
  let m: RegExpMatchArray | null
  if (expr === '* * * * *') return { kind: 'minutes', n: 1 }
  if ((m = expr.match(/^\*\/(\d+) \* \* \* \*$/))) return { kind: 'minutes', n: Number(m[1]) }
  if (expr === '0 * * * *') return { kind: 'hours', n: 1 }
  if ((m = expr.match(/^0 \*\/(\d+) \* \* \*$/))) return { kind: 'hours', n: Number(m[1]) }
  if ((m = expr.match(/^(\d{1,2}) (\d{1,2}) \* \* \*$/))) {
    const h = Number(m[2])
    const min = Number(m[1])
    if (h <= 23 && min <= 59) return { kind: 'daily', time: `${pad(h)}:${pad(min)}` }
  }
  return { kind: 'cron', expr: expr || '0 * * * *' }
}

/** Short label for a cron the backend accepts (scheduler.ParseCron forms). */
export function describeCron(cron: string | null | undefined): string {
  if (!cron) return '—'
  const f = cronToFrequency(cron)
  switch (f.kind) {
    case 'minutes':
      return f.n === 1 ? 'every minute' : `every ${f.n} min`
    case 'hours':
      return f.n === 1 ? 'every hour' : `every ${f.n} h`
    case 'daily':
      return `daily at ${f.time}`
    case 'cron': {
      const m = f.expr.match(/^(\d{1,2}) \* \* \* \*$/)
      return m ? `hourly at :${pad(Number(m[1]))}` : f.expr
    }
  }
}

// ── timezones ──

const FALLBACK_ZONES = ['UTC', 'Europe/Warsaw', 'Europe/London', 'America/New_York']

/** IANA timezone names for the select (always includes UTC and Europe/Warsaw). */
export function timezones(): string[] {
  let zones: string[] = []
  try {
    zones = Intl.supportedValuesOf('timeZone')
  } catch {
    // older runtimes
  }
  return [...new Set([...FALLBACK_ZONES, ...zones])].sort()
}

function zoneParts(tz: string, t: number) {
  const parts = new Intl.DateTimeFormat('en-US', {
    timeZone: tz,
    hourCycle: 'h23',
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  }).formatToParts(new Date(t))
  const get = (type: string) => Number(parts.find((p) => p.type === type)?.value)
  return { y: get('year'), mo: get('month'), d: get('day'), h: get('hour'), mi: get('minute'), s: get('second') }
}

/** Offset of tz from UTC at instant t, in ms. */
function offsetMs(tz: string, t: number): number {
  const p = zoneParts(tz, t)
  return Date.UTC(p.y, p.mo - 1, p.d, p.h, p.mi, p.s) - Math.floor(t / 1000) * 1000
}

/** The instant of the local wall time y-mo-d h:mi in tz (mo is 1-based; d may overflow). */
export function wallTime(tz: string, y: number, mo: number, d: number, h: number, mi: number): number {
  const guess = Date.UTC(y, mo - 1, d, h, mi)
  const first = guess - offsetMs(tz, guess)
  const second = guess - offsetMs(tz, first)
  return second
}

/** "HH:MM" of an instant in tz. */
export function clockIn(iso: string, tz: string): string {
  const p = zoneParts(tz, Date.parse(iso))
  return `${pad(p.h)}:${pad(p.mi)}`
}

/** A date + time in tz, e.g. "Sat 22 Nov, 22:00". */
export function formatIn(t: number, tz: string): string {
  return new Intl.DateTimeFormat('en-GB', {
    timeZone: tz,
    weekday: 'short',
    day: 'numeric',
    month: 'short',
    hour: '2-digit',
    minute: '2-digit',
    hourCycle: 'h23',
  }).format(new Date(t))
}

const minutes = (hhmm: string) => {
  const [h, m] = hm(hhmm)
  return h * 60 + m
}

/**
 * Daily window "HH:MM"–"HH:MM" in tz as the timestamps the API stores: today in tz,
 * with the end on the next day for an overnight window. Null when either is empty.
 */
export function windowToISO(start: string, end: string, tz: string, now = Date.now()) {
  if (!start || !end) return null
  const today = zoneParts(tz, now)
  const [sh, sm] = hm(start)
  const [eh, em] = hm(end)
  const endDay = today.d + (minutes(end) <= minutes(start) ? 1 : 0)
  return {
    window_start: new Date(wallTime(tz, today.y, today.mo, today.d, sh, sm)).toISOString(),
    window_end: new Date(wallTime(tz, today.y, today.mo, endDay, eh, em)).toISOString(),
  }
}

/** Window column: daily clock range for UI schedules, absolute range for Dojo ones. */
export function describeWindow(s: Schedule): string {
  if (!s.window_start || !s.window_end) return 'any time'
  const tz = s.timezone ?? 'UTC'
  if (s.source === 'dojo') return `${formatIn(Date.parse(s.window_start), tz)} – ${formatIn(Date.parse(s.window_end), tz)}`
  return `${clockIn(s.window_start, tz)}–${clockIn(s.window_end, tz)} daily`
}

/** Next window column: "open now", the next start, or "ended" for a past Dojo window. */
export function nextWindow(s: Schedule, now = Date.now()): string {
  const tz = s.timezone ?? 'UTC'
  if (!s.window_start || !s.window_end) return 'open now'
  if (s.source === 'dojo') {
    const start = Date.parse(s.window_start)
    const end = Date.parse(s.window_end)
    if (now < start) return formatIn(start, tz)
    return now < end ? 'open now' : 'ended'
  }
  const start = clockIn(s.window_start, tz)
  const end = clockIn(s.window_end, tz)
  const [sh, sm] = hm(start)
  const overnight = minutes(end) <= minutes(start)
  const [eh, em] = hm(end)
  const today = zoneParts(tz, now)
  for (const back of [-1, 0]) {
    const ws = wallTime(tz, today.y, today.mo, today.d + back, sh, sm)
    const we = wallTime(tz, today.y, today.mo, today.d + back + (overnight ? 1 : 0), eh, em)
    if (now >= ws && now < we) return 'open now'
  }
  const todayStart = wallTime(tz, today.y, today.mo, today.d, sh, sm)
  return formatIn(todayStart > now ? todayStart : wallTime(tz, today.y, today.mo, today.d + 1, sh, sm), tz)
}
