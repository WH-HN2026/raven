// Test data for the profiles pages (only imported by tests).
import type { Profile, Schedule } from './ui'

export const profile: Profile = {
  id: 3,
  name: 'lab-quick',
  ports: '22,80,443,8000-8100',
  nmap_max_rate: 300,
  nuclei_rate: 20,
  nuclei_tags: ['tech', 'ssl'],
  miss_threshold: 3,
  target_batch_seconds: 600,
  enabled: true,
}

export const uiSchedule: Schedule = {
  id: 7,
  name: 'Nightly lab',
  profile_id: 3,
  source: 'ui',
  cron: '0 */6 * * *',
  window_start: '2026-11-21T21:00:00Z',
  window_end: '2026-11-22T05:00:00Z',
  timezone: 'Europe/Warsaw',
  enabled: true,
  dojo_url: '',
}

export const dojoSchedule: Schedule = {
  id: 8,
  name: 'Q4 planned audit',
  profile_id: 3,
  source: 'dojo',
  dojo_engagement_id: 118,
  cron: null,
  window_start: '2030-01-05T01:00:00Z',
  window_end: '2030-01-05T05:00:00Z',
  timezone: 'UTC',
  enabled: true,
  dojo_url: 'http://dojo.local/engagement/118',
}

export const scopeEntry = { id: 11, kind: 'ip', value: '172.30.0.99', list: 'exclude', profile_id: 3, note: '' }

/** fetch mock: answers every list endpoint the profiles pages use. */
export function route(url: string) {
  if (url.startsWith('/api/profiles')) return { items: [profile], total: 1 }
  if (url.startsWith('/api/schedules')) return { items: [uiSchedule, dojoSchedule], total: 2 }
  if (url.startsWith('/api/scope')) return { items: [scopeEntry], total: 1 }
  return { items: [], total: 0 }
}
