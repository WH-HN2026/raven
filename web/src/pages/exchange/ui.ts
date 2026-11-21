import type { Schemas } from '../../api/client'

export type ImportKind = 'results-json' | 'results-csv' | 'nmap-xml' | 'nuclei-jsonl' | 'nessus'

export const importKinds: { value: ImportKind; label: string }[] = [
  { value: 'results-json', label: 'RAVEN results JSON' },
  { value: 'results-csv', label: 'RAVEN results CSV' },
  { value: 'nmap-xml', label: 'nmap XML' },
  { value: 'nuclei-jsonl', label: 'nuclei JSONL' },
  { value: 'nessus', label: 'Nessus (.nessus)' },
]

export const kindLabel = (k: string) => importKinds.find((x) => x.value === k)?.label ?? k

export const IMPORT_ACCEPT = '.json,.csv,.xml,.jsonl,.ndjson,.nessus'
export const MAX_IMPORT_BYTES = 25 << 20

/** The kind the server picks from the file extension (exchange.DetectImportKind); undefined = sniffed from content. */
export function kindFromName(name: string): ImportKind | undefined {
  const n = name.trim().toLowerCase()
  if (n.endsWith('.nessus')) return 'nessus'
  if (n.endsWith('.xml')) return 'nmap-xml'
  if (n.endsWith('.jsonl') || n.endsWith('.ndjson')) return 'nuclei-jsonl'
  if (n.endsWith('.csv')) return 'results-csv'
  if (n.endsWith('.json')) return 'results-json'
  return undefined
}

/** A numeric run.stats entry, or undefined. */
export function statNum(run: Schemas['Run'], key: string): number | undefined {
  const v = run.stats[key]
  return typeof v === 'number' ? v : undefined
}

export function statStrings(run: Schemas['Run'], key: string): string[] {
  const v = run.stats[key]
  return Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string') : []
}

export function dojoPush(run: Schemas['Run']): { ok: number; failed: number } | undefined {
  const v = run.stats['dojo_push'] as { ok?: unknown; failed?: unknown } | undefined
  if (!v || typeof v !== 'object') return undefined
  return { ok: typeof v.ok === 'number' ? v.ok : 0, failed: typeof v.failed === 'number' ? v.failed : 0 }
}

export function fmtBytes(n: number): string {
  if (n < 1024) return `${n} B`
  if (n < 1 << 20) return `${(n / 1024).toFixed(1)} KiB`
  return `${(n / (1 << 20)).toFixed(1)} MiB`
}
