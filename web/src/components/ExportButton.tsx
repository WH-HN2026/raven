import { useSearchParams } from 'react-router'
import { useCan } from '../auth/hooks'
import { buttonClass } from './ui'

export type ExportKind = 'hosts' | 'services' | 'findings' | 'changes' | 'targets'
export type ExportFormat = 'csv' | 'json'

/** Query params GET /api/export/{kind} honours (internal/httpapi/exchange.go), same names as the list pages' URLs. */
export const exportFilterKeys: Record<ExportKind, string[]> = {
  hosts: ['state', 'port', 'tech', 'tag', 'q'],
  services: ['port', 'proto', 'state', 'ip', 'product', 'q'],
  findings: ['severity', 'active', 'ip', 'q', 'scanner'],
  changes: ['from', 'to', 'limit'],
  targets: [],
}

/** /api/export/{kind}?format=…&<the filters from `params` that the kind honours, empty ones dropped>. */
export function exportHref(kind: ExportKind, format: ExportFormat, params?: URLSearchParams): string {
  const qs = new URLSearchParams({ format })
  for (const k of exportFilterKeys[kind]) {
    const v = params?.get(k)?.trim()
    if (v) qs.set(k, v)
  }
  return `/api/export/${kind}?${qs.toString()}`
}

/**
 * "Export CSV" + "Export JSON" download links for `kind`, carrying the current
 * page's URL filters. Hidden without the export permission.
 */
export function ExportButton({ kind, onDark = false }: { kind: ExportKind; onDark?: boolean }) {
  const can = useCan('export')
  const [params] = useSearchParams()
  if (!can) return null
  return (
    <>
      {(['csv', 'json'] as const).map((f) => (
        <a key={f} href={exportHref(kind, f, params)} download className={buttonClass('secondary', 'md', onDark)}>
          Export {f.toUpperCase()}
        </a>
      ))}
    </>
  )
}
