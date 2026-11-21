import { useSearchParams } from 'react-router'
import { useCan } from '../auth/hooks'
import { buttonClass } from './ui'

export type ExportKind = 'hosts' | 'services' | 'findings' | 'changes' | 'targets'
export type ExportFormat = 'csv' | 'json'

/** Query params GET /api/export/{kind} honours (internal/httpapi/exchange.go), same names as the list pages' URLs. */
export const exportFilterKeys: Record<ExportKind, string[]> = {
  hosts: ['state', 'port', 'tech', 'tag', 'q'],
  services: ['port', 'proto', 'state', 'ip', 'product', 'technology', 'version', 'q'],
  findings: [
    'severity',
    'active',
    'verified',
    'false_p',
    'out_of_scope',
    'risk_accepted',
    'duplicate',
    'is_mitigated',
    'asset',
    'asset_id',
    'ip',
    'q',
    'scanner',
  ],
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
export function ExportButton({
  kind,
  onDark = false,
  disabled = false,
}: {
  kind: ExportKind
  onDark?: boolean
  /** Nothing to export (e.g. no diff yet): render inert. */
  disabled?: boolean
}) {
  const can = useCan('export')
  const [params] = useSearchParams()
  if (!can) return null
  const cls = buttonClass('secondary', 'md', onDark)
  return (
    <>
      {(['csv', 'json'] as const).map((f) =>
        disabled ? (
          <a key={f} role="link" aria-disabled="true" className={cls + ' pointer-events-none opacity-50'}>
            Export {f.toUpperCase()}
          </a>
        ) : (
          <a key={f} href={exportHref(kind, f, params)} download className={cls}>
            Export {f.toUpperCase()}
          </a>
        ),
      )}
    </>
  )
}
