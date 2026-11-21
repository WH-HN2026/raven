// Shared Tailwind class strings for the Targets & Scope page (theme tokens only).
export const card = 'rounded-lg border border-line bg-surface p-4 shadow-sm'
export const input =
  'rounded border border-line px-3 py-1.5 text-sm focus:border-brand focus:outline-none focus:ring-2 focus:ring-brand-light'
export const btnPrimary =
  'rounded bg-brand px-3 py-1.5 text-sm font-medium text-white hover:bg-brand-dark disabled:opacity-60'
export const btnSecondary =
  'rounded border border-line bg-surface px-3 py-1.5 text-sm text-graphite hover:bg-canvas disabled:opacity-60'
export const btnDanger = 'rounded px-2 py-0.5 text-sm text-accent hover:bg-accent-light disabled:opacity-60'
export const th = 'border-b border-line px-3 py-2 text-left text-xs font-semibold uppercase tracking-wide text-muted'
export const td = 'border-b border-line px-3 py-2 align-top'

export const targetsKey = ['targets'] as const
export const scopeKey = ['scope'] as const

/** Splits a comma/semicolon separated tag field. */
export function splitTags(s: string): string[] {
  return s
    .split(/[,;|]/)
    .map((t) => t.trim())
    .filter(Boolean)
}
