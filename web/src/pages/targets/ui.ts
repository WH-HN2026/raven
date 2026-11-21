// Shared bits of the Targets & scope page.
export const targetsKey = ['targets'] as const
export const scopeKey = ['scope'] as const

/** Splits a comma/semicolon separated tag field. */
export function splitTags(s: string): string[] {
  return s
    .split(/[,;|]/)
    .map((t) => t.trim())
    .filter(Boolean)
}
