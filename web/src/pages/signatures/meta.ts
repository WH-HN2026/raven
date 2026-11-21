// Shared bits of the Signatures page: query keys and best-effort template header parsing.
import type { Schemas } from '../../api/client'
import type { Severity } from '../../components/ui'

export const signaturesKey = ['signatures'] as const
export const signatureKey = (id: number) => ['signatures', id] as const

export type Issue = Schemas['SignatureIssue']

export interface TemplateMeta {
  id: string
  name: string
  severity: Severity | null
  tags: string[]
}

const severities: Severity[] = ['critical', 'high', 'medium', 'low', 'info']

function unquote(s: string): string {
  const t = s.replace(/\s+#.*$/, '').trim()
  if (t.length >= 2 && (t[0] === '"' || t[0] === "'") && t[t.length - 1] === t[0]) return t.slice(1, -1)
  return t
}

/**
 * Reads id, info.name, info.severity and info.tags from a nuclei template without a YAML
 * library. Good enough for display; the backend validator is the source of truth.
 */
export function parseMeta(yaml: string): TemplateMeta {
  const meta: TemplateMeta = { id: '', name: '', severity: null, tags: [] }
  let inInfo = false
  let inTagList = false
  for (const raw of yaml.split('\n')) {
    const line = raw.replace(/\r$/, '')
    if (/^\S/.test(line)) {
      inTagList = false
      inInfo = /^info:\s*$/.test(line)
      const m = /^id:\s*(.+)$/.exec(line)
      if (m) meta.id = unquote(m[1]!)
      continue
    }
    if (!inInfo) continue
    if (inTagList) {
      const item = /^\s+-\s*(.+)$/.exec(line)
      if (item) {
        meta.tags.push(unquote(item[1]!))
        continue
      }
      inTagList = false
    }
    const kv = /^\s{1,4}([a-z-]+):\s*(.*)$/.exec(line)
    if (!kv) continue
    const [, key, value = ''] = kv
    const v = unquote(value)
    if (key === 'name') meta.name = v
    else if (key === 'severity') {
      const s = v.toLowerCase() as Severity
      meta.severity = severities.includes(s) ? s : null
    } else if (key === 'tags') {
      if (v === '') inTagList = true
      else
        meta.tags = v
          .replace(/^\[|\]$/g, '')
          .split(',')
          .map((t) => unquote(t))
          .filter(Boolean)
    }
  }
  return meta
}

/** Splits a stored validation_error ("line 3: msg; line 9: msg") back into issues. */
export function parseValidationError(s: string): Issue[] {
  if (!s) return []
  return s.split(/; (?=line \d+: )/).map((part) => {
    const m = /^line (\d+): ([\s\S]*)$/.exec(part)
    return m ? { line: Number(m[1]), message: m[2]! } : { line: 0, message: part }
  })
}

/** Issues from a 400 SignatureInvalid body, if that's what it is. */
export function issuesOf(body: unknown): Issue[] | null {
  const issues = (body as { issues?: unknown } | null)?.issues
  return Array.isArray(issues) ? (issues as Issue[]) : null
}

export const newTemplate = `id: my-signature
info:
  name: My signature
  author: raven
  severity: info
  tags: custom
http:
  - method: GET
    path:
      - "{{BaseURL}}/"
    matchers:
      - type: status
        status:
          - 200
`
