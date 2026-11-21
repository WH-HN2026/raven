import type { Schemas } from '../api/client'

/** Lists per-line input errors ("Line 3: …"), optionally with the offending input text. */
export function LineErrors({
  errors,
  title,
  inputOf,
}: {
  errors: Schemas['LineError'][]
  title?: string
  inputOf?: (line: number) => string | undefined
}) {
  if (errors.length === 0) return null
  return (
    <div role="alert" className="rounded border border-accent bg-accent-light px-3 py-2 text-sm text-accent-dark">
      {title && <p className="font-medium">{title}</p>}
      <ul className="mt-1 space-y-0.5">
        {errors.map((e, i) => {
          const input = inputOf?.(e.line)
          return (
            <li key={i}>
              <span className="font-mono font-medium">Line {e.line}</span>
              {input !== undefined && <span className="font-mono"> ({input})</span>}: {e.message}
            </li>
          )
        })}
      </ul>
    </div>
  )
}
