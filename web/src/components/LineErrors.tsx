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
    <div role="alert" className="border-l-2 border-red bg-band px-4 py-2.5 text-sm">
      {title && <p className="m-0 font-medium">{title}</p>}
      <ul className="mt-1 space-y-0.5">
        {errors.map((e, i) => {
          const input = inputOf?.(e.line)
          return (
            <li key={i}>
              <span className="font-mono font-medium text-red">Line {e.line}</span>
              {input !== undefined && <span className="font-mono"> ({input})</span>}: {e.message}
            </li>
          )
        })}
      </ul>
    </div>
  )
}
