import type { Issue } from './meta'

/** Validation issues; "Line N" jumps to the line in the editor. */
export function IssueList({ issues, title, onGo }: { issues: Issue[]; title: string; onGo: (line: number) => void }) {
  if (issues.length === 0) return null
  return (
    <div role="alert" aria-label="Validation issues" className="border-l-2 border-red bg-band px-4 py-2.5 text-sm">
      <p className="m-0 font-medium">{title}</p>
      <ul className="mt-1 space-y-0.5">
        {issues.map((is, i) => (
          <li key={i}>
            {is.line > 0 ? (
              <button
                type="button"
                onClick={() => onGo(is.line)}
                className="border-0 bg-transparent p-0 font-mono font-medium text-red underline underline-offset-[3px] hover:text-ink"
              >
                Line {is.line}
              </button>
            ) : (
              <span className="font-mono font-medium text-red">Template</span>
            )}
            : {is.message}
          </li>
        ))}
      </ul>
    </div>
  )
}
