import { useEffect, useRef, useState } from 'react'

const LINE = 20 // px, must match leading-5
const PAD = 10 // px, must match py-2.5

/** A request to jump to a line; `seq` makes repeated clicks on the same line work. */
export interface GoTo {
  line: number
  seq: number
}

/** Start offset of each line in `text`. */
function lineStarts(text: string): number[] {
  const starts = [0]
  for (let i = 0; i < text.length; i++) if (text[i] === '\n') starts.push(i + 1)
  return starts
}

/**
 * Plain monospace textarea with a line-number gutter. Lines with issues are marked red in the
 * gutter; `goTo` scrolls to a line, selects it and highlights it.
 */
export function YamlEditor({
  value,
  onChange,
  readOnly = false,
  issueLines,
  goTo,
  label,
  rows = 28,
}: {
  value: string
  onChange?: (v: string) => void
  readOnly?: boolean
  issueLines: Set<number>
  goTo?: GoTo | null
  label: string
  rows?: number
}) {
  const ta = useRef<HTMLTextAreaElement>(null)
  const [scrollTop, setScrollTop] = useState(0)
  const [active, setActive] = useState<number | null>(null)
  const starts = lineStarts(value)

  useEffect(() => {
    if (!goTo || !ta.current) return
    const el = ta.current
    const line = Math.min(Math.max(goTo.line, 1), starts.length)
    const start = starts[line - 1]!
    const end = line < starts.length ? starts[line]! - 1 : value.length
    el.focus()
    el.setSelectionRange(start, end)
    el.scrollTop = Math.max(0, (line - 1) * LINE - el.clientHeight / 2 + LINE)
    setScrollTop(el.scrollTop)
    setActive(line)
    // Only react to new jump requests.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [goTo])

  const height = rows * LINE + 2 * PAD
  return (
    <div className="relative flex border border-line-strong bg-white font-mono text-[13px]" style={{ height }}>
      <div
        aria-hidden
        className="relative w-12 flex-none overflow-hidden border-r border-line bg-band text-right text-muted select-none"
      >
        <div style={{ transform: `translateY(${PAD - scrollTop}px)` }}>
          {starts.map((_, i) => {
            const n = i + 1
            const bad = issueLines.has(n)
            return (
              <div
                key={n}
                data-line={n}
                data-issue={bad || undefined}
                className={
                  'h-5 pr-2 leading-5 ' + (n === active ? 'bg-rose text-ink ' : '') + (bad ? 'font-medium text-red' : '')
                }
              >
                {n}
              </div>
            )
          })}
        </div>
      </div>
      <div className="relative min-w-0 flex-1">
        {active !== null && (
          <div
            aria-hidden
            className="pointer-events-none absolute inset-x-0 h-5 bg-rose/40"
            style={{ top: PAD + (active - 1) * LINE - scrollTop }}
          />
        )}
        <textarea
          ref={ta}
          aria-label={label}
          value={value}
          readOnly={readOnly}
          spellCheck={false}
          wrap="off"
          onChange={(e) => onChange?.(e.target.value)}
          onScroll={(e) => setScrollTop(e.currentTarget.scrollTop)}
          className="relative block h-full w-full resize-none overflow-auto border-0 bg-transparent px-3 py-2.5 leading-5 whitespace-pre text-ink outline-none read-only:text-ink"
        />
      </div>
    </div>
  )
}
