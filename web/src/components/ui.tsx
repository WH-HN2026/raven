// Shared UI building blocks for every page (docs/design/README.md "Rules").
// See components/README.md for when to use which. Theme tokens only.
import type { ButtonHTMLAttributes, ReactNode, TdHTMLAttributes, ThHTMLAttributes } from 'react'

/* ---------- layout ---------- */

/** A full-width content section: max 1440px, 40px side padding. `band` = grey background. */
export function Section({
  children,
  band = false,
  className = '',
  label,
}: {
  children: ReactNode
  band?: boolean
  className?: string
  /** aria-label for the section (when it has no heading). */
  label?: string
}) {
  return (
    <section aria-label={label} className={band ? 'bg-band' : ''}>
      <div className={'mx-auto max-w-[1440px] px-10 py-12 ' + className}>{children}</div>
    </section>
  )
}

/** Section heading: a 10×10 red square + Roboto Bold 28px (`size="sm"`: 22px, for narrow columns). */
export function SectionHeading({
  children,
  size = 'lg',
  square = 'red',
  aside,
}: {
  children: ReactNode
  size?: 'lg' | 'sm'
  /** Square colour: red (default), green (e.g. include lists). */
  square?: 'red' | 'green'
  /** Right-aligned content on the heading line (counts, links, buttons). */
  aside?: ReactNode
}) {
  const h = (
    <h2 className={'m-0 flex items-center gap-3.5 font-bold ' + (size === 'lg' ? 'text-[28px]' : 'text-[22px]')}>
      <span aria-hidden className={'size-2.5 flex-none ' + (square === 'green' ? 'bg-green' : 'bg-red')} />
      {children}
    </h2>
  )
  if (!aside) return h
  return (
    <div className="flex flex-wrap items-end justify-between gap-4">
      {h}
      <div className="flex flex-wrap items-center gap-2 text-sm">{aside}</div>
    </div>
  )
}

/* ---------- buttons ---------- */

export type ButtonVariant = 'primary' | 'secondary' | 'danger' | 'ghost'
export type ButtonSize = 'lg' | 'md' | 'sm'

/**
 * Class string for a button (also for <Link>s that look like buttons).
 * primary = red/white; secondary = 1px outline (white on black with onDark);
 * danger = red outline; sizes: lg 48px, md 44px, sm 36px.
 */
export function buttonClass(variant: ButtonVariant = 'secondary', size: ButtonSize = 'md', onDark = false): string {
  const base =
    'inline-flex items-center justify-center gap-2 no-underline whitespace-nowrap disabled:cursor-not-allowed disabled:opacity-50 '
  const sizes: Record<ButtonSize, string> = {
    lg: 'h-12 px-6 text-[15px]',
    md: 'h-11 px-[18px] text-sm',
    sm: 'h-9 px-3 text-[13px]',
  }
  const variants: Record<ButtonVariant, string> = {
    primary: 'border-0 bg-red font-medium text-white hover:bg-red/85 hover:text-white',
    secondary: onDark
      ? 'border border-white bg-transparent text-white hover:bg-white hover:text-black'
      : 'border border-line-strong bg-white text-ink hover:bg-black hover:text-white',
    danger: 'border border-red bg-white font-medium text-red hover:bg-red hover:text-white',
    ghost: 'border-0 bg-transparent text-ink underline decoration-red underline-offset-[3px] hover:text-red',
  }
  return base + sizes[size] + ' ' + variants[variant]
}

export function Button({
  variant = 'secondary',
  size = 'md',
  onDark = false,
  className = '',
  type = 'button',
  ...rest
}: ButtonHTMLAttributes<HTMLButtonElement> & { variant?: ButtonVariant; size?: ButtonSize; onDark?: boolean }) {
  return <button type={type} className={buttonClass(variant, size, onDark) + ' ' + className} {...rest} />
}

/** Joined square toggle buttons; the selected one is black. */
export function ToggleGroup<T extends string>({
  options,
  value,
  onChange,
  label,
}: {
  options: { value: T; label: ReactNode }[]
  value: T
  onChange: (v: T) => void
  /** Accessible group name (also shown as a field label when set). */
  label?: string
}) {
  return (
    <div role="group" aria-label={label} className="flex flex-wrap">
      {options.map((o, i) => {
        const on = o.value === value
        return (
          <button
            key={o.value}
            type="button"
            aria-pressed={on}
            onClick={() => onChange(o.value)}
            className={
              'h-11 border border-black px-4 text-sm ' +
              (i > 0 ? 'border-l-0 ' : '') +
              (on ? 'bg-black text-white' : 'bg-white text-ink hover:bg-band')
            }
          >
            {o.label}
          </button>
        )
      })}
    </div>
  )
}

/* ---------- forms ---------- */

/** 44px input / select with a 1px dark border. Add `font-mono` for IPs. */
export const inputClass =
  'h-11 w-full border border-line-strong bg-white px-3 text-sm text-ink placeholder:text-muted disabled:bg-band aria-[invalid=true]:border-red'
export const textareaClass =
  'w-full border border-line-strong bg-white px-3 py-2.5 text-sm text-ink placeholder:text-muted resize-y'

/** A label above its control (13px medium). Wrap the input as the child. */
export function Field({ label, children, className = '' }: { label: ReactNode; children: ReactNode; className?: string }) {
  return (
    <label className={'flex min-w-0 flex-col gap-1.5 text-[13px] font-medium text-ink ' + className}>
      {label}
      {children}
    </label>
  )
}

/** The grey filter band under the page header: fields side by side, bottom-aligned. */
export function FilterBar({ children, onSubmit }: { children: ReactNode; onSubmit?: (e: React.FormEvent) => void }) {
  return (
    <section aria-label="Filters" className="bg-band">
      <form
        role="search"
        onSubmit={onSubmit}
        className="mx-auto flex max-w-[1440px] flex-wrap items-end gap-4 px-10 py-7"
      >
        {children}
      </form>
    </section>
  )
}

/* ---------- data ---------- */

/** Table wrapper: horizontal scroll, 14px rows. Use <Th>/<Td> inside. */
export function Table({ children, minWidth, label }: { children: ReactNode; minWidth?: number; label?: string }) {
  return (
    <div className="overflow-x-auto">
      <table aria-label={label} className="w-full border-collapse text-sm" style={minWidth ? { minWidth } : undefined}>
        {children}
      </table>
    </div>
  )
}

/** Header row: put it in <thead>. 2px black bottom rule. */
export function THeadRow({ children }: { children: ReactNode }) {
  return (
    <tr className="border-b-2 border-black text-left text-xs tracking-[0.06em] text-muted uppercase">{children}</tr>
  )
}

/** Body row with a 1px separator. */
export function Tr({ children, className = '' }: { children: ReactNode; className?: string }) {
  return <tr className={'border-b border-line ' + className}>{children}</tr>
}

export function Th({ className = '', ...rest }: ThHTMLAttributes<HTMLTableCellElement>) {
  return <th className={'px-3 py-2.5 font-medium first:pl-0 last:pr-0 ' + className} {...rest} />
}

export function Td({ className = '', ...rest }: TdHTMLAttributes<HTMLTableCellElement>) {
  return <td className={'px-3 py-3 align-top first:pl-0 last:pr-0 ' + className} {...rest} />
}

/** A table row with one muted cell spanning the table (empty / loading). */
export function EmptyRow({ colSpan, children }: { colSpan: number; children: ReactNode }) {
  return (
    <tr className="border-b border-line">
      <td colSpan={colSpan} className="py-6 text-muted">
        {children}
      </td>
    </tr>
  )
}

/** Short muted text for an empty area outside a table. */
export function EmptyState({ children }: { children: ReactNode }) {
  return <p className="m-0 border-t-2 border-black py-6 text-muted">{children}</p>
}

/** "1–50 of 120" + joined Previous / Next. Renders nothing when everything fits on one page. */
export function Pagination({
  offset,
  pageSize,
  total,
  onChange,
}: {
  offset: number
  pageSize: number
  total: number
  onChange: (offset: number) => void
}) {
  if (total <= pageSize) return null
  return (
    <div className="flex flex-wrap items-center justify-between gap-3 pt-5 text-sm text-muted">
      <span>
        {Math.min(offset + 1, total)}–{Math.min(offset + pageSize, total)} of {total}
      </span>
      <div className="flex">
        <button
          type="button"
          className="h-11 border border-black bg-white px-[18px] text-ink hover:bg-band disabled:opacity-40"
          disabled={offset === 0}
          onClick={() => onChange(Math.max(0, offset - pageSize))}
        >
          Previous
        </button>
        <button
          type="button"
          className="h-11 border border-l-0 border-black bg-black px-[18px] text-white hover:bg-red disabled:bg-white disabled:text-ink disabled:opacity-40"
          disabled={offset + pageSize >= total}
          onClick={() => onChange(offset + pageSize)}
        >
          Next
        </button>
      </div>
    </div>
  )
}

/** Key number: 2px coloured left rule, 14px label, 52px light value (`size="md"`: 30px), optional note. */
export function KeyNumber({
  label,
  value,
  note,
  edge = 'red',
  size = 'lg',
}: {
  label: ReactNode
  value: ReactNode
  note?: ReactNode
  edge?: 'red' | 'green' | 'black' | 'rose'
  size?: 'lg' | 'md' | 'sm'
}) {
  const edges = { red: 'border-red', green: 'border-green', black: 'border-black', rose: 'border-rose' }
  const sizes = { lg: 'text-[52px] leading-[1.1]', md: 'text-[30px] leading-[1.2]', sm: 'text-xl leading-[1.3]' }
  return (
    <div className={'flex min-w-0 flex-col border-l-2 py-0.5 pl-[18px] ' + edges[edge]}>
      <span className="text-sm text-muted">{label}</span>
      <span className={'font-light break-words ' + sizes[size]}>{value}</span>
      {note && <span className="text-[13px] text-muted">{note}</span>}
    </div>
  )
}

/** Grid of KeyNumbers. */
export function KeyNumbers({ children, min = 170 }: { children: ReactNode; min?: number }) {
  return (
    <div className="grid gap-6" style={{ gridTemplateColumns: `repeat(auto-fit, minmax(${min}px, 1fr))` }}>
      {children}
    </div>
  )
}

/* ---------- badges ---------- */

export type BadgeTone = 'new' | 'changed' | 'gone' | 'done' | 'red' | 'rose' | 'neutral' | 'outline' | 'outline-dark'

const badgeTones: Record<BadgeTone, string> = {
  new: 'bg-green text-white', // + NEW, up, done-ok, high confidence
  changed: 'bg-rose text-ink', // ~ CHANGED, running, medium confidence, SUSPENDED
  rose: 'bg-rose text-ink',
  gone: 'bg-line text-ink', // − GONE, inactive
  done: 'bg-black text-white', // DONE
  red: 'bg-red text-white', // failed, interest score, role
  neutral: 'bg-band text-ink',
  outline: 'border border-line-strong text-ink',
  'outline-dark': 'border border-sev-info text-white', // on the black header
}

/** Solid, uppercase 12px badge. */
export function Badge({ tone = 'neutral', children, title }: { tone?: BadgeTone; children: ReactNode; title?: string }) {
  return (
    <span
      title={title}
      className={
        'inline-block px-2 py-[3px] text-xs leading-[1.4] font-medium tracking-[0.06em] whitespace-nowrap uppercase ' +
        badgeTones[tone]
      }
    >
      {children}
    </span>
  )
}

/** Small chip (tags, ports, technologies). `filled` = rose tag; default 1px outline. */
export function Chip({ children, variant = 'outline', mono = false }: { children: ReactNode; variant?: 'outline' | 'filled' | 'light'; mono?: boolean }) {
  const v = {
    outline: 'border border-line-strong',
    filled: 'bg-rose text-ink',
    light: 'border border-on-dark-muted',
  }[variant]
  return (
    <span className={'inline-block px-2 py-px text-[13px] whitespace-nowrap ' + v + (mono ? ' font-mono text-xs' : '')}>
      {children}
    </span>
  )
}

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info'
const sevColor: Record<Severity, string> = {
  critical: 'bg-sev-critical',
  high: 'bg-sev-high',
  medium: 'bg-sev-medium',
  low: 'bg-sev-low',
  info: 'bg-sev-info',
}

/** Severity: a colour square plus its text label (never colour alone). */
export function SeverityLabel({ severity }: { severity: Severity }) {
  return (
    <span className="inline-flex items-center gap-2">
      <span aria-hidden className={'size-2.5 flex-none ' + sevColor[severity]} />
      <span className="capitalize">{severity}</span>
    </span>
  )
}

/* ---------- messages ---------- */

/** Error / success message: a 2px left rule on the band background. */
export function Alert({ tone = 'error', children }: { tone?: 'error' | 'ok'; children: ReactNode }) {
  return (
    <div
      role={tone === 'error' ? 'alert' : 'status'}
      className={'border-l-2 bg-band px-4 py-2.5 text-sm ' + (tone === 'error' ? 'border-red' : 'border-green')}
    >
      {children}
    </div>
  )
}

/** Inline error text (query failures), red. */
export function ErrorText({ children }: { children: ReactNode }) {
  return <p className="m-0 text-sm font-medium text-red">{children}</p>
}

/** Lock + "Admin only", for read-only areas that need explaining. */
export function AdminOnly() {
  return (
    <div className="flex items-center gap-3 bg-band px-4 py-3.5 text-sm">
      <svg
        width="18"
        height="18"
        viewBox="0 0 24 24"
        fill="none"
        stroke="currentColor"
        strokeWidth="2"
        strokeLinecap="square"
        aria-hidden
      >
        <rect x="5" y="11" width="14" height="9" />
        <path d="M8 11V8a4 4 0 0 1 8 0v3" />
      </svg>
      <span>Admin only</span>
    </div>
  )
}
