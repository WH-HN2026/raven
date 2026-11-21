import type { ReactNode } from 'react'
import { Link } from 'react-router'
import { Squares } from './Squares'

export interface Crumb {
  label: string
  /** Omit for the current page (last crumb). */
  to?: string
}

/**
 * The black page header (docs/design/canvas/*.dc.html, top section): breadcrumb,
 * 64px light title, optional badges next to the title, a meta line with a red
 * left rule, actions, and the squares band on the right. Every page starts with it.
 */
export function PageHeader({
  title,
  crumbs,
  badges,
  meta,
  children,
  mono = false,
}: {
  title: ReactNode
  /** Breadcrumb before the title; "Dashboard" is prepended automatically. */
  crumbs?: Crumb[]
  /** Badges shown on the title line (state, score). */
  badges?: ReactNode
  /** Short data line under the title (red left rule). */
  meta?: ReactNode
  /** Actions: buttons with onDark. */
  children?: ReactNode
  /** Title in Roboto Mono (IPs). */
  mono?: boolean
}) {
  const trail: Crumb[] | null = crumbs ? [{ label: 'Dashboard', to: '/' }, ...crumbs] : null
  return (
    <section className="bg-black text-white">
      <div className="mx-auto flex max-w-[1440px] flex-wrap items-end justify-between gap-x-10 gap-y-6 px-10 pt-4 pb-11">
        <div className="flex min-w-0 flex-[1_1_520px] flex-col gap-[18px]">
          {trail && (
            <nav aria-label="Breadcrumb" className="text-sm text-on-dark-muted">
              {trail.map((c, i) => (
                <span key={i}>
                  {i > 0 && ' / '}
                  {c.to ? (
                    <Link to={c.to} className="text-on-dark-muted hover:text-white">
                      {c.label}
                    </Link>
                  ) : (
                    c.label
                  )}
                </span>
              ))}
            </nav>
          )}
          <div className="flex flex-wrap items-center gap-4">
            <h1 className={'m-0 leading-[1.05] font-light ' + (mono ? 'font-mono text-[56px] break-all' : 'text-[64px] break-words')}>
              {title}
            </h1>
            {badges}
          </div>
          {meta && (
            <div className="border-l-2 border-red pl-4 text-lg font-light text-on-dark [&_a]:text-white">{meta}</div>
          )}
          {children && <div className="flex flex-wrap gap-3">{children}</div>}
        </div>
        <div className="min-w-[280px] flex-[0_1_560px]">
          <Squares variant="masthead" />
        </div>
      </div>
    </section>
  )
}
