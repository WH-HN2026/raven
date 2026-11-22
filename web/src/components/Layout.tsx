import { useMutation } from '@tanstack/react-query'
import { NavLink, Navigate, Outlet, useLocation } from 'react-router'
import { api, type Schemas } from '../api/client'
import { useAuth } from '../auth/hooks'
import type { AppRoute } from '../pages/types'
import { Logo, RavenLogo } from './Logo'
import { PageHeader } from './PageHeader'
import { Squares } from './Squares'
import { Section } from './ui'

/** Visible nav entries for a set of permissions, in nav order. */
export function navItems(routes: AppRoute[], permissions: readonly string[]): AppRoute[] {
  return routes
    .filter((r) => r.nav && (!r.perm || permissions.includes(r.perm)))
    .sort((a, b) => (a.nav?.order ?? 0) - (b.nav?.order ?? 0))
}

/** The page frame: black top bar, the page (which renders its own PageHeader), footer. */
export function Layout({ routes }: { routes: AppRoute[] }) {
  const { me, setMe } = useAuth()
  const location = useLocation()
  const logout = useMutation({
    mutationFn: () => api.post('/auth/logout'),
    onSettled: () => setMe(null),
  })

  if (!me) return <Navigate to="/login" replace state={{ from: location.pathname }} />

  return (
    <div className="flex min-h-full flex-col bg-white">
      <TopBar items={navItems(routes, me.permissions)} user={me.user} onLogout={() => logout.mutate()} />
      <main className="flex-1">
        <Outlet />
      </main>
      <Footer />
    </div>
  )
}

/** Wordmark: AGH logo, rule, RAVEN wordmark SVG and subtitle. */
export function Brand() {
  return (
    <span className="flex items-center gap-3.5 py-3">
      <Logo className="h-[54px] w-7 shrink-0" />
      <span className="flex flex-col gap-0.5 border-l border-on-dark-rule pl-3.5">
        <RavenLogo className="block h-[30px] w-auto max-w-full self-start" />
        <span className="text-xs font-light text-on-dark-muted">Recon of Assets, Versions, Exposures &amp; Networks</span>
      </span>
    </span>
  )
}

/** The black top bar (docs/development/design/canvas/Nav.dc.html). */
export function TopBar({
  items,
  user,
  onLogout,
}: {
  items: AppRoute[]
  user: Schemas['Me']['user']
  onLogout: () => void
}) {
  return (
    <header className="bg-black text-white">
      <div className="mx-auto flex max-w-[1440px] flex-wrap items-center justify-between gap-x-6 px-10">
        <NavLink to="/" className="flex text-white no-underline hover:text-white">
          <Brand />
        </NavLink>
        <div className="flex flex-wrap items-center gap-3.5 py-3">
          <NavLink to="/account" title="Profile" className="text-sm text-white no-underline hover:text-on-dark-muted">
            {user.username}
          </NavLink>
          <span className="bg-red px-2 py-1 text-[11px] font-medium tracking-[0.08em] text-white uppercase">
            {user.role}
          </span>
          <button
            type="button"
            onClick={onLogout}
            className="border-b border-red text-[13px] text-white hover:text-on-dark-muted"
          >
            Log out
          </button>
        </div>
      </div>
      <div className="border-t border-on-dark-rule">
        <div className="mx-auto max-w-[1440px] px-10">
          <nav aria-label="Main" className="-mx-3 flex flex-nowrap items-stretch overflow-x-auto">
            {items.map((r) => (
              <NavLink
                key={r.path}
                to={r.path}
                end={r.path === '/'}
                className={({ isActive }) =>
                  'flex h-12 shrink-0 items-center whitespace-nowrap border-y-4 border-t-transparent px-3 text-[15px] text-white no-underline hover:text-white ' +
                  (isActive ? 'border-b-red font-medium' : 'border-b-transparent hover:border-b-on-dark-rule')
                }
              >
                {r.nav?.label}
              </NavLink>
            ))}
          </nav>
        </div>
      </div>
    </header>
  )
}

/** Footer (docs/development/design/canvas/Footer.dc.html): mirrored squares across the white/black edge, then a status line. */
export function Footer() {
  return (
    <footer className="bg-black font-sans text-white">
      <div className="bg-[linear-gradient(var(--color-white)_0_50%,var(--color-black)_50%_100%)]">
        <div className="mx-auto max-w-[1440px] px-10">
          <div className="max-w-[840px]">
            <Squares variant="footer" />
          </div>
        </div>
      </div>
      <div className="mx-auto flex max-w-[1440px] flex-wrap justify-between gap-x-6 gap-y-2 px-10 pt-2 pb-5 text-[13px] font-light text-on-dark">
        <span>Centrum Bezpieczeństwa Informacji AGH · RAVEN</span>
      </div>
    </footer>
  )
}

/** Renders the page only if the role has its permission. */
export function Guard({ route }: { route: AppRoute }) {
  const { me } = useAuth()
  if (route.perm && !me?.permissions.includes(route.perm)) {
    return (
      <>
        <PageHeader title={route.nav?.label ?? 'No access'} />
        <Section>
          <p className="m-0 font-medium text-red">No access.</p>
        </Section>
      </>
    )
  }
  return <>{route.element}</>
}
