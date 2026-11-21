import { useMutation } from '@tanstack/react-query'
import { NavLink, Navigate, Outlet, useLocation } from 'react-router'
import { api } from '../api/client'
import { useAuth } from '../auth/hooks'
import type { AppRoute } from '../pages/types'
import { Logo } from './Logo'

/** Visible sidebar entries for a set of permissions, in nav order. */
export function navItems(routes: AppRoute[], permissions: readonly string[]): AppRoute[] {
  return routes
    .filter((r) => r.nav && (!r.perm || permissions.includes(r.perm)))
    .sort((a, b) => (a.nav?.order ?? 0) - (b.nav?.order ?? 0))
}

export function Layout({ routes }: { routes: AppRoute[] }) {
  const { me, setMe } = useAuth()
  const location = useLocation()
  const logout = useMutation({
    mutationFn: () => api.post('/auth/logout'),
    onSettled: () => setMe(null),
  })

  if (!me) return <Navigate to="/login" replace state={{ from: location.pathname }} />
  const items = navItems(routes, me.permissions)

  return (
    <div className="flex h-full flex-col">
      <header className="flex items-center gap-4 bg-ink px-4 py-2 text-white">
        <Logo className="h-8 w-auto" />
        <div className="border-l border-graphite pl-4 font-semibold">ASI · Attack Surface Intelligence</div>
        <div className="ml-auto flex items-center gap-3 text-sm">
          <span>
            {me.user.username} <span className="rounded bg-graphite px-2 py-0.5 text-xs">{me.user.role}</span>
          </span>
          <button
            onClick={() => logout.mutate()}
            className="rounded border border-graphite px-3 py-1 hover:bg-graphite"
          >
            Log out
          </button>
        </div>
      </header>
      <div className="h-1 bg-accent" />
      <div className="flex min-h-0 flex-1">
        <nav aria-label="Main" className="w-56 shrink-0 overflow-y-auto border-r border-line bg-surface py-3">
          <ul>
            {items.map((r) => (
              <li key={r.path}>
                <NavLink
                  to={r.path}
                  end={r.path === '/'}
                  className={({ isActive }) =>
                    'block border-l-4 px-4 py-2 text-sm ' +
                    (isActive
                      ? 'border-brand bg-brand-light font-medium text-brand-dark'
                      : 'border-transparent text-graphite hover:bg-canvas')
                  }
                >
                  {r.nav?.label}
                </NavLink>
              </li>
            ))}
          </ul>
        </nav>
        <main className="min-w-0 flex-1 overflow-y-auto p-6">
          <Outlet />
        </main>
      </div>
    </div>
  )
}

/** Renders the page only if the role has its permission. */
export function Guard({ route }: { route: AppRoute }) {
  const { me } = useAuth()
  if (route.perm && !me?.permissions.includes(route.perm)) {
    return <p className="text-accent">You don&apos;t have access to this page.</p>
  }
  return <>{route.element}</>
}
