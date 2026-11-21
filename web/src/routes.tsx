// Concatenates the route arrays exported by each page module. One line per area.
import { routes as changes } from './pages/changes'
import { routes as dashboard } from './pages/dashboard'
import { routes as exchange } from './pages/exchange'
import { routes as findings } from './pages/findings'
import { routes as hosts } from './pages/hosts'
import { routes as profiles } from './pages/profiles'
import { routes as runs } from './pages/runs'
import { routes as services } from './pages/services'
import { routes as signatures } from './pages/signatures'
import { routes as targets } from './pages/targets'
import { routes as users } from './pages/users'
import type { AppRoute } from './pages/types'

export const appRoutes: AppRoute[] = [
  ...dashboard,
  ...hosts,
  ...services,
  ...findings,
  ...changes,
  ...runs,
  ...targets,
  ...profiles,
  ...signatures,
  ...exchange,
  ...users,
]
