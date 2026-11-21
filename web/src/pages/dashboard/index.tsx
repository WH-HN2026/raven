import type { AppRoute } from '../types'
import { DashboardPage } from './DashboardPage'

export const routes: AppRoute[] = [
  {
    path: '/',
    element: <DashboardPage />,
    perm: 'read',
    nav: { label: 'Dashboard', order: 10 },
  },
]
