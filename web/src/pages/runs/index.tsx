import type { AppRoute } from '../types'
import { RunDetailPage } from './RunDetailPage'
import { RunsPage } from './RunsPage'

export const routes: AppRoute[] = [
  {
    path: '/runs',
    element: <RunsPage />,
    perm: 'read',
    nav: { label: 'Runs', order: 60 },
  },
  { path: '/runs/:id', element: <RunDetailPage />, perm: 'read' },
]
