import type { AppRoute } from '../types'
import { HostDetailPage } from './HostDetail'
import { HostsPage } from './HostsList'

export const routes: AppRoute[] = [
  {
    path: '/hosts',
    element: <HostsPage />,
    perm: 'read',
    nav: { label: 'Hosts', order: 20 },
  },
  { path: '/hosts/:ip', element: <HostDetailPage />, perm: 'read' },
]
