import type { AppRoute } from '../types'
import { ChangesPage } from './ChangesPage'
import { HostTimelinePage } from './HostTimeline'

export const routes: AppRoute[] = [
  {
    path: '/changes',
    element: <ChangesPage />,
    perm: 'read',
    nav: { label: 'Changes', order: 35 },
  },
  { path: '/changes/hosts/:ip', element: <HostTimelinePage />, perm: 'read' },
]
