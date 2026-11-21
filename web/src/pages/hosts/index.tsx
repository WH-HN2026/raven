import { Placeholder } from '../../components/Placeholder'
import type { AppRoute } from '../types'

export const routes: AppRoute[] = [
  {
    path: '/hosts',
    element: <Placeholder title="Hosts" task="W3" />,
    perm: 'read',
    nav: { label: 'Hosts', order: 20 },
  },
]
