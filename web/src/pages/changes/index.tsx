import { Placeholder } from '../../components/Placeholder'
import type { AppRoute } from '../types'

export const routes: AppRoute[] = [
  {
    path: '/changes',
    element: <Placeholder title="Changes" task="W6" />,
    perm: 'read',
    nav: { label: 'Changes', order: 35 },
  },
]
