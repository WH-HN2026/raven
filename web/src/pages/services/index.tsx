import { Placeholder } from '../../components/Placeholder'
import type { AppRoute } from '../types'

export const routes: AppRoute[] = [
  {
    path: '/services',
    element: <Placeholder title="Services & Technologies" task="W3" />,
    perm: 'read',
    nav: { label: 'Services & Technologies', order: 30 },
  },
]
