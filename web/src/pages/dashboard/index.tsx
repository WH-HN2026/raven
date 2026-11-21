import { Placeholder } from '../../components/Placeholder'
import type { AppRoute } from '../types'

export const routes: AppRoute[] = [
  {
    path: '/',
    element: <Placeholder title="Dashboard" task="W4" />,
    perm: 'read',
    nav: { label: 'Dashboard', order: 10 },
  },
]
