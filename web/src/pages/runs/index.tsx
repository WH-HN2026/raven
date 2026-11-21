import { Placeholder } from '../../components/Placeholder'
import type { AppRoute } from '../types'

export const routes: AppRoute[] = [
  {
    path: '/runs',
    element: <Placeholder title="Runs" task="W2" />,
    perm: 'read',
    nav: { label: 'Runs', order: 60 },
  },
]
