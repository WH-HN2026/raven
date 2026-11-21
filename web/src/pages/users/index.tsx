import { Placeholder } from '../../components/Placeholder'
import type { AppRoute } from '../types'

export const routes: AppRoute[] = [
  {
    path: '/users',
    element: <Placeholder title="Users" task="W9" />,
    perm: 'users:admin',
    nav: { label: 'Users', order: 110 },
  },
]
