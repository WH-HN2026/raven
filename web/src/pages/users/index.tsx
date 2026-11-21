import type { AppRoute } from '../types'
import { UsersPage } from './UsersPage'

export const routes: AppRoute[] = [
  {
    path: '/users',
    element: <UsersPage />,
    perm: 'users:admin',
    nav: { label: 'Users', order: 110 },
  },
]
