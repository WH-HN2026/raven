import type { AppRoute } from '../types'
import { FindingsPage } from './FindingsPage'

export const routes: AppRoute[] = [
  {
    path: '/findings',
    element: <FindingsPage />,
    perm: 'read',
    nav: { label: 'Findings', order: 40 },
  },
]
