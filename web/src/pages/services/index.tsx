import type { AppRoute } from '../types'
import { ServicesPage } from './ServicesPage'

export const routes: AppRoute[] = [
  {
    path: '/services',
    element: <ServicesPage />,
    perm: 'read',
    nav: { label: 'Services', order: 30 },
  },
]
