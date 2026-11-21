import { Placeholder } from '../../components/Placeholder'
import type { AppRoute } from '../types'

export const routes: AppRoute[] = [
  {
    path: '/profiles',
    element: <Placeholder title="Profiles & Schedules" task="W7" />,
    perm: 'read',
    nav: { label: 'Profiles & Schedules', order: 80 },
  },
]
