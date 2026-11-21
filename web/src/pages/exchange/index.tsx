import { Placeholder } from '../../components/Placeholder'
import type { AppRoute } from '../types'

export const routes: AppRoute[] = [
  {
    path: '/exchange',
    element: <Placeholder title="Import / Export" task="P3" />,
    perm: 'export',
    nav: { label: 'Import / Export', order: 100 },
  },
]
