import { Placeholder } from '../../components/Placeholder'
import type { AppRoute } from '../types'

export const routes: AppRoute[] = [
  {
    path: '/findings',
    element: <Placeholder title="Findings" task="W5" />,
    perm: 'read',
    nav: { label: 'Findings', order: 40 },
  },
]
