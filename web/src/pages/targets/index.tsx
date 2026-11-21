import { Placeholder } from '../../components/Placeholder'
import type { AppRoute } from '../types'

export const routes: AppRoute[] = [
  {
    path: '/targets',
    element: <Placeholder title="Targets & Scope" task="W1" />,
    perm: 'read',
    nav: { label: 'Targets & Scope', order: 70 },
  },
]
