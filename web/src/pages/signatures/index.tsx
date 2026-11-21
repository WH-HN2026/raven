import { Placeholder } from '../../components/Placeholder'
import type { AppRoute } from '../types'

export const routes: AppRoute[] = [
  {
    path: '/signatures',
    element: <Placeholder title="Signatures" task="W8" />,
    perm: 'read',
    nav: { label: 'Signatures', order: 90 },
  },
]
