import type { AppRoute } from '../types'
import { ProfileEditorPage } from './ProfileEditor'
import { ProfilesPage } from './ProfilesPage'

export const routes: AppRoute[] = [
  {
    path: '/profiles',
    element: <ProfilesPage />,
    perm: 'read',
    nav: { label: 'Profiles', order: 80 },
  },
  { path: '/profiles/new', element: <ProfileEditorPage />, perm: 'profiles:write' },
  { path: '/profiles/:id', element: <ProfileEditorPage />, perm: 'read' },
]
