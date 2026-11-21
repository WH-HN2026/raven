import type { AppRoute } from '../types'
import { SignatureEditorPage } from './SignatureEditor'
import { SignaturesList } from './SignaturesList'

export const routes: AppRoute[] = [
  {
    path: '/signatures',
    element: <SignaturesList />,
    perm: 'read',
    nav: { label: 'Signatures', order: 90 },
  },
  { path: '/signatures/new', element: <SignatureEditorPage />, perm: 'signatures:write' },
  { path: '/signatures/:id', element: <SignatureEditorPage />, perm: 'read' },
]
