import type { ReactNode } from 'react'
import type { Permission } from '../auth/permissions'

/** A route exported by a page module (web/src/pages/<area>/index.tsx). */
export interface AppRoute {
  path: string
  element: ReactNode
  /** Permission needed to see the page; the sidebar hides it otherwise. */
  perm?: Permission
  /** Sidebar entry; omit for routes that aren't in the nav (detail pages). */
  nav?: { label: string; order: number }
}
