import { useContext } from 'react'
import { AuthContext } from './AuthContext'
import type { Permission } from './permissions'

export function useAuth() {
  return useContext(AuthContext)
}

/** useCan hides controls the role can't use. The backend check is the source of truth. */
export function useCan(perm: Permission | undefined): boolean {
  const { me } = useAuth()
  if (!perm) return true
  return !!me?.permissions.includes(perm)
}
