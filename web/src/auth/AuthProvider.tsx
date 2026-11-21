import { useQuery, useQueryClient } from '@tanstack/react-query'
import { useCallback, type ReactNode } from 'react'
import { ApiError, api } from '../api/client'
import { AuthContext, type Me } from './AuthContext'

export const meQueryKey = ['auth', 'me'] as const

async function fetchMe(): Promise<Me | null> {
  try {
    return await api.get('/auth/me')
  } catch (e) {
    if (e instanceof ApiError && e.status === 401) return null
    throw e
  }
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const qc = useQueryClient()
  const { data, isPending, error } = useQuery({ queryKey: meQueryKey, queryFn: fetchMe, retry: false })
  const setMe = useCallback((me: Me | null) => qc.setQueryData(meQueryKey, me), [qc])

  if (isPending) return <div className="p-8 text-muted">Loading…</div>
  if (error) return <div className="p-10 font-medium text-red">Cannot reach the server: {error.message}</div>
  return <AuthContext.Provider value={{ me: data ?? null, setMe }}>{children}</AuthContext.Provider>
}
