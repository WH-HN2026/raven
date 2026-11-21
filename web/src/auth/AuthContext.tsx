import { createContext } from 'react'
import type { Schemas } from '../api/client'

export type Me = Schemas['Me']

export interface AuthState {
  me: Me | null
  setMe: (me: Me | null) => void
}

export const AuthContext = createContext<AuthState>({ me: null, setMe: () => {} })
