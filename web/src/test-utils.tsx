// Test helpers for role-aware rendering. Only imported by *.test.tsx files.
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render } from '@testing-library/react'
import type { ReactNode } from 'react'
import { MemoryRouter, Route, Routes } from 'react-router'
import type { Schemas } from './api/client'
import { AuthContext } from './auth/AuthContext'
import type { Permission, Role } from './auth/permissions'

const viewer: Permission[] = ['read', 'export']
const operator: Permission[] = [...viewer, 'findings:edit', 'hosts:edit']
const editor: Permission[] = [
  ...operator,
  'targets:write',
  'scope:write',
  'profiles:write',
  'schedules:write',
  'signatures:write',
  'import',
  'runs:control',
]
const admin: Permission[] = [...editor, 'users:admin', 'tokens:admin', 'settings:admin', 'scope:global', 'audit:read']

/** Role → permissions, mirroring internal/auth/rbac.go. */
export const ROLE_PERMS: Record<Role, Permission[]> = { viewer, operator, editor, admin }
export const ROLES: Role[] = ['viewer', 'operator', 'editor', 'admin']

/** Renders `ui` at `path` (matched by `route`, default = path) as a user with `role`. */
export function renderAs(role: Role, ui: ReactNode, { path = '/', route }: { path?: string; route?: string } = {}) {
  const me: Schemas['Me'] = { user: { id: 1, username: 'me', role }, permissions: ROLE_PERMS[role] }
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <AuthContext.Provider value={{ me, setMe: () => {} }}>
        <MemoryRouter initialEntries={[path]}>
          <Routes>
            <Route path={route ?? path} element={ui} />
          </Routes>
        </MemoryRouter>
      </AuthContext.Provider>
    </QueryClientProvider>,
  )
}

export const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
