import { useMutation } from '@tanstack/react-query'
import { useState, type FormEvent } from 'react'
import { Navigate, useLocation, useNavigate } from 'react-router'
import { ApiError, api } from '../../api/client'
import { useAuth } from '../../auth/hooks'
import { Logo } from '../../components/Logo'

export function LoginPage() {
  const { me, setMe } = useAuth()
  const navigate = useNavigate()
  const location = useLocation()
  const from = (location.state as { from?: string } | null)?.from ?? '/'
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')

  const login = useMutation({
    mutationFn: () => api.post('/auth/login', { body: { username, password } }),
    onSuccess: (data) => {
      setMe(data)
      navigate(from, { replace: true })
    },
  })

  if (me) return <Navigate to={from} replace />

  const onSubmit = (e: FormEvent) => {
    e.preventDefault()
    login.mutate()
  }
  const err = login.error
  const message =
    err instanceof ApiError && err.status === 401 ? 'Invalid username or password.' : err ? err.message : null

  return (
    <div className="flex min-h-full items-center justify-center bg-canvas p-4">
      <div className="w-full max-w-sm overflow-hidden rounded-lg border border-line bg-surface shadow-sm">
        <div className="flex items-center gap-3 bg-ink px-6 py-5 text-white">
          <Logo className="h-9 w-auto" />
          <div className="border-l border-graphite pl-3">
            <div className="text-lg font-semibold leading-tight">ASI</div>
            <div className="text-xs text-line">Attack Surface Intelligence</div>
          </div>
        </div>
        <div className="h-1 bg-accent" />
        <form onSubmit={onSubmit} className="space-y-4 p-6">
          <h1 className="text-xl font-semibold text-ink">Sign in</h1>
          <label className="block">
            <span className="text-sm text-graphite">Username</span>
            <input
              className="mt-1 w-full rounded border border-line px-3 py-2 focus:border-brand focus:outline-none focus:ring-2 focus:ring-brand-light"
              autoComplete="username"
              autoFocus
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              required
            />
          </label>
          <label className="block">
            <span className="text-sm text-graphite">Password</span>
            <input
              type="password"
              className="mt-1 w-full rounded border border-line px-3 py-2 focus:border-brand focus:outline-none focus:ring-2 focus:ring-brand-light"
              autoComplete="current-password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
            />
          </label>
          {message && (
            <p role="alert" className="rounded bg-accent-light px-3 py-2 text-sm text-accent-dark">
              {message}
            </p>
          )}
          <button
            type="submit"
            disabled={login.isPending}
            className="w-full rounded bg-brand px-4 py-2 font-medium text-white hover:bg-brand-dark disabled:opacity-60"
          >
            {login.isPending ? 'Signing in…' : 'Sign in'}
          </button>
        </form>
      </div>
    </div>
  )
}
