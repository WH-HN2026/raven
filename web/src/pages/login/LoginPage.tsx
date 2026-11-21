import { useMutation } from '@tanstack/react-query'
import { useState, type FormEvent } from 'react'
import { Navigate, useLocation, useNavigate } from 'react-router'
import { ApiError, api } from '../../api/client'
import { useAuth } from '../../auth/hooks'
import { Brand, Footer } from '../../components/Layout'
import { PageHeader } from '../../components/PageHeader'
import { Alert, Button, Field, Section, inputClass } from '../../components/ui'

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
    <div className="flex min-h-full flex-col bg-white">
      <header className="bg-black text-white">
        <div className="mx-auto flex min-h-20 max-w-[1440px] items-center px-10">
          <Brand />
        </div>
      </header>
      <PageHeader title="Sign in" />
      <main className="flex-1">
        <Section>
          <form onSubmit={onSubmit} className="flex max-w-sm flex-col gap-4">
            <Field label="Username">
              <input
                className={inputClass}
                autoComplete="username"
                autoFocus
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                required
              />
            </Field>
            <Field label="Password">
              <input
                type="password"
                className={inputClass}
                autoComplete="current-password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
              />
            </Field>
            {message && <Alert>{message}</Alert>}
            <Button type="submit" variant="primary" size="lg" disabled={login.isPending}>
              {login.isPending ? 'Signing in…' : 'Sign in'}
            </Button>
          </form>
        </Section>
      </main>
      <Footer />
    </div>
  )
}
