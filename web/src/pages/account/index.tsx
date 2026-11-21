import { useMutation } from '@tanstack/react-query'
import { useState, type FormEvent } from 'react'
import { api } from '../../api/client'
import { useAuth } from '../../auth/hooks'
import { PageHeader } from '../../components/PageHeader'
import { Alert, Badge, Button, Field, Section, SectionHeading, inputClass } from '../../components/ui'
import type { AppRoute } from '../types'

const MIN_PASSWORD = 12

export function ProfilePage() {
  const { me } = useAuth()
  const [current, setCurrent] = useState('')
  const [next, setNext] = useState('')
  const [repeat, setRepeat] = useState('')
  const change = useMutation({
    mutationFn: () => api.patch('/auth/me/password', { body: { current_password: current, new_password: next } }),
    onSuccess: () => {
      setCurrent('')
      setNext('')
      setRepeat('')
    },
  })
  const mismatch = repeat.length > 0 && repeat !== next
  const ok = current.length > 0 && next.length >= MIN_PASSWORD && next === repeat
  const onSubmit = (e: FormEvent) => {
    e.preventDefault()
    if (ok) change.mutate()
  }
  return (
    <>
      <PageHeader title="Profile" />
      {me && (
        <Section>
          <dl className="m-0 flex flex-wrap gap-x-12 gap-y-4">
            <div>
              <dt className="text-sm text-muted">Username</dt>
              <dd className="m-0 font-medium">{me.user.username}</dd>
            </div>
            <div>
              <dt className="text-sm text-muted">Role</dt>
              <dd className="m-0">
                <Badge tone="red">{me.user.role}</Badge>
              </dd>
            </div>
          </dl>
        </Section>
      )}
      <Section>
        <form onSubmit={onSubmit} aria-label="Change password" className="flex max-w-[520px] flex-col gap-5">
          <SectionHeading>Change password</SectionHeading>
          <Field label="Current password">
            <input
              type="password"
              className={inputClass}
              value={current}
              onChange={(e) => setCurrent(e.target.value)}
              autoComplete="current-password"
            />
          </Field>
          <Field label={`New password (min ${MIN_PASSWORD})`}>
            <input
              type="password"
              className={inputClass}
              value={next}
              onChange={(e) => setNext(e.target.value)}
              autoComplete="new-password"
            />
          </Field>
          <Field label="Repeat new password">
            <input
              type="password"
              className={inputClass}
              value={repeat}
              aria-invalid={mismatch}
              onChange={(e) => setRepeat(e.target.value)}
              autoComplete="new-password"
            />
          </Field>
          {mismatch && <Alert>Passwords do not match</Alert>}
          {change.error && <Alert>{change.error.message}</Alert>}
          {change.isSuccess && <Alert tone="ok">Password changed</Alert>}
          <div>
            <Button type="submit" variant="primary" size="lg" disabled={!ok || change.isPending}>
              Change password
            </Button>
          </div>
        </form>
      </Section>
    </>
  )
}

export const routes: AppRoute[] = [{ path: '/account', perm: 'read', element: <ProfilePage /> }]
