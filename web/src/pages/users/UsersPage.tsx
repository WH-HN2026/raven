import { SortTh, useTableSort, useListOffset } from '../../components/SortTh'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Fragment, useState, type FormEvent } from 'react'
import { api, type Schemas } from '../../api/client'
import { useAuth } from '../../auth/hooks'
import type { Role } from '../../auth/permissions'
import { PageHeader } from '../../components/PageHeader'
import {
  Alert,
  Badge,
  Button,
  EmptyRow,
  ErrorText,
  Field,
  Pagination,
  Section,
  SectionHeading,
  THeadRow,
  Table,
  Td,
  Th,
  Tr,
  inputClass,
} from '../../components/ui'

type User = Schemas['User']

export const ROLE_OPTIONS: Role[] = ['admin', 'editor', 'operator', 'viewer']
export const MIN_PASSWORD = 12
const PAGE = 50
const usersKey = ['users'] as const

export function UsersPage() {
  const [offset, setOffset] = useListOffset()
  const sort = useTableSort(['username', 'role', 'status', 'created_at'], { offset: 'offset', initial: 'username' })
  const q = useQuery({
    queryKey: [...usersKey, offset, sort.query],
    queryFn: () => api.get('/users', { query: { limit: PAGE, offset, ...sort.query } }),
  })
  const total = q.data?.total
  return (
    <>
      <PageHeader title="Users" meta={total !== undefined ? `${total} users` : undefined} />
      <Section>
        <CreateUserForm />
      </Section>
      <Section band className="pb-16">
        <div className="flex flex-col gap-5">
          <SectionHeading>Accounts</SectionHeading>
          {q.error && <ErrorText>Cannot load users: {q.error.message}</ErrorText>}
          <Table label="Users" minWidth={880}>
            <thead>
              <THeadRow>
                <SortTh sort={sort} col="username">Username</SortTh>
                <SortTh sort={sort} col="role">Role</SortTh>
                <SortTh sort={sort} col="status">Status</SortTh>
                <SortTh sort={sort} col="created_at">Created</SortTh>
                <Th className="text-right">Actions</Th>
              </THeadRow>
            </thead>
            <tbody>
              {q.data?.items.map((u) => <UserRow key={u.id} user={u} />)}
              {q.isPending && <EmptyRow colSpan={5}>Loading…</EmptyRow>}
              {q.isSuccess && q.data.items.length === 0 && <EmptyRow colSpan={5}>No users</EmptyRow>}
            </tbody>
          </Table>
          <Pagination offset={offset} pageSize={PAGE} total={total ?? 0} onChange={setOffset} />
        </div>
      </Section>
    </>
  )
}

function CreateUserForm() {
  const qc = useQueryClient()
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [role, setRole] = useState<Role>('viewer')
  const [created, setCreated] = useState<string | null>(null)
  const create = useMutation({
    mutationFn: () => api.post('/users', { body: { username: username.trim(), password, role } }),
    onSuccess: (u) => {
      setCreated(u.username)
      setUsername('')
      setPassword('')
      void qc.invalidateQueries({ queryKey: usersKey })
    },
  })
  const short = password.length > 0 && password.length < MIN_PASSWORD
  const onSubmit = (e: FormEvent) => {
    e.preventDefault()
    setCreated(null)
    if (username.trim() && !short) create.mutate()
  }
  return (
    <section className="flex flex-col gap-5">
      <SectionHeading>Add user</SectionHeading>
      <form onSubmit={onSubmit} aria-label="Add user" className="flex flex-wrap items-end gap-4">
        <Field label="Username" className="flex-[1_1_200px]">
          <input className={inputClass} value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="off" />
        </Field>
        <Field label={`Password (min ${MIN_PASSWORD})`} className="flex-[1_1_220px]">
          <input
            type="password"
            className={inputClass}
            value={password}
            aria-invalid={short}
            onChange={(e) => setPassword(e.target.value)}
            autoComplete="new-password"
          />
        </Field>
        <Field label="Role">
          <select className={inputClass} value={role} onChange={(e) => setRole(e.target.value as Role)}>
            {ROLE_OPTIONS.map((r) => (
              <option key={r} value={r}>
                {r}
              </option>
            ))}
          </select>
        </Field>
        <Button type="submit" variant="primary" size="md" disabled={create.isPending || !username.trim() || password.length < MIN_PASSWORD}>
          Add user
        </Button>
      </form>
      {create.error && <Alert>{create.error.message}</Alert>}
      {created && <Alert tone="ok">Created {created}</Alert>}
    </section>
  )
}

type Panel = null | 'password' | 'delete'

function UserRow({ user }: { user: User }) {
  const qc = useQueryClient()
  const { me } = useAuth()
  const self = me?.user.id === user.id
  const [panel, setPanel] = useState<Panel>(null)
  const [password, setPassword] = useState('')
  const [done, setDone] = useState<string | null>(null)

  const patch = useMutation({
    mutationFn: (body: Schemas['UserPatch']) => api.patch('/users/{id}', { params: { id: user.id }, body }),
    onSuccess: (_u, body) => {
      setDone(body.password ? 'Password reset' : null)
      setPanel(null)
      setPassword('')
      void qc.invalidateQueries({ queryKey: usersKey })
    },
  })
  const del = useMutation({
    mutationFn: () => api.delete('/users/{id}', { params: { id: user.id } }),
    onSuccess: () => qc.invalidateQueries({ queryKey: usersKey }),
  })
  const busy = patch.isPending || del.isPending
  const error = patch.error ?? del.error
  const open = (p: Panel) => {
    patch.reset()
    del.reset()
    setDone(null)
    setPanel(panel === p ? null : p)
  }

  return (
    <Fragment>
      <Tr className={error || panel || done ? 'border-b-0' : ''}>
        <Td className="font-medium">
          {user.username} {self && <Badge tone="outline">You</Badge>}
        </Td>
        <Td>
          <select
            aria-label={`Role of ${user.username}`}
            className={inputClass + ' h-9 w-32'}
            value={user.role}
            disabled={busy}
            onChange={(e) => {
              setDone(null)
              del.reset()
              patch.mutate({ role: e.target.value as Role })
            }}
          >
            {ROLE_OPTIONS.map((r) => (
              <option key={r} value={r}>
                {r}
              </option>
            ))}
          </select>
        </Td>
        <Td>{user.disabled ? <Badge tone="gone">Disabled</Badge> : <Badge tone="new">Active</Badge>}</Td>
        <Td className="text-muted">{user.created_at ? new Date(user.created_at).toLocaleString() : '—'}</Td>
        <Td>
          <div className="flex flex-wrap justify-end gap-2">
            <Button
              size="sm"
              disabled={busy}
              onClick={() => {
                setDone(null)
                del.reset()
                setPanel(null)
                patch.mutate({ disabled: !user.disabled })
              }}
            >
              {user.disabled ? 'Enable' : 'Disable'}
            </Button>
            <Button size="sm" disabled={busy} aria-expanded={panel === 'password'} onClick={() => open('password')}>
              Reset password
            </Button>
            <Button variant="danger" size="sm" disabled={busy} onClick={() => open('delete')}>
              Delete
            </Button>
          </div>
        </Td>
      </Tr>
      {(error || panel || done) && (
        <tr className="border-b border-line">
          <td colSpan={5} className="pb-3">
            <div className="flex flex-col gap-3">
              {panel === 'password' && (
                <form
                  aria-label={`Reset password of ${user.username}`}
                  className="flex flex-wrap items-end justify-end gap-3"
                  onSubmit={(e) => {
                    e.preventDefault()
                    if (password.length >= MIN_PASSWORD) patch.mutate({ password })
                  }}
                >
                  <Field label={`New password (min ${MIN_PASSWORD})`} className="w-72">
                    <input
                      type="password"
                      className={inputClass}
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      autoComplete="new-password"
                    />
                  </Field>
                  <Button onClick={() => setPanel(null)}>Cancel</Button>
                  <Button type="submit" variant="primary" disabled={busy || password.length < MIN_PASSWORD}>
                    Save password
                  </Button>
                </form>
              )}
              {panel === 'delete' && (
                <div className="flex flex-wrap items-center justify-end gap-3">
                  <span className="font-medium">Delete {user.username}?</span>
                  <Button onClick={() => setPanel(null)} disabled={busy}>
                    Cancel
                  </Button>
                  <Button variant="primary" onClick={() => del.mutate()} disabled={busy}>
                    Confirm delete
                  </Button>
                </div>
              )}
              {error && <Alert>{error.message}</Alert>}
              {done && <Alert tone="ok">{done}</Alert>}
            </div>
          </td>
        </tr>
      )}
    </Fragment>
  )
}
