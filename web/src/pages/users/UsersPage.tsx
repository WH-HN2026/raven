import { SortTh, useTableSort, useListOffset } from '../../components/SortTh'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Fragment, useState, type FormEvent } from 'react'
import { api, type Schemas } from '../../api/client'
import { useAuth, useCan } from '../../auth/hooks'
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
type ApiToken = Schemas['ApiToken']
type ApiTokenCreated = Schemas['ApiTokenCreated']

export const ROLE_OPTIONS: Role[] = ['admin', 'editor', 'operator', 'viewer']
export const MIN_PASSWORD = 12
const PAGE = 50
const usersKey = ['users'] as const
const tokensKey = ['api-tokens'] as const

export function UsersPage() {
  const canTokens = useCan('tokens:admin')
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
      <Section band className={canTokens ? '' : 'pb-16'}>
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
      {canTokens && (
        <Section className="pb-16">
          <ApiTokensSection users={q.data?.items ?? []} />
        </Section>
      )}
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
      void qc.invalidateQueries({ queryKey: tokensKey })
    },
  })
  const del = useMutation({
    mutationFn: () => api.delete('/users/{id}', { params: { id: user.id } }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: usersKey })
      void qc.invalidateQueries({ queryKey: tokensKey })
    },
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

function ApiTokensSection({ users }: { users: User[] }) {
  const qc = useQueryClient()
  const { me } = useAuth()
  const [offset, setOffset] = useState(0)
  const [name, setName] = useState('')
  const [userId, setUserId] = useState('')
  const [issued, setIssued] = useState<ApiTokenCreated | null>(null)
  const [copied, setCopied] = useState(false)

  const q = useQuery({
    queryKey: [...tokensKey, offset],
    queryFn: () => api.get('/tokens', { query: { limit: PAGE, offset } }),
  })

  const create = useMutation({
    mutationFn: () => {
      const uid = userId ? Number(userId) : undefined
      return api.post('/tokens', { body: { name: name.trim(), ...(uid ? { user_id: uid } : {}) } })
    },
    onSuccess: (tok) => {
      setIssued(tok)
      setCopied(false)
      setName('')
      void qc.invalidateQueries({ queryKey: tokensKey })
    },
  })

  const onSubmit = (e: FormEvent) => {
    e.preventDefault()
    if (name.trim()) create.mutate()
  }

  const copyToken = async () => {
    if (!issued) return
    try {
      await navigator.clipboard.writeText(issued.token)
      setCopied(true)
    } catch {
      setCopied(false)
    }
  }

  const total = q.data?.total ?? 0
  const selectedUserId = userId || (me?.user.id ? String(me.user.id) : '')

  return (
    <div className="flex flex-col gap-5">
      <SectionHeading aside={<span className="font-mono text-muted">/mcp</span>}>API tokens</SectionHeading>
      <form onSubmit={onSubmit} aria-label="Issue API token" className="flex flex-wrap items-end gap-4">
        <Field label="Token name" className="flex-[1_1_240px]">
          <input
            className={inputClass}
            value={name}
            maxLength={100}
            onChange={(e) => setName(e.target.value)}
            autoComplete="off"
          />
        </Field>
        <Field label="User" className="flex-[1_1_220px]">
          <select className={inputClass} value={selectedUserId} onChange={(e) => setUserId(e.target.value)}>
            {users.length === 0 && me && (
              <option value={String(me.user.id)}>
                {me.user.username} ({me.user.role})
              </option>
            )}
            {users.map((u) => (
              <option key={u.id} value={String(u.id)}>
                {u.username} ({u.role})
              </option>
            ))}
          </select>
        </Field>
        <Button type="submit" variant="primary" size="md" disabled={create.isPending || !name.trim()}>
          Issue token
        </Button>
      </form>
      {create.error && <Alert>{create.error.message}</Alert>}
      {issued && (
        <div role="status" className="flex flex-col gap-3 border border-line-strong bg-band p-4">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div className="flex flex-wrap items-center gap-2">
              <Badge tone="new">Shown once</Badge>
              <span className="font-medium">{issued.name}</span>
              <span className="text-muted">
                {issued.username} ({issued.role})
              </span>
            </div>
            <div className="flex gap-2">
              <Button size="sm" onClick={() => void copyToken()}>
                {copied ? 'Copied' : 'Copy'}
              </Button>
              <Button size="sm" onClick={() => setIssued(null)}>
                Dismiss
              </Button>
            </div>
          </div>
          <code data-testid="issued-token" className="block overflow-x-auto border border-line bg-white px-3 py-2 font-mono text-xs">
            {issued.token}
          </code>
        </div>
      )}
      {q.error && <ErrorText>Cannot load API tokens: {q.error.message}</ErrorText>}
      <Table label="API tokens" minWidth={880}>
        <thead>
          <THeadRow>
            <Th>Name</Th>
            <Th>User</Th>
            <Th>Role</Th>
            <Th>Created</Th>
            <Th>Last used</Th>
            <Th className="text-right">Actions</Th>
          </THeadRow>
        </thead>
        <tbody>
          {q.data?.items.map((t) => <TokenRow key={t.id} token={t} />)}
          {q.isPending && <EmptyRow colSpan={6}>Loading…</EmptyRow>}
          {q.isSuccess && q.data.items.length === 0 && <EmptyRow colSpan={6}>No API tokens</EmptyRow>}
        </tbody>
      </Table>
      <Pagination offset={offset} pageSize={PAGE} total={total} onChange={setOffset} />
    </div>
  )
}

function TokenRow({ token }: { token: ApiToken }) {
  const qc = useQueryClient()
  const [confirming, setConfirming] = useState(false)
  const revoke = useMutation({
    mutationFn: () => api.delete('/tokens/{id}', { params: { id: token.id } }),
    onSuccess: () => {
      setConfirming(false)
      void qc.invalidateQueries({ queryKey: tokensKey })
    },
  })

  return (
    <Fragment>
      <Tr className={confirming || revoke.error ? 'border-b-0' : ''}>
        <Td className="font-medium">{token.name}</Td>
        <Td>{token.username}</Td>
        <Td>
          <Badge tone="outline">{token.role}</Badge>
        </Td>
        <Td className="text-muted">{token.created_at ? new Date(token.created_at).toLocaleString() : '—'}</Td>
        <Td className="text-muted">{token.last_used_at ? new Date(token.last_used_at).toLocaleString() : 'Never'}</Td>
        <Td>
          <div className="flex justify-end">
            <Button variant="danger" size="sm" disabled={revoke.isPending} onClick={() => setConfirming((v) => !v)}>
              Revoke
            </Button>
          </div>
        </Td>
      </Tr>
      {(confirming || revoke.error) && (
        <tr className="border-b border-line">
          <td colSpan={6} className="pb-3">
            <div className="flex flex-col gap-3">
              {confirming && (
                <div className="flex flex-wrap items-center justify-end gap-3">
                  <span className="font-medium">Revoke {token.name}?</span>
                  <Button onClick={() => setConfirming(false)} disabled={revoke.isPending}>
                    Cancel
                  </Button>
                  <Button variant="primary" onClick={() => revoke.mutate()} disabled={revoke.isPending}>
                    Confirm revoke
                  </Button>
                </div>
              )}
              {revoke.error && <Alert>{revoke.error.message}</Alert>}
            </div>
          </td>
        </tr>
      )}
    </Fragment>
  )
}
