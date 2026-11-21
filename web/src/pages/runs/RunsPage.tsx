import { SortTh, useTableSort, useListOffset } from '../../components/SortTh'
import { keepPreviousData, useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'
import { Link, useNavigate } from 'react-router'
import { api, ApiError, type Schemas } from '../../api/client'
import { useCan } from '../../auth/hooks'
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
  Table,
  Td,
  Th,
  THeadRow,
  Tr,
  inputClass,
} from '../../components/ui'
import { StageChips } from '../../components/StageChips'
import {
  formatDuration,
  formatTime,
  isActive,
  pollWhile,
  profilesKey,
  ProgressBar,
  runDurationMs,
  runsKey,
  StatusBadge,
} from './ui'

const PAGE = 50

function useProfiles() {
  return useQuery({
    queryKey: profilesKey,
    queryFn: () => api.get('/profiles', { query: { limit: 1000 } }),
  })
}

export function StartRunForm() {
  const qc = useQueryClient()
  const navigate = useNavigate()
  const profiles = useProfiles()
  const enabled = (profiles.data?.items ?? []).filter((p) => p.enabled)
  const [picked, setPicked] = useState<number | null>(null)
  const [confirming, setConfirming] = useState(false)
  const profileId = picked ?? enabled[0]?.id ?? null
  const selected = enabled.find((p) => p.id === profileId) ?? null

  const start = useMutation({
    mutationFn: (body: { profile_id: number; confirm_aggressive?: boolean }) => api.post('/runs', { body }),
    onSuccess: (run) => {
      setConfirming(false)
      void qc.invalidateQueries({ queryKey: runsKey })
      void navigate(`/runs/${run.id}`)
    },
    onError: () => {
      setConfirming(false)
    },
  })

  const err = start.error
  const conflict = err instanceof ApiError && err.status === 409
  // The run that blocks a new one, if it's in the cached list.
  const blocking = conflict
    ? qc.getQueriesData<Schemas['RunList']>({ queryKey: runsKey })
        .flatMap(([, data]) => data?.items ?? [])
        .find((r) => r.profile_id === profileId && isActive(r.status))
    : undefined

  return (
    <section aria-label="Start a run" className="bg-band">
      <div className="mx-auto flex max-w-[1440px] flex-col gap-4 px-10 py-7">
        <form
          className="flex flex-wrap items-end gap-4"
          onSubmit={(e) => {
            e.preventDefault()
            if (profileId === null) return
            if (selected?.aggressive) {
              setConfirming(true)
              return
            }
            start.mutate({ profile_id: profileId })
          }}
        >
          <Field label="Profile" className="flex-[0_1_360px]">
            <select
              className={inputClass}
              value={profileId ?? ''}
              onChange={(e) => {
                setPicked(Number(e.target.value))
                setConfirming(false)
                start.reset()
              }}
              disabled={enabled.length === 0}
            >
              {enabled.map((p) => (
                <option key={p.id} value={p.id}>
                  {p.name}
                </option>
              ))}
            </select>
          </Field>
          <Button type="submit" variant="primary" disabled={profileId === null || start.isPending}>
            {start.isPending ? 'Starting…' : 'Start run'}
          </Button>
          {selected?.aggressive && <Badge tone="red">Aggressive</Badge>}
        </form>
        {confirming && selected?.aggressive && (
          <div role="dialog" aria-label="Start aggressive run?" className="flex flex-col gap-3 border-2 border-red bg-white p-4">
            <div className="flex flex-wrap items-center gap-2 font-medium">
              <span>Start aggressive run?</span>
              <Badge tone="red">Aggressive</Badge>
            </div>
            <div className="text-sm text-muted">
              Profile: <span className="font-medium text-ink">{selected.name}</span>
            </div>
            <div className="flex gap-2">
              <Button
                type="button"
                variant="primary"
                onClick={() => start.mutate({ profile_id: selected.id, confirm_aggressive: true })}
                disabled={start.isPending}
              >
                Start
              </Button>
              <Button type="button" onClick={() => setConfirming(false)} disabled={start.isPending}>
                Cancel
              </Button>
            </div>
          </div>
        )}
        {profiles.error && <ErrorText>Cannot load profiles: {profiles.error.message}</ErrorText>}
        {profiles.data && enabled.length === 0 && <p className="m-0 text-sm text-muted">No enabled profiles</p>}
        {err && (
          <Alert>
            {conflict ? (
              <>
                This profile already has an active run
                {blocking && (
                  <>
                    {' '}
                    (<Link className="font-medium" to={`/runs/${blocking.id}`}>
                      run #{blocking.id}
                    </Link>
                    )
                  </>
                )}
                .
              </>
            ) : (
              <>Cannot start the run: {err.message}</>
            )}
          </Alert>
        )}
      </div>
    </section>
  )
}

export function RunsTable() {
  const [offset, setOffset] = useListOffset()
  const sort = useTableSort(['id', 'profile', 'status', 'progress', 'hosts_up', 'started_at', 'duration'], { offset: 'offset', initial: 'id', direction: 'desc' })
  const profiles = useProfiles()
  const names = new Map((profiles.data?.items ?? []).map((p) => [p.id, p.name]))
  const q = useQuery({
    queryKey: [...runsKey, offset, sort.query],
    queryFn: () => api.get('/runs', { query: { limit: PAGE, offset, ...sort.query } }),
    placeholderData: keepPreviousData,
    refetchInterval: (query) => pollWhile(!!query.state.data?.items.some((r) => isActive(r.status))),
  })
  const items = q.data?.items ?? []
  const total = q.data?.total ?? 0

  return (
    <Section className="flex flex-col gap-4 pb-16">
      <SectionHeading>Runs · {total}</SectionHeading>
      {q.error && <ErrorText>Cannot load runs: {q.error.message}</ErrorText>}
      <Table minWidth={760}>
        <thead>
          <THeadRow>
            <SortTh sort={sort} col="id">Run</SortTh>
            <SortTh sort={sort} col="profile">Profile</SortTh>
            <Th>Workflow</Th>
            <SortTh sort={sort} col="status">Status</SortTh>
            <SortTh sort={sort} col="progress">Progress</SortTh>
            <SortTh sort={sort} col="hosts_up">Hosts up / total</SortTh>
            <SortTh sort={sort} col="started_at">Started</SortTh>
            <SortTh sort={sort} col="duration" className="text-right">Duration</SortTh>
          </THeadRow>
        </thead>
        <tbody>
          {items.map((r) => (
            <Tr key={r.id}>
              <Td className="text-xl leading-none font-light">
                <Link to={`/runs/${r.id}`}>#{r.id}</Link>
              </Td>
              <Td>
                <span className="inline-flex flex-wrap items-center gap-2">
                  {names.get(r.profile_id) ?? `profile ${r.profile_id}`}
                  {r.aggressive && <Badge tone="red">Aggressive</Badge>}
                </span>
              </Td>
              <Td>
                <StageChips stages={r.stages} />
              </Td>
              <Td>
                <StatusBadge status={r.status} />
              </Td>
              <Td>
                <ProgressBar run={r} />
              </Td>
              <Td className="whitespace-nowrap tabular-nums">
                {r.hosts_up} / {r.hosts_total}
              </Td>
              <Td className="whitespace-nowrap text-muted">{formatTime(r.started_at ?? r.created_at)}</Td>
              <Td className="text-right whitespace-nowrap">{formatDuration(runDurationMs(r))}</Td>
            </Tr>
          ))}
          {q.data && items.length === 0 && <EmptyRow colSpan={8}>No runs</EmptyRow>}
        </tbody>
      </Table>
      <Pagination offset={offset} pageSize={PAGE} total={total} onChange={setOffset} />
    </Section>
  )
}

export function RunsPage() {
  const canControl = useCan('runs:control')
  return (
    <>
      <PageHeader title="Runs" />
      {canControl && <StartRunForm />}
      <RunsTable />
    </>
  )
}
