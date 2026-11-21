import { SortTh, sortRows, useTableSort } from '../../components/SortTh'
import { useQuery } from '@tanstack/react-query'
import { Link, useParams } from 'react-router'
import { ApiError, api } from '../../api/client'
import { PageHeader } from '../../components/PageHeader'
import {
  Badge,
  EmptyRow,
  ErrorText,
  Section,
  SectionHeading,
  Table,
  Td,
  THeadRow,
  Tr,
  buttonClass,
} from '../../components/ui'
import { changesKey, runTime } from './ui'

const RUNS = 20

/** Per-host timeline: host and port up/down in the last runs that scanned the IP. */
export function HostTimelinePage() {
  const { ip = '' } = useParams()
  const q = useQuery({
    queryKey: [...changesKey, 'timeline', ip],
    queryFn: () => api.get('/changes/hosts/{ip}', { params: { ip }, query: { runs: RUNS } }),
    retry: (n, err) => !(err instanceof ApiError && err.status < 500) && n < 2,
  })
  const tl = q.data
  const ports = tl?.ports ?? []
  const sort = useTableSort(['run', 'time', 'host', ...ports.map((p) => `port_${p}` as const)], {
    initial: 'run', direction: 'desc',
  })
  const rows = sortRows(tl?.runs ?? [], sort, {
    run: (r) => r.run.id,
    time: (r) => {
      const time = r.run.finished_at ?? r.run.started_at
      return time ? Date.parse(time) : null
    },
    host: (r) => r.up,
    ...Object.fromEntries(ports.map((p) => [`port_${p}`, (r: NonNullable<typeof tl>['runs'][number]) => r.open_ports.includes(p)])),
  })
  return (
    <>
      <PageHeader title={ip} mono crumbs={[{ label: 'Changes', to: '/changes' }, { label: ip }]} meta="Timeline">
        <Link className={buttonClass('secondary', 'sm', true)} to={`/hosts/${ip}`}>
          Host detail
        </Link>
      </PageHeader>
      <Section className="flex flex-col gap-5 pb-16">
        <SectionHeading>Last {tl ? tl.runs.length : RUNS} runs</SectionHeading>
        {q.error && <ErrorText>Cannot load timeline: {q.error.message}</ErrorText>}
        {q.isPending && <p className="m-0 text-muted">Loading…</p>}
        {tl && (
          <Table minWidth={560} label="Timeline">
            <thead>
              <THeadRow>
                <SortTh sort={sort} col="run">Run</SortTh>
                <SortTh sort={sort} col="time">Time</SortTh>
                <SortTh sort={sort} col="host">Host</SortTh>
                {tl.ports.map((p) => (
                  <SortTh key={p} sort={sort} col={`port_${p}`} className="text-center font-mono">
                    {p}
                  </SortTh>
                ))}
              </THeadRow>
            </thead>
            <tbody>
              {rows.map((r) => (
                <Tr key={r.run.id}>
                  <Td className="text-xl leading-none font-light">
                    <Link to={`/runs/${r.run.id}`}>#{r.run.id}</Link>
                  </Td>
                  <Td className="whitespace-nowrap text-muted">{runTime(r.run)}</Td>
                  <Td>
                    <Badge tone={r.up ? 'new' : 'gone'}>{r.up ? 'up' : 'down'}</Badge>
                  </Td>
                  {tl.ports.map((p) => {
                    const open = r.open_ports.includes(p)
                    return (
                      <Td key={p} className="text-center">
                        <span
                          role="img"
                          aria-label={`${p} ${open ? 'open' : 'closed'}`}
                          title={`${p} ${open ? 'open' : 'closed'}`}
                          className={'inline-block size-3.5 border ' + (open ? 'border-green bg-green' : 'border-line bg-band')}
                        />
                      </Td>
                    )
                  })}
                </Tr>
              ))}
              {tl.runs.length === 0 && <EmptyRow colSpan={3 + tl.ports.length}>No runs scanned this host</EmptyRow>}
            </tbody>
          </Table>
        )}
      </Section>
    </>
  )
}
