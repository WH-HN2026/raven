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
  Th,
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
                <Th>Run</Th>
                <Th>Time</Th>
                <Th>Host</Th>
                {tl.ports.map((p) => (
                  <Th key={p} className="text-center font-mono">
                    {p}
                  </Th>
                ))}
              </THeadRow>
            </thead>
            <tbody>
              {tl.runs.map((r) => (
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
