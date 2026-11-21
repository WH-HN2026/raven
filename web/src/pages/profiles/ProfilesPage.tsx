import { SortTh, useTableSort } from '../../components/SortTh'
import { Link } from 'react-router'
import { useCan } from '../../auth/hooks'
import { PageHeader } from '../../components/PageHeader'
import { Badge, Chip, EmptyRow, ErrorText, Section, SectionHeading, Table, Td, Th, THeadRow, Tr, buttonClass } from '../../components/ui'
import { StageChips } from '../../components/StageChips'
import { Schedules } from './Schedules'
import { batchMinutes, useProfiles } from './ui'

function ProfilesTable() {
  const sort = useTableSort(['name', 'ports', 'nmap_rate', 'nuclei_rate', 'nuclei_tags', 'miss_threshold', 'batch', 'enabled'], { initial: 'name' })
  const q = useProfiles(sort.query)
  const items = q.data?.items ?? []
  return (
    <Section className="flex flex-col gap-4">
      <SectionHeading>Profiles · {q.data?.total ?? 0}</SectionHeading>
      {q.error && <ErrorText>Cannot load profiles: {q.error.message}</ErrorText>}
      <Table minWidth={880} label="Profiles">
        <thead>
          <THeadRow>
            <SortTh sort={sort} col="name">Name</SortTh>
            <Th>Workflow</Th>
            <SortTh sort={sort} col="ports">Ports</SortTh>
            <SortTh sort={sort} col="nmap_rate" className="text-right">nmap rate</SortTh>
            <SortTh sort={sort} col="nuclei_rate" className="text-right">nuclei rate</SortTh>
            <SortTh sort={sort} col="nuclei_tags">Nuclei tags</SortTh>
            <SortTh sort={sort} col="miss_threshold" className="text-right">Miss threshold</SortTh>
            <SortTh sort={sort} col="batch" className="text-right">Batch duration</SortTh>
            <SortTh sort={sort} col="enabled">Enabled</SortTh>
          </THeadRow>
        </thead>
        <tbody>
          {items.map((p) => (
            <Tr key={p.id}>
              <Td className="font-medium">
                <Link to={`/profiles/${p.id}`}>{p.name}</Link>
              </Td>
              <Td>
                <StageChips stages={p.stages} />
              </Td>
              <Td className="max-w-[280px] font-mono text-[13px] break-all">{p.ports}</Td>
              <Td className="text-right tabular-nums">{p.nmap_max_rate} pps</Td>
              <Td className="text-right tabular-nums">{p.nuclei_rate ?? '—'} req/s</Td>
              <Td>
                <div className="flex flex-wrap gap-1">
                  {(p.nuclei_tags ?? []).map((t) => (
                    <Chip key={t}>{t}</Chip>
                  ))}
                  {(p.nuclei_tags ?? []).length === 0 && <span className="text-muted">—</span>}
                </div>
              </Td>
              <Td className="text-right tabular-nums">{p.miss_threshold ?? '—'}</Td>
              <Td className="text-right whitespace-nowrap tabular-nums">
                {p.target_batch_seconds !== undefined ? `${batchMinutes(p.target_batch_seconds)} min` : '—'}
              </Td>
              <Td>{p.enabled ? <Badge tone="new">On</Badge> : <Badge tone="gone">Off</Badge>}</Td>
            </Tr>
          ))}
          {q.data && items.length === 0 && <EmptyRow colSpan={9}>No profiles</EmptyRow>}
        </tbody>
      </Table>
    </Section>
  )
}

export function ProfilesPage() {
  const canWrite = useCan('profiles:write')
  return (
    <>
      <PageHeader title="Profiles & schedules">
        {canWrite && (
          <Link to="/profiles/new" className={buttonClass('primary', 'lg', true)}>
            New profile
          </Link>
        )}
      </PageHeader>
      <ProfilesTable />
      <Schedules />
    </>
  )
}
