import { Link } from 'react-router'
import { useCan } from '../../auth/hooks'
import { PageHeader } from '../../components/PageHeader'
import { Badge, Chip, EmptyRow, ErrorText, Section, SectionHeading, Table, Td, Th, THeadRow, Tr, buttonClass } from '../../components/ui'
import { Schedules } from './Schedules'
import { useProfiles } from './ui'

function ProfilesTable() {
  const q = useProfiles()
  const items = q.data?.items ?? []
  return (
    <Section className="flex flex-col gap-4">
      <SectionHeading>Profiles · {q.data?.total ?? 0}</SectionHeading>
      {q.error && <ErrorText>Cannot load profiles: {q.error.message}</ErrorText>}
      <Table minWidth={880} label="Profiles">
        <thead>
          <THeadRow>
            <Th>Name</Th>
            <Th>Ports</Th>
            <Th className="text-right">nmap rate</Th>
            <Th className="text-right">nuclei rate</Th>
            <Th>Nuclei tags</Th>
            <Th className="text-right">Miss threshold</Th>
            <Th className="text-right">Batch</Th>
            <Th>Enabled</Th>
          </THeadRow>
        </thead>
        <tbody>
          {items.map((p) => (
            <Tr key={p.id}>
              <Td className="font-medium">
                <Link to={`/profiles/${p.id}`}>{p.name}</Link>
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
                {p.target_batch_seconds !== undefined ? `${Math.round(p.target_batch_seconds / 60)} min` : '—'}
              </Td>
              <Td>{p.enabled ? <Badge tone="new">On</Badge> : <Badge tone="gone">Off</Badge>}</Td>
            </Tr>
          ))}
          {q.data && items.length === 0 && <EmptyRow colSpan={8}>No profiles</EmptyRow>}
        </tbody>
      </Table>
    </Section>
  )
}

export function ProfilesPage() {
  const canWrite = useCan('profiles:write')
  return (
    <>
      <PageHeader title="Profiles & schedules" crumbs={[{ label: 'Profiles & schedules' }]}>
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
