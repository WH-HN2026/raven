import { keepPreviousData, useQuery } from '@tanstack/react-query'
import { Link, useSearchParams } from 'react-router'
import { api } from '../../api/client'
import { ExportButton } from '../../components/ExportButton'
import { PageHeader } from '../../components/PageHeader'
import { SortTh, useTableSort } from '../../components/SortTh'
import { listParams, useInstantFilters, validPortFilter } from '../../components/instantFilters'
import {
  Badge,
  Button,
  Chip,
  EmptyRow,
  ErrorText,
  Field,
  FilterBar,
  Pagination,
  Section,
  Table,
  Td,
  THeadRow,
  ToggleGroup,
  Tr,
  inputClass,
} from '../../components/ui'
import {
  PAGE,
  apiQuery,
  filtersFromParams,
  fmtTime,
  hostFindingsLink,
  hostStateLabel,
  hostStates,
  hostsKey,
  offsetFromParams,
  paramsFromFilters,
  portsSummary,
  stateTone,
  type HostFilters,
} from './ui'

export function HostsPage() {
  const [params, setParams] = useSearchParams()
  const filters = filtersFromParams(params)
  const offset = offsetFromParams(params)
  const sort = useTableSort(['ip', 'hostnames', 'state', 'open_ports', 'active_finding_count', 'technologies', 'tags', 'first_seen', 'last_seen', 'misses'], {
    initial: 'ip',
    offset: 'offset',
  })
  const query = { ...apiQuery(filters, offset), ...sort.query }
  const q = useQuery({
    queryKey: [...hostsKey, query],
    queryFn: () => api.get('/hosts', { query }),
    placeholderData: keepPreviousData,
  })
  const apply = (f: HostFilters, off = 0, replace = false) =>
    setParams((current) => listParams(current, paramsFromFilters(f, off)), { replace })

  const total = q.data?.total ?? 0
  const items = q.data?.items ?? []
  const filtered = Object.values(filters).some((v) => v !== '')

  return (
    <>
      <PageHeader
        title="Hosts"
        meta={q.isSuccess ? `${total} ${filtered ? 'matching' : 'total'}` : undefined}
      >
        <ExportButton kind="hosts" onDark />
      </PageHeader>
      <FilterForm initial={filters} onChange={(f, replace) => apply(f, 0, replace)} />
      <Section className="pt-10 pb-16">
        {q.error && <ErrorText>Cannot load hosts: {q.error.message}</ErrorText>}
        <Table minWidth={1040}>
          <thead>
            <THeadRow>
              <SortTh sort={sort} col="ip">IP</SortTh>
              <SortTh sort={sort} col="hostnames">Hostnames</SortTh>
              <SortTh sort={sort} col="state">State</SortTh>
              <SortTh sort={sort} col="open_ports">Open ports</SortTh>
              <SortTh sort={sort} col="active_finding_count" className="text-right">Findings</SortTh>
              <SortTh sort={sort} col="technologies">Technologies</SortTh>
              <SortTh sort={sort} col="tags">Tags</SortTh>
              <SortTh sort={sort} col="first_seen">First seen</SortTh>
              <SortTh sort={sort} col="last_seen">Last seen</SortTh>
              <SortTh sort={sort} col="misses" className="text-right">Misses</SortTh>
            </THeadRow>
          </thead>
          <tbody>
            {items.map((h) => (
              <Tr key={h.ip}>
                <Td className="whitespace-nowrap">
                  <Link
                    className="font-mono font-medium"
                    to={`/hosts/${encodeURIComponent(h.ip)}`}
                    state={{ from: params.toString() }}
                  >
                    {h.ip}
                  </Link>
                </Td>
                <Td>
                  {h.hostnames.join(', ')}
                  {(h.owner || h.criticality) && (
                    <div className="text-[13px] text-muted">
                      {h.owner}
                      {h.criticality && ` (${h.criticality})`}
                    </div>
                  )}
                </Td>
                <Td>
                  <Badge tone={stateTone(h.state)}>{hostStateLabel[h.state]}</Badge>
                </Td>
                <Td className="font-mono text-[13px]" title={h.open_ports.join(', ')}>
                  {portsSummary(h.open_ports)}
                  {h.open_service_count > h.open_ports.length && (
                    <span className="font-sans text-muted"> ({h.open_service_count} services)</span>
                  )}
                </Td>
                <Td className="text-right tabular-nums">
                  <Link
                    to={hostFindingsLink(h.ip)}
                    aria-label={`${h.active_finding_count} active findings for ${h.ip}`}
                  >
                    {h.active_finding_count}
                  </Link>
                </Td>
                <Td>
                  <div className="flex flex-wrap gap-1">
                    {h.technologies.map((t) => (
                      <Chip key={t}>{t}</Chip>
                    ))}
                  </div>
                </Td>
                <Td>
                  <div className="flex flex-wrap gap-1">
                    {h.user_tags.map((t) => (
                      <Chip key={t} variant="filled">
                        {t}
                      </Chip>
                    ))}
                  </div>
                </Td>
                <Td className="whitespace-nowrap text-muted">{fmtTime(h.first_seen)}</Td>
                <Td className="whitespace-nowrap text-muted">{fmtTime(h.last_seen)}</Td>
                <Td className="text-right text-xl leading-none font-light tabular-nums">{h.miss_count}</Td>
              </Tr>
            ))}
            {q.isSuccess && items.length === 0 && (
              <EmptyRow colSpan={10}>{filtered ? 'No hosts match these filters.' : 'No hosts yet.'}</EmptyRow>
            )}
          </tbody>
        </Table>
        <Pagination offset={offset} pageSize={PAGE} total={total} onChange={(o) => apply(filters, o)} />
      </Section>
    </>
  )
}

const stateOptions = [
  { value: '', label: 'Any' },
  ...hostStates.map((s) => ({ value: s as string, label: hostStateLabel[s] })),
]

function FilterForm({ initial, onChange }: { initial: HostFilters; onChange: (f: HostFilters, replace: boolean) => void }) {
  const { draft: f, update } = useInstantFilters(initial, onChange, (v) => paramsFromFilters(v).toString(), (next, applied) => ({
    ...next,
    port: validPortFilter(next.port) ? next.port : applied.port,
  }))
  const set = (k: keyof HostFilters) => (e: { target: { value: string } }) => update({ ...f, [k]: e.target.value }, true)
  const portInvalid = !validPortFilter(f.port)
  return (
    <FilterBar>
      <Field label="IP, CIDR or hostname" className="flex-[2_1_260px]">
        <input className={inputClass + ' font-mono'} value={f.q} onChange={set('q')} placeholder="10.0.0.0/24" />
      </Field>
      <Field label="Open port" className="flex-[1_1_110px]">
        <input
          className={inputClass}
          value={f.port}
          onChange={set('port')}
          inputMode="numeric"
          placeholder="443"
          aria-invalid={portInvalid}
        />
      </Field>
      <Field label="Technology" className="flex-[1_1_150px]">
        <input className={inputClass} value={f.tech} onChange={set('tech')} placeholder="WordPress" />
      </Field>
      <Field label="Tag" className="flex-[1_1_130px]">
        <input className={inputClass} value={f.tag} onChange={set('tag')} />
      </Field>
      <div className="flex flex-col gap-1.5">
        <span className="text-[13px] font-medium">State</span>
        <ToggleGroup
          label="State"
          options={stateOptions}
          value={f.state}
          onChange={(state) => update({ ...f, state })}
        />
      </div>
      <Button onClick={() => update({ state: '', port: '', tech: '', tag: '', q: '' })}>Reset</Button>
      {portInvalid && <span className="w-full text-[13px] font-medium text-red">Port must be a number 0–65535.</span>}
    </FilterBar>
  )
}
