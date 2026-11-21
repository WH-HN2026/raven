import { keepPreviousData, useQuery } from '@tanstack/react-query'
import { useState, type FormEvent } from 'react'
import { Link, useSearchParams } from 'react-router'
import { api } from '../../api/client'
import { ExportButton } from '../../components/ExportButton'
import { PageHeader } from '../../components/PageHeader'
import {
  Badge,
  Button,
  EmptyRow,
  ErrorText,
  Field,
  FilterBar,
  Pagination,
  Section,
  SectionHeading,
  SeverityLabel,
  Table,
  Td,
  Th,
  THeadRow,
  ToggleGroup,
  Tr,
  inputClass,
} from '../../components/ui'
import {
  PAGE,
  TECH_PAGE,
  apiQuery,
  emptyFilters,
  filtersFromParams,
  fmtTime,
  offsetFromParams,
  paramsFromFilters,
  serviceProtos,
  serviceStates,
  servicesKey,
  sevKey,
  stateTone,
  techApiQuery,
  technologiesKey,
  type ServiceFilters,
  type ServiceSort,
} from './ui'

export function ServicesPage() {
  const [params, setParams] = useSearchParams()
  const filters = filtersFromParams(params)
  const offset = offsetFromParams(params, 'offset')
  const techOffset = offsetFromParams(params, 'tech_offset')

  const sQuery = apiQuery(filters, offset)
  const tQuery = techApiQuery(filters, techOffset)

  const svcs = useQuery({
    queryKey: [...servicesKey, sQuery],
    queryFn: () => api.get('/services', { query: sQuery }),
    placeholderData: keepPreviousData,
  })
  const techs = useQuery({
    queryKey: [...technologiesKey, tQuery],
    queryFn: () => api.get('/technologies', { query: tQuery }),
    placeholderData: keepPreviousData,
  })

  const apply = (f: ServiceFilters, off = 0, tOff = 0) => setParams(paramsFromFilters(f, off, tOff))

  const toggleSort = (col: ServiceSort) => {
    const order = filters.sort === col && filters.order === 'asc' ? 'desc' : 'asc'
    apply({ ...filters, sort: col, order }, 0, techOffset)
  }

  const filterByTech = (technology: string, version = '') => {
    apply({ ...filters, technology, version }, 0, techOffset)
  }

  const svcTotal = svcs.data?.total ?? 0
  const svcItems = svcs.data?.items ?? []
  const techTotal = techs.data?.total ?? 0
  const techItems = techs.data?.items ?? []
  const filtered = Boolean(
    filters.port ||
      filters.proto ||
      filters.product ||
      filters.technology ||
      filters.version ||
      filters.state ||
      filters.q,
  )

  return (
    <>
      <PageHeader
        title="Services & Technologies"
        meta={
          svcs.isSuccess && techs.isSuccess
            ? `${techTotal} technologies · ${svcTotal} ${filtered ? 'matching services' : 'services'}`
            : undefined
        }
      >
        <ExportButton kind="services" onDark />
      </PageHeader>

      <FilterForm key={params.toString()} initial={filters} onApply={(f) => apply(f, 0, 0)} />

      <Section className="flex flex-col gap-5 pt-10 pb-12">
        <SectionHeading aside={<span className="text-muted">{techTotal} detected</span>}>Technologies</SectionHeading>
        {techs.error && <ErrorText>Cannot load technologies: {techs.error.message}</ErrorText>}
        <Table label="Technologies" minWidth={720}>
          <thead>
            <THeadRow>
              <Th>Technology</Th>
              <Th>Version</Th>
              <Th className="text-right">Hosts</Th>
              <Th className="text-right">Services</Th>
              <Th>CVE matches</Th>
            </THeadRow>
          </thead>
          <tbody>
            {techItems.map((t) => {
              const sev = sevKey(t.max_severity)
              const active =
                filters.technology.toLowerCase() === t.technology.toLowerCase() &&
                filters.version.toLowerCase() === t.version.toLowerCase()
              return (
                <Tr key={`${t.technology}\0${t.version}`} className={active ? 'bg-band' : ''}>
                  <Td>
                    <button
                      type="button"
                      className="border-0 bg-transparent p-0 font-medium text-ink underline decoration-red underline-offset-[3px] hover:text-red"
                      onClick={() => filterByTech(t.technology, t.version)}
                    >
                      {t.technology}
                    </button>
                  </Td>
                  <Td className="font-mono text-[13px]">{t.version || <span className="text-muted">—</span>}</Td>
                  <Td className="text-right text-xl leading-none font-light tabular-nums">{t.host_count}</Td>
                  <Td className="text-right text-xl leading-none font-light tabular-nums">{t.service_count}</Td>
                  <Td className="whitespace-nowrap">
                    {t.cve_count > 0 && sev ? (
                      <span className="inline-flex items-center gap-2">
                        <SeverityLabel severity={sev} />
                        <span className="tabular-nums text-muted">
                          {t.cve_count} ({t.cve_match_count})
                        </span>
                      </span>
                    ) : (
                      <span className="text-muted">—</span>
                    )}
                  </Td>
                </Tr>
              )
            })}
            {techs.isSuccess && techItems.length === 0 && (
              <EmptyRow colSpan={5}>{filters.q ? 'No technologies match.' : 'No technologies detected yet.'}</EmptyRow>
            )}
          </tbody>
        </Table>
        <Pagination
          offset={techOffset}
          pageSize={TECH_PAGE}
          total={techTotal}
          onChange={(o) => apply(filters, offset, o)}
        />
      </Section>

      <Section band className="flex flex-col gap-5 pt-10 pb-16">
        <SectionHeading aside={<span className="text-muted">{svcTotal} matching</span>}>Services</SectionHeading>
        {svcs.error && <ErrorText>Cannot load services: {svcs.error.message}</ErrorText>}
        <Table label="Services" minWidth={1080}>
          <thead>
            <THeadRow>
              <SortTh col="ip" cur={filters.sort} order={filters.order} onSort={toggleSort}>
                Host
              </SortTh>
              <SortTh col="port" cur={filters.sort} order={filters.order} onSort={toggleSort}>
                Port
              </SortTh>
              <SortTh col="state" cur={filters.sort} order={filters.order} onSort={toggleSort}>
                State
              </SortTh>
              <Th>Service</Th>
              <SortTh col="product" cur={filters.sort} order={filters.order} onSort={toggleSort}>
                Product
              </SortTh>
              <SortTh col="version" cur={filters.sort} order={filters.order} onSort={toggleSort}>
                Version
              </SortTh>
              <Th>Technologies</Th>
              <Th>CVEs</Th>
              <SortTh col="last_seen" cur={filters.sort} order={filters.order} onSort={toggleSort}>
                Last seen
              </SortTh>
            </THeadRow>
          </thead>
          <tbody>
            {svcItems.map((s) => {
              const sev = sevKey(s.cve_severity)
              return (
                <Tr key={s.id} className={s.state === 'gone' ? 'text-muted' : ''}>
                  <Td className="whitespace-nowrap">
                    <Link className="font-mono font-medium" to={`/hosts/${encodeURIComponent(s.ip)}`}>
                      {s.ip}
                    </Link>
                    {s.hostnames.length > 0 && (
                      <div className="text-[13px] text-muted">{s.hostnames.join(', ')}</div>
                    )}
                  </Td>
                  <Td className="font-mono whitespace-nowrap">
                    {s.port}/{s.proto}
                  </Td>
                  <Td>
                    <Badge tone={stateTone(s.state)}>{s.state}</Badge>
                  </Td>
                  <Td>
                    {s.name}
                    {s.overridden.includes('name') && (
                      <span className="ml-1.5">
                        <Badge tone="rose">edited</Badge>
                      </span>
                    )}
                  </Td>
                  <Td className="font-mono text-[13px]">
                    {s.product}
                    {s.overridden.includes('product') && (
                      <span className="ml-1.5">
                        <Badge tone="rose">edited</Badge>
                      </span>
                    )}
                  </Td>
                  <Td className="font-mono text-[13px]">
                    {s.version}
                    {s.overridden.includes('version') && (
                      <span className="ml-1.5">
                        <Badge tone="rose">edited</Badge>
                      </span>
                    )}
                  </Td>
                  <Td>
                    <div className="flex flex-wrap gap-1">
                      {s.technologies.map((tech) => (
                        <button
                          key={tech}
                          type="button"
                          onClick={() => filterByTech(tech)}
                          className="border border-line-strong bg-white px-2 py-px text-[13px] whitespace-nowrap text-ink hover:bg-black hover:text-white"
                        >
                          {tech}
                        </button>
                      ))}
                    </div>
                  </Td>
                  <Td className="whitespace-nowrap">
                    {s.cve_count > 0 && sev ? (
                      <span className="inline-flex items-center gap-2">
                        <SeverityLabel severity={sev} />
                        <span className="tabular-nums text-muted">{s.cve_count}</span>
                      </span>
                    ) : (
                      <span className="text-muted">—</span>
                    )}
                  </Td>
                  <Td className="whitespace-nowrap text-muted">{fmtTime(s.last_seen)}</Td>
                </Tr>
              )
            })}
            {svcs.isSuccess && svcItems.length === 0 && (
              <EmptyRow colSpan={9}>{filtered ? 'No services match these filters.' : 'No services yet.'}</EmptyRow>
            )}
          </tbody>
        </Table>
        <Pagination offset={offset} pageSize={PAGE} total={svcTotal} onChange={(o) => apply(filters, o, techOffset)} />
      </Section>
    </>
  )
}

function SortTh({
  col,
  cur,
  order,
  onSort,
  children,
}: {
  col: ServiceSort
  cur: ServiceSort
  order: 'asc' | 'desc'
  onSort: (c: ServiceSort) => void
  children: string
}) {
  const active = cur === col
  const arrow = active ? (order === 'asc' ? ' ↑' : ' ↓') : ''
  return (
    <Th aria-sort={active ? (order === 'asc' ? 'ascending' : 'descending') : 'none'}>
      <button
        type="button"
        onClick={() => onSort(col)}
        className="border-0 bg-transparent p-0 text-xs font-medium tracking-[0.06em] text-muted uppercase hover:text-ink"
      >
        {children}
        {arrow}
      </button>
    </Th>
  )
}

const stateOptions = [
  { value: '', label: 'Any' },
  ...serviceStates.map((s) => ({ value: s as string, label: s.charAt(0).toUpperCase() + s.slice(1) })),
]

function FilterForm({ initial, onApply }: { initial: ServiceFilters; onApply: (f: ServiceFilters) => void }) {
  const [f, setF] = useState(initial)
  const set = (k: 'port' | 'proto' | 'product' | 'technology' | 'version' | 'q') => (e: { target: { value: string } }) =>
    setF({ ...f, [k]: e.target.value })
  const submit = (e: FormEvent) => {
    e.preventDefault()
    onApply(f)
  }
  const portTrim = f.port.trim()
  const portInvalid = portTrim !== '' && (!/^\d{1,5}$/.test(portTrim) || Number(portTrim) > 65535)
  return (
    <FilterBar onSubmit={submit}>
      <Field label="Search" className="flex-[2_1_220px]">
        <input className={inputClass} value={f.q} onChange={set('q')} placeholder="IP, host, product, tech" />
      </Field>
      <Field label="Port" className="flex-[1_1_100px]">
        <input
          className={inputClass + ' font-mono'}
          value={f.port}
          onChange={set('port')}
          inputMode="numeric"
          placeholder="443"
          aria-invalid={portInvalid}
        />
      </Field>
      <Field label="Protocol" className="flex-[1_1_110px]">
        <select className={inputClass} value={f.proto} onChange={set('proto')}>
          <option value="">Any</option>
          {serviceProtos.map((p) => (
            <option key={p} value={p}>
              {p.toUpperCase()}
            </option>
          ))}
        </select>
      </Field>
      <Field label="Product" className="flex-[1_1_140px]">
        <input className={inputClass} value={f.product} onChange={set('product')} placeholder="nginx" />
      </Field>
      <Field label="Technology" className="flex-[1_1_150px]">
        <input className={inputClass} value={f.technology} onChange={set('technology')} placeholder="WordPress" />
      </Field>
      <Field label="Version" className="flex-[1_1_120px]">
        <input className={inputClass + ' font-mono'} value={f.version} onChange={set('version')} placeholder="1.25" />
      </Field>
      <div className="flex flex-col gap-1.5">
        <span className="text-[13px] font-medium">State</span>
        <ToggleGroup
          label="State"
          options={stateOptions}
          value={f.state}
          onChange={(state) => {
            const next = { ...f, state }
            setF(next)
            onApply(next)
          }}
        />
      </div>
      <div className="flex">
        <Button type="submit" variant="primary" disabled={portInvalid}>
          Apply
        </Button>
        <Button onClick={() => onApply(emptyFilters)}>Reset</Button>
      </div>
      {portInvalid && <span className="w-full text-[13px] font-medium text-red">Port must be a number 0–65535.</span>}
    </FilterBar>
  )
}
