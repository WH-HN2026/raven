import { keepPreviousData, useQueries, useQuery } from '@tanstack/react-query'
import { Fragment, useState, useSyncExternalStore, type FormEvent } from 'react'
import { Link, useSearchParams } from 'react-router'
import { api } from '../../api/client'
import { ExportButton } from '../../components/ExportButton'
import { PageHeader } from '../../components/PageHeader'
import {
  Badge,
  Button,
  EmptyRow,
  EmptyState,
  ErrorText,
  Field,
  FilterBar,
  Pagination,
  Section,
  SeverityLabel,
  Table,
  Td,
  Th,
  THeadRow,
  Tr,
  inputClass,
} from '../../components/ui'
import { TriagePanel } from './TriagePanel'
import {
  PAGE,
  apiQuery,
  emptyFilters,
  filtersFromParams,
  findingsKey,
  fmtDate,
  offsetFromParams,
  paramsFromFilters,
  scanners,
  selectedFromParams,
  severities,
  sevKey,
  statusFilterOf,
  statusFilterOptions,
  statusLabel,
  statusOf,
  statusTone,
  withStatusFilter,
  type FindingFilters,
  type Severity,
  type StatusFilterValue,
} from './ui'

const sevEdge: Record<Severity, string> = {
  Critical: 'border-sev-critical',
  High: 'border-sev-high',
  Medium: 'border-sev-medium',
  Low: 'border-sev-low',
  Info: 'border-sev-info',
}

// The existing column bases (640px + 380px), gap (40px), and side padding (80px).
const detailMedia = '(min-width: 1140px)'

function subscribeToDetailMedia(onChange: () => void) {
  const media = window.matchMedia(detailMedia)
  media.addEventListener('change', onChange)
  return () => media.removeEventListener('change', onChange)
}

const detailFitsBesideList = () => window.matchMedia(detailMedia).matches

export function FindingsPage() {
  const wide = useSyncExternalStore(subscribeToDetailMedia, detailFitsBesideList)
  const [params, setParams] = useSearchParams()
  const filters = filtersFromParams(params)
  const offset = offsetFromParams(params)
  const selected = selectedFromParams(params)
  const query = apiQuery(filters, offset)
  const q = useQuery({
    queryKey: [...findingsKey, 'list', query],
    queryFn: () => api.get('/findings', { query }),
    placeholderData: keepPreviousData,
  })
  // Per-severity totals under the other filters (limit 1: only `total` is used).
  const counts = useQueries({
    queries: severities.map((s) => {
      const cq = apiQuery({ ...filters, severity: [s] }, 0, 1)
      return {
        queryKey: [...findingsKey, 'count', cq],
        queryFn: () => api.get('/findings', { query: cq }),
        placeholderData: keepPreviousData,
      }
    }),
  })
  const apply = (f: FindingFilters, off = 0) => setParams(paramsFromFilters(f, off))
  const toggleSeverity = (s: Severity) =>
    apply({
      ...filters,
      severity: filters.severity.includes(s) ? filters.severity.filter((x) => x !== s) : [...filters.severity, s],
    })

  const total = q.data?.total ?? 0
  const items = q.data?.items ?? []
  const current = items.find((f) => f.id === selected)
  const filtered = JSON.stringify(filters) !== JSON.stringify(emptyFilters)
  const selectHref = (id: number) => '?' + paramsFromFilters(filters, offset, id).toString()
  const detailId = current ? `finding-detail-${current.id}` : undefined
  const detail = (
    <aside
      id={detailId}
      aria-label="Selected finding"
      className={
        'flex flex-col gap-5 border-t-4 border-red bg-band p-6 ' +
        (wide ? 'sticky top-4 max-h-[calc(100dvh-2rem)] min-w-0 flex-[1_1_380px] overflow-y-auto' : 'sticky left-0 w-[100cqw]')
      }
    >
      {current ? <TriagePanel key={current.id} finding={current} /> : <EmptyState>No finding selected.</EmptyState>}
    </aside>
  )

  return (
    <>
      <PageHeader
        title="Findings"
        crumbs={[{ label: 'Findings' }]}
        meta={q.isSuccess ? `${total} ${filtered ? 'matching' : 'total'}` : undefined}
      >
        <ExportButton kind="findings" onDark />
      </PageHeader>
      <Section label="Findings by severity" className="pt-10 pb-8">
        <div className="grid gap-6" style={{ gridTemplateColumns: 'repeat(auto-fit, minmax(170px, 1fr))' }}>
          {severities.map((s, i) => {
            const on = filters.severity.includes(s)
            return (
              <button
                key={s}
                type="button"
                aria-pressed={on}
                onClick={() => toggleSeverity(s)}
                className={
                  'border-0 border-l-4 py-2.5 pr-3.5 pl-4 text-left text-ink ' +
                  sevEdge[s] +
                  (on ? ' bg-band' : ' bg-white hover:bg-band')
                }
              >
                <span className="block text-sm text-muted">{s}</span>
                <span className="block text-[44px] leading-[1.1] font-light tabular-nums">
                  {counts[i]?.data?.total ?? '–'}
                </span>
              </button>
            )
          })}
        </div>
      </Section>
      {/* key: re-initialise the inputs when the URL filters change (back/forward, reset). */}
      <FilterForm key={paramsFromFilters(filters).toString()} initial={filters} onApply={apply} />
      <div className="mx-auto flex max-w-[1440px] items-start gap-10 px-10 pt-8 pb-16">
        <section aria-label="Findings" className="flex min-w-0 flex-[999_1_640px] flex-col gap-3.5 [container-type:inline-size]">
          {q.error && <ErrorText>Cannot load findings: {q.error.message}</ErrorText>}
          <Table minWidth={900}>
            <thead>
              <THeadRow>
                <Th>Severity ↓</Th>
                <Th>Finding</Th>
                <Th>Host</Th>
                <Th>Source</Th>
                <Th>Status</Th>
                <Th>Date</Th>
              </THeadRow>
            </thead>
            <tbody>
              {items.map((f) => {
                const st = statusOf(f)
                const sel = f.id === selected
                return (
                  <Fragment key={f.id}>
                    <Tr className={sel ? 'bg-band' : ''}>
                      <Td className={'whitespace-nowrap ' + (sel ? 'border-l-4 border-l-red pl-2!' : '')}>
                        <SeverityLabel severity={sevKey(f.severity)} />
                      </Td>
                      <Td>
                        <Link
                          to={selectHref(f.id)}
                          aria-current={sel ? 'true' : undefined}
                          aria-expanded={sel}
                          aria-controls={sel ? detailId : undefined}
                          preventScrollReset
                          className="font-medium"
                        >
                          {f.title}
                        </Link>
                      </Td>
                      <Td className="whitespace-nowrap">
                        {f.ip && (
                          <Link className="font-mono" to={`/hosts/${encodeURIComponent(f.ip)}`}>
                            {f.ip}
                          </Link>
                        )}
                      </Td>
                      <Td className="text-[13px] text-muted">{f.scanner}</Td>
                      <Td>
                        <Badge tone={statusTone[st]}>{statusLabel[st]}</Badge>
                      </Td>
                      <Td className="whitespace-nowrap text-muted">{fmtDate(f.date)}</Td>
                    </Tr>
                    {!wide && sel && (
                      <Tr>
                        <td colSpan={6} className="p-0">
                          {detail}
                        </td>
                      </Tr>
                    )}
                  </Fragment>
                )
              })}
              {q.isSuccess && items.length === 0 && (
                <EmptyRow colSpan={6}>{filtered ? 'No findings match these filters.' : 'No findings yet.'}</EmptyRow>
              )}
            </tbody>
          </Table>
          <Pagination offset={offset} pageSize={PAGE} total={total} onChange={(o) => apply(filters, o)} />
        </section>
        {wide && detail}
      </div>
    </>
  )
}

function FilterForm({ initial, onApply }: { initial: FindingFilters; onApply: (f: FindingFilters) => void }) {
  const [f, setF] = useState(initial)
  const set = (k: 'q' | 'ip' | 'asset' | 'scanner') => (e: { target: { value: string } }) =>
    setF({ ...f, [k]: e.target.value })
  const submit = (e: FormEvent) => {
    e.preventDefault()
    onApply(f)
  }
  const ipInvalid = f.ip.trim() !== '' && !/^[0-9a-fA-F:.]+(\/\d{1,3})?$/.test(f.ip.trim())
  const scannerOptions = f.scanner && !scanners.includes(f.scanner) ? [...scanners, f.scanner] : scanners
  return (
    <FilterBar onSubmit={submit}>
      <Field label="Title" className="flex-[3_1_220px]">
        <input type="search" className={inputClass} value={f.q} onChange={set('q')} placeholder="admin panel" />
      </Field>
      <Field label="IP or CIDR" className="flex-[2_1_180px]">
        <input
          className={inputClass + ' font-mono'}
          value={f.ip}
          onChange={set('ip')}
          placeholder="172.30.0.0/24"
          aria-invalid={ipInvalid}
        />
      </Field>
      <Field label="Asset" className="flex-[1_1_150px]">
        <input className={inputClass} value={f.asset} onChange={set('asset')} placeholder="ID or name" />
      </Field>
      <Field label="Status" className="flex-[1_1_160px]">
        <select
          className={inputClass}
          value={statusFilterOf(f)}
          onChange={(e) => setF(withStatusFilter(f, e.target.value as StatusFilterValue))}
        >
          {statusFilterOptions.map((o) => (
            <option key={o.value} value={o.value}>
              {o.label}
            </option>
          ))}
        </select>
      </Field>
      <Field label="Source" className="flex-[1_1_140px]">
        <select className={inputClass} value={f.scanner} onChange={set('scanner')}>
          <option value="">Any</option>
          {scannerOptions.map((s) => (
            <option key={s} value={s}>
              {s}
            </option>
          ))}
        </select>
      </Field>
      <div className="flex">
        <Button type="submit" variant="primary" disabled={ipInvalid}>
          Apply
        </Button>
        <Button onClick={() => onApply(emptyFilters)}>Reset</Button>
      </div>
      {ipInvalid && <span className="w-full text-[13px] font-medium text-red">IP must be an address or CIDR.</span>}
    </FilterBar>
  )
}
