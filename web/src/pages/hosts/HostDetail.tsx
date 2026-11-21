import { useQuery } from '@tanstack/react-query'
import { useState, type ReactNode } from 'react'
import { Link, useLocation, useParams } from 'react-router'
import { ApiError, api, type Schemas } from '../../api/client'
import { useCan } from '../../auth/hooks'
import { PageHeader } from '../../components/PageHeader'
import {
  Badge,
  Button,
  Chip,
  EmptyRow,
  ErrorText,
  KeyNumber,
  KeyNumbers,
  Section,
  SectionHeading,
  Table,
  Td,
  Th,
  THeadRow,
  Tr,
  buttonClass,
} from '../../components/ui'
import { HostDetailsPanel, ServiceEditCells, detailKey } from './HostEdit'
import { fmtTime, hostFindingsLink, hostStateLabel, stateTone } from './ui'

type Service = Schemas['Service']
type HttpObservation = Schemas['HttpObservation']

export function HostDetailPage() {
  const { ip = '' } = useParams()
  const location = useLocation()
  const from = (location.state as { from?: string } | null)?.from
  const q = useQuery({
    queryKey: detailKey(ip),
    queryFn: () => api.get('/hosts/{ip}', { params: { ip } }),
    retry: (n, err) => !(err instanceof ApiError && err.status < 500) && n < 2,
  })
  const crumbs = [{ label: 'Hosts', to: from ? `/hosts?${from}` : '/hosts' }, { label: ip }]

  if (q.isPending || q.error) {
    const notFound = q.error instanceof ApiError && q.error.status === 404
    return (
      <>
        <PageHeader title={ip} crumbs={crumbs} />
        <Section>
          {q.isPending ? (
            <p className="m-0 text-muted">Loading…</p>
          ) : (
            <ErrorText>{notFound ? `Host ${ip} is not known.` : `Cannot load host: ${q.error?.message}`}</ErrorText>
          )}
        </Section>
      </>
    )
  }
  const h = q.data
  return (
    <>
      <PageHeader
        title={h.ip}
        crumbs={crumbs}
        badges={<Badge tone={stateTone(h.state)}>{hostStateLabel[h.state]}</Badge>}
        meta={
          <>
            {h.hostnames.length > 0 && <div>{h.hostnames.join(' · ')}</div>}
            <div>
              First seen {fmtTime(h.first_seen)} · last seen {fmtTime(h.last_seen)}
            </div>
            <Link to={hostFindingsLink(h.ip)}>Active findings: {h.active_finding_count}</Link>
          </>
        }
      >
        {h.user_tags.map((t) => (
          <Chip key={t} variant="light">
            {t}
          </Chip>
        ))}
        <Link className={buttonClass('secondary', 'sm', true)} to={`/changes/hosts/${h.ip}`}>
          Timeline
        </Link>
      </PageHeader>

      <div className="mx-auto flex max-w-[1440px] flex-wrap items-start gap-12 px-10 pt-12 pb-16">
        <div className="flex min-w-0 flex-[999_1_640px] flex-col gap-12">
          <ServicesTable ip={h.ip} services={h.services} />
          <HttpSection http={h.http} services={h.services} />
        </div>
        <aside className="flex min-w-0 flex-[1_1_340px] flex-col gap-8">
          <HostDetailsPanel h={h} />
          <Timeline items={h.timeline} />
        </aside>
      </div>
    </>
  )
}

/** A service field with an "edited" marker when the user overrode the scan value. */
function Eff({ s, field }: { s: Service; field: 'name' | 'product' | 'version' }) {
  const over = s.overridden.includes(field)
  return (
    <>
      {s[field]}
      {over && (
        <span className="ml-1.5">
          <Badge tone="rose" title={`Scan value: ${s.scan[field] || '—'}`}>
            edited
          </Badge>
        </span>
      )}
    </>
  )
}

function ServicesTable({ ip, services }: { ip: string; services: Service[] }) {
  const canEdit = useCan('hosts:edit')
  const [editing, setEditing] = useState<number | null>(null)
  const cols = canEdit ? 9 : 8
  return (
    <section className="flex flex-col gap-4">
      <SectionHeading>Services</SectionHeading>
      <Table minWidth={760}>
        <thead>
          <THeadRow>
            <Th>Port</Th>
            <Th>State</Th>
            <Th>Service</Th>
            <Th>Product</Th>
            <Th>Version</Th>
            <Th>Banner</Th>
            <Th>First seen</Th>
            <Th>Last seen</Th>
            {canEdit && <Th aria-label="Actions" />}
          </THeadRow>
        </thead>
        <tbody>
          {services.map((s) => (
            <Tr key={s.id} className={s.state === 'gone' ? 'text-muted' : ''}>
              <Td className="font-mono whitespace-nowrap">
                {s.port}/{s.proto}
              </Td>
              <Td>
                <Badge tone={stateTone(s.state)}>{s.state}</Badge>
              </Td>
              {editing === s.id ? (
                <ServiceEditCells s={s} ip={ip} onDone={() => setEditing(null)} />
              ) : (
                <>
                  <Td>
                    <Eff s={s} field="name" />
                  </Td>
                  <Td className="font-mono text-[13px]">
                    <Eff s={s} field="product" />
                  </Td>
                  <Td className="font-mono text-[13px]">
                    <Eff s={s} field="version" />
                  </Td>
                  <Td className="max-w-xs font-mono text-xs break-all">{s.banner}</Td>
                  <Td className="whitespace-nowrap text-muted">{fmtTime(s.first_seen)}</Td>
                  <Td className="whitespace-nowrap text-muted">{fmtTime(s.last_seen)}</Td>
                  {canEdit && (
                    <Td className="text-right">
                      <Button
                        size="sm"
                        variant="ghost"
                        aria-label={`Edit ${s.port}/${s.proto}`}
                        onClick={() => setEditing(s.id)}
                      >
                        Edit
                      </Button>
                    </Td>
                  )}
                </>
              )}
            </Tr>
          ))}
          {services.length === 0 && <EmptyRow colSpan={cols}>No services.</EmptyRow>}
        </tbody>
      </Table>
    </section>
  )
}

function HttpSection({ http, services }: { http: HttpObservation[]; services: Service[] }) {
  const port = new Map(services.map((s) => [s.id, `${s.port}/${s.proto}`]))
  return (
    <section className="flex flex-col gap-6">
      <SectionHeading>HTTP fingerprint</SectionHeading>
      {http.length === 0 ? (
        <p className="m-0 border-t-2 border-black py-4 text-muted">No HTTP observations.</p>
      ) : (
        http.map((o) => (
          <article key={o.id} className="flex flex-col gap-5 border-t-2 border-black pt-4">
            <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1">
              <span className="font-mono font-medium break-all">{o.url}</span>
              <span className="text-[13px] text-muted">{port.get(o.service_id)}</span>
            </div>
            <KeyNumbers>
              <KeyNumber size="sm" label="Status" value={o.status ?? '—'} />
              <KeyNumber size="sm" label="Title" value={o.title || '—'} />
              {o.favicon_hash && (
                <KeyNumber size="sm" label="Favicon (mmh3)" value={<span className="font-mono">{o.favicon_hash}</span>} />
              )}
              <KeyNumber
                size="sm"
                label="Observed"
                value={o.run_id !== null ? `run #${o.run_id}` : fmtTime(o.observed_at)}
                note={o.run_id !== null ? fmtTime(o.observed_at) : undefined}
              />
            </KeyNumbers>
            {o.redirects.length > 0 && (
              <div>
                <SubHeading>Redirect chain</SubHeading>
                <div className="flex flex-wrap items-center gap-2 font-mono text-[13px]">
                  {o.redirects.map((r, i) => (
                    <span key={i} className="flex items-center gap-2">
                      {i > 0 && <span className="text-muted">→</span>}
                      <span className="bg-band px-2 py-1 break-all">{r}</span>
                    </span>
                  ))}
                </div>
              </div>
            )}
            <div className="flex flex-wrap gap-8">
              {Object.keys(o.headers).length > 0 && (
                <div className="min-w-0 flex-[1_1_380px]">
                  <SubHeading rule>Response headers</SubHeading>
                  <table className="w-full border-collapse font-mono text-[13px]">
                    <tbody>
                      {Object.entries(o.headers)
                        .sort(([a], [b]) => a.localeCompare(b))
                        .map(([k, v]) => (
                          <tr key={k} className="border-b border-line">
                            <td className="py-2 pr-2.5 align-top whitespace-nowrap text-muted">{k}</td>
                            <td className="py-2 break-all">{v}</td>
                          </tr>
                        ))}
                    </tbody>
                  </table>
                </div>
              )}
              {(o.cookies.length > 0 || o.tls_cert) && (
                <div className="flex min-w-0 flex-[1_1_320px] flex-col gap-6">
                  {o.cookies.length > 0 && (
                    <div>
                      <SubHeading rule>Cookies</SubHeading>
                      <ul className="m-0 list-none p-0 font-mono text-[13px]">
                        {o.cookies.map((c, i) => (
                          <li key={i} className="border-b border-line py-2 break-all">
                            {c}
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}
                  {o.tls_cert && (
                    <div>
                      <SubHeading rule>TLS certificate</SubHeading>
                      <pre className="m-0 pt-2 font-mono text-[13px] break-all whitespace-pre-wrap">{o.tls_cert}</pre>
                    </div>
                  )}
                </div>
              )}
            </div>
            {o.technologies.length > 0 && (
              <div>
                <SubHeading rule>Technologies</SubHeading>
                <div className="flex flex-wrap gap-2 pt-1">
                  {o.technologies.map((t) => (
                    <span key={t} className="border border-line-strong px-3.5 py-2 font-medium">
                      {t}
                    </span>
                  ))}
                </div>
              </div>
            )}
          </article>
        ))
      )}
    </section>
  )
}

/** 12px uppercase label, optionally with the 2px black rule under it. */
function SubHeading({ children, rule = false }: { children: ReactNode; rule?: boolean }) {
  return (
    <h3
      className={
        'm-0 mb-2 text-xs font-medium tracking-[0.06em] text-muted uppercase ' + (rule ? 'border-b-2 border-black pb-2' : '')
      }
    >
      {children}
    </h3>
  )
}

function Timeline({ items }: { items: Schemas['HostObservation'][] }) {
  const up = items.filter((o) => o.up).length
  // Oldest first in the strip (the API returns newest first).
  const strip = [...items].reverse()
  return (
    <section className="flex flex-col gap-3">
      <SectionHeading size="sm">Presence, last {items.length} runs</SectionHeading>
      {items.length === 0 ? (
        <p className="m-0 text-sm text-muted">No run observations.</p>
      ) : (
        <>
          <div
            aria-hidden
            className="grid gap-[3px]"
            style={{ gridTemplateColumns: `repeat(${strip.length}, minmax(0, 1fr))` }}
          >
            {strip.map((o) => (
              <span
                key={o.run_id}
                title={`run #${o.run_id}: ${o.up ? 'up' : 'down'}`}
                className={'h-7 border ' + (o.up ? 'border-green bg-green' : 'border-on-dark-muted bg-band')}
              />
            ))}
          </div>
          <p className="m-0 text-sm font-light">
            Up in {up} of {items.length} runs
          </p>
          <ul aria-label="Up/down timeline" className="m-0 flex list-none flex-col p-0 text-sm">
            {items.map((o) => (
              <li key={o.run_id} className="flex items-center gap-3 border-b border-line py-1.5">
                <Badge tone={o.up ? 'new' : 'gone'}>{o.up ? 'up' : 'down'}</Badge>
                <span>run #{o.run_id}</span>
                <span className="ml-auto text-muted">{fmtTime(o.observed_at)}</span>
              </li>
            ))}
          </ul>
        </>
      )}
    </section>
  )
}
