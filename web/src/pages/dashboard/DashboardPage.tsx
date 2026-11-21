import { SortTh, sortRows, useTableSort } from '../../components/SortTh'
import { useQuery } from '@tanstack/react-query'
import type { ReactNode } from 'react'
import { Link } from 'react-router'
import { api } from '../../api/client'
import { useCan } from '../../auth/hooks'
import { PageHeader } from '../../components/PageHeader'
import {
  Badge,
  buttonClass,
  EmptyRow,
  EmptyState,
  ErrorText,
  KeyNumber,
  KeyNumbers,
  Section,
  SectionHeading,
  SeverityLabel,
  type Severity as SeverityKey,
  Table,
  Td,
  THeadRow,
  Tr,
} from '../../components/ui'
import { diffRows, type ChangeKind } from '../changes/ui'
import { formatDuration, StatusBadge } from '../runs/ui'
import {
  changeCounts,
  changesLink,
  changeText,
  dashboardKey,
  findingsLink,
  formatCount,
  hostsLink,
  pct,
  severityBars,
  unstablePattern,
  type Dashboard,
  type DashboardRun,
} from './ui'

export function DashboardPage() {
  const q = useQuery({ queryKey: dashboardKey, queryFn: () => api.get('/dashboard') })
  const canRun = useCan('runs:control')
  // Ignore a body that is not a dashboard (e.g. a stubbed fetch).
  const d = q.data && 'findings' in q.data ? q.data : undefined
  const last = d?.runs.find((r) => r.id === d.latest_run?.id)

  return (
    <>
      <PageHeader title="Dashboard" meta={last ? <LastRun run={last} /> : undefined}>
        {canRun && (
          <Link to="/runs" className={buttonClass('primary', 'lg')}>
            Start scan
          </Link>
        )}
      </PageHeader>
      {q.error ? (
        <Section>
          <ErrorText>Cannot load dashboard: {q.error.message}</ErrorText>
        </Section>
      ) : !d ? (
        <Section>
          <p className="m-0 text-muted">Loading…</p>
        </Section>
      ) : (
        <Body d={d} />
      )}
    </>
  )
}

function LastRun({ run }: { run: DashboardRun }) {
  const at = run.finished_at ?? run.started_at
  return (
    <>
      Last run <Link to={`/runs/${run.id}`}>#{run.id} · {run.profile}</Link>
      {at && <> · {new Date(at).toLocaleString()}</>} · {formatDuration(run.duration_ms)} ·{' '}
      {formatCount(run.hosts_up)} of {formatCount(run.hosts_total)} hosts up
    </>
  )
}

function Body({ d }: { d: Dashboard }) {
  const c = d.changes
  const counts = c ? changeCounts(c.summary) : null
  const since = c ? `since run #${c.from.id}` : undefined
  return (
    <>
      <Section label="Key numbers" className="pb-2">
        <KeyNumbers min={180}>
          <KeyNumber
            label="Active hosts"
            value={formatCount(d.hosts.active)}
            edge="green"
            note={c ? `+${c.summary.hosts_new} / −${c.summary.hosts_gone} ${since}` : undefined}
          />
          <KeyNumber
            label="Open services"
            value={formatCount(d.hosts.services_open)}
            edge="green"
            note={c ? `+${c.summary.services_new} / −${c.summary.services_gone} ${since}` : undefined}
          />
          <KeyNumber
            label="Active findings"
            value={
              <Link to={findingsLink()} aria-label={`${formatCount(d.findings.total)} active findings`}>
                {formatCount(d.findings.total)}
              </Link>
            }
            edge="red"
          />
          <KeyNumber
            label="New devices"
            value={formatCount(d.new_hosts_total)}
            edge="red"
            note={d.latest_run ? `in run #${d.latest_run.id}` : undefined}
          />
          <KeyNumber label="Changed services" value={counts ? formatCount(counts.changed) : '—'} edge="rose" note={since} />
          <KeyNumber label="Gone" value={counts ? formatCount(counts.gone) : '—'} edge="black" note={since} />
          <KeyNumber
            label="Intermittent hosts"
            value={<Link to={hostsLink({ state: 'unstable' })}>{formatCount(d.hosts.unstable)}</Link>}
            edge="black"
            note={<Link to={hostsLink({ state: 'inactive' })}>{formatCount(d.hosts.inactive)} inactive</Link>}
          />
        </KeyNumbers>
      </Section>

      <ChangesSection d={d} />

      <Section band className="grid gap-10 [grid-template-columns:repeat(auto-fit,minmax(340px,1fr))]">
        <FindingsColumn d={d} />
        <NewDevicesColumn d={d} />
        <TechnologiesColumn d={d} />
      </Section>

      <Section className="flex flex-wrap gap-12">
        <div className="min-w-0 flex-[2_1_600px]">
          <CVESection d={d} />
        </div>
        <div className="min-w-0 flex-[1_1_300px]">
          <IntermittentSection d={d} />
        </div>
      </Section>

      <Section className="pt-0 pb-16">
        <RunsSection runs={d.runs} />
      </Section>
    </>
  )
}

const kindBadge: Record<ChangeKind, { tone: 'new' | 'changed' | 'gone'; label: string }> = {
  new: { tone: 'new', label: '+ New' },
  changed: { tone: 'changed', label: '~ Changed' },
  gone: { tone: 'gone', label: '− Gone' },
}

function ChangesSection({ d }: { d: Dashboard }) {
  const sort = useTableSort(['change', 'ip', 'service', 'summary'], { prefix: 'changes_' })
  const c = d.changes
  if (!c) {
    return (
      <Section className="flex flex-col gap-5">
        <SectionHeading>Changes</SectionHeading>
        <EmptyState>No two finished runs to compare</EmptyState>
      </Section>
    )
  }
  const n = changeCounts(c.summary)
  const rows = sortRows(diffRows(c), sort, {
    change: (r) => r.kind,
    ip: (r) => r.ip,
    service: (r) => r.type === 'service' ? `${r.service.port}/${r.service.proto}` : 'host',
    summary: changeText,
  })
  return (
    <Section className="flex flex-col gap-5">
      <SectionHeading
        aside={
          <>
            <Badge tone="new">+ {formatCount(n.new)} new</Badge>
            <Badge tone="changed">~ {formatCount(n.changed)} changed</Badge>
            <Badge tone="gone">− {formatCount(n.gone)} gone</Badge>
            <Link to={changesLink(c)} className="ml-3 font-medium">
              Compare runs
            </Link>
          </>
        }
      >
        Changes since run #{c.from.id}
      </SectionHeading>
      <Table minWidth={760} label="Changes">
        <thead>
          <THeadRow>
            <SortTh sort={sort} col="change">Change</SortTh>
            <SortTh sort={sort} col="ip">Host</SortTh>
            <SortTh sort={sort} col="service">Service</SortTh>
            <SortTh sort={sort} col="summary">What changed</SortTh>
          </THeadRow>
        </thead>
        <tbody>
          {rows.slice(0, 10).map((r) => (
            <Tr key={r.key}>
              <Td>
                <span className="inline-block min-w-[92px]">
                  <Badge tone={kindBadge[r.kind].tone}>{kindBadge[r.kind].label}</Badge>
                </span>
              </Td>
              <Td>
                <Link to={`/hosts/${r.ip}`} className="font-mono font-medium">
                  {r.ip}
                </Link>
              </Td>
              <Td className="font-mono text-[13px] whitespace-nowrap">
                {r.type === 'service' ? `${r.service.port}/${r.service.proto}` : <span className="text-muted">host</span>}
              </Td>
              <Td className="break-words">{changeText(r)}</Td>
            </Tr>
          ))}
          {rows.length === 0 && <EmptyRow colSpan={4}>No changes</EmptyRow>}
        </tbody>
      </Table>
      {(c.truncated || rows.length > 10) && (
        <Link to={changesLink(c)} className="self-start text-sm font-medium">
          All {formatCount(n.new + n.changed + n.gone)} changes
        </Link>
      )}
    </Section>
  )
}

function Column({ title, children }: { title: ReactNode; children: ReactNode }) {
  return (
    <div className="flex min-w-0 flex-col gap-[18px]">
      <SectionHeading size="sm">{title}</SectionHeading>
      {children}
    </div>
  )
}

// Full class names so Tailwind sees them.
const sevBar: Record<SeverityKey, string> = {
  critical: 'bg-sev-critical',
  high: 'bg-sev-high',
  medium: 'bg-sev-medium',
  low: 'bg-sev-low',
  info: 'bg-sev-info',
}

function FindingsColumn({ d }: { d: Dashboard }) {
  const { bars, info } = severityBars(d.findings)
  return (
    <Column title="Active findings by severity">
      <ul className="m-0 flex list-none flex-col gap-3 p-0" aria-label="Active findings by severity">
        {bars.map((b) => (
          <li key={b.severity} className="grid grid-cols-[96px_1fr_56px] items-center gap-3">
            <Link to={findingsLink(b.severity)} className="text-sm no-underline">
              <SeverityLabel severity={b.key} />
            </Link>
            <div className="h-3.5 bg-white">
              <div className={'h-3.5 ' + sevBar[b.key]} style={{ width: b.width }} />
            </div>
            <span className="text-right text-lg font-light tabular-nums">{formatCount(b.count)}</span>
          </li>
        ))}
      </ul>
      <p className="m-0 text-sm text-muted">
        + {formatCount(info)} informational · <Link to={findingsLink()}>All findings</Link>
      </p>
    </Column>
  )
}

function NewDevicesColumn({ d }: { d: Dashboard }) {
  return (
    <Column title="New devices">
      {d.new_hosts.length === 0 ? (
        <p className="m-0 text-sm text-muted">No new devices in the last run</p>
      ) : (
        <ul className="m-0 flex list-none flex-col gap-3.5 p-0" aria-label="New devices">
          {d.new_hosts.map((h) => (
            <li key={h.ip} className="border-l-2 border-red pl-3.5">
              <div className="flex justify-between gap-2">
                <Link to={`/hosts/${h.ip}`} className="font-mono font-medium">
                  {h.ip}
                </Link>
                <span className="text-[13px] text-muted">{new Date(h.first_seen).toLocaleString()}</span>
              </div>
              <div className="text-[15px] font-light break-words">
                {[h.hostnames[0], h.ports.length > 0 ? h.ports.map((p) => `${p}/tcp`).join(', ') : 'no open ports']
                  .filter(Boolean)
                  .join(' · ')}
              </div>
            </li>
          ))}
        </ul>
      )}
      {d.new_hosts_total > d.new_hosts.length && d.changes && (
        <Link to={changesLink(d.changes)} className="text-sm font-medium">
          All {formatCount(d.new_hosts_total)} new devices
        </Link>
      )}
    </Column>
  )
}

function TechnologiesColumn({ d }: { d: Dashboard }) {
  const max = Math.max(0, ...d.technologies.map((t) => t.hosts))
  return (
    <Column title="Top web technologies">
      {d.technologies.length === 0 ? (
        <p className="m-0 text-sm text-muted">No web technologies</p>
      ) : (
        <ul className="m-0 flex list-none flex-col gap-2.5 p-0" aria-label="Top web technologies">
          {d.technologies.map((t) => (
            <li key={t.name} className="grid grid-cols-[minmax(0,200px)_1fr_44px] items-center gap-3 text-sm">
              <Link to={hostsLink({ tech: t.name })} className="truncate" title={t.name}>
                {t.name}
              </Link>
              <div className="h-3 bg-white">
                <div className="h-3 bg-green" style={{ width: pct(t.hosts, max) }} />
              </div>
              <span className="text-right tabular-nums">{formatCount(t.hosts)}</span>
            </li>
          ))}
        </ul>
      )}
    </Column>
  )
}

function CVESection({ d }: { d: Dashboard }) {
  const sort = useTableSort(['severity', 'service', 'product', 'cves', 'cvss', 'kev'], {
    prefix: 'cves_', initial: 'severity', direction: 'desc',
  })
  const rows = sortRows(d.cve_matches, sort, {
    severity: (m) => ['Info', 'Low', 'Medium', 'High', 'Critical'].indexOf(m.severity),
    service: (m) => `${m.ip}:${m.port}/${m.proto}`,
    product: (m) => `${m.product} ${m.version}`,
    cves: (m) => m.cves,
    cvss: (m) => m.max_cvss,
    kev: (m) => m.kev,
  })
  return (
    <div className="flex flex-col gap-4">
      <SectionHeading aside={d.cve_total > 0 ? <span className="text-muted">{formatCount(d.cve_total)} services</span> : undefined}>
        CVE matches
      </SectionHeading>
      <Table minWidth={560} label="CVE matches">
        <thead>
          <THeadRow>
            <SortTh sort={sort} col="severity">Severity</SortTh>
            <SortTh sort={sort} col="service">Service</SortTh>
            <SortTh sort={sort} col="product">Product</SortTh>
            <SortTh sort={sort} col="cves" className="text-right">CVEs</SortTh>
            <SortTh sort={sort} col="cvss" className="text-right">Max CVSS</SortTh>
            <SortTh sort={sort} col="kev" className="text-right">KEV</SortTh>
          </THeadRow>
        </thead>
        <tbody>
          {rows.map((m) => (
            <Tr key={`${m.ip}-${m.port}-${m.proto}-${m.product}`}>
              <Td>
                <SeverityLabel severity={m.severity.toLowerCase() as SeverityKey} />
              </Td>
              <Td className="font-mono text-[13px] whitespace-nowrap">
                <Link to={`/hosts/${m.ip}`} className="font-medium">
                  {m.ip}
                </Link>
                :{m.port}/{m.proto}
              </Td>
              <Td>
                {m.product} {m.version}
              </Td>
              <Td className="text-right tabular-nums">{m.cves}</Td>
              <Td className="text-right tabular-nums">{m.max_cvss.toFixed(1)}</Td>
              <Td className="text-right tabular-nums">{m.kev > 0 ? m.kev : '—'}</Td>
            </Tr>
          ))}
          {d.cve_matches.length === 0 && <EmptyRow colSpan={6}>No CVE matches</EmptyRow>}
        </tbody>
      </Table>
    </div>
  )
}

function IntermittentSection({ d }: { d: Dashboard }) {
  return (
    <div className="flex flex-col gap-4">
      <SectionHeading>Intermittent hosts</SectionHeading>
      {d.unstable_hosts.length === 0 ? (
        <EmptyState>No intermittent or inactive hosts</EmptyState>
      ) : (
        <ul className="m-0 list-none border-t-2 border-black p-0" aria-label="Intermittent hosts">
          {d.unstable_hosts.map((u) => (
            <li key={u.ip} className="flex flex-wrap items-center justify-between gap-2 border-b border-line py-2.5">
              <span className="flex items-center gap-2">
                <Link to={`/hosts/${u.ip}`} className="font-mono text-sm font-medium">
                  {u.ip}
                </Link>
                {u.state === 'inactive' && <Badge tone="gone">inactive</Badge>}
              </span>
              <Link to={`/changes/hosts/${u.ip}`} className="text-sm text-muted">
                {unstablePattern(u)}
              </Link>
            </li>
          ))}
        </ul>
      )}
      <div className="flex flex-wrap gap-x-5 gap-y-1 text-sm font-medium">
        <Link to={hostsLink({ state: 'unstable' })}>All intermittent ({formatCount(d.hosts.unstable)})</Link>
        <Link to={hostsLink({ state: 'inactive' })}>Inactive ({formatCount(d.hosts.inactive)})</Link>
      </div>
    </div>
  )
}

function RunsSection({ runs }: { runs: DashboardRun[] }) {
  const sort = useTableSort(['id', 'profile', 'status', 'started_at', 'duration', 'hosts_up'], {
    prefix: 'runs_', initial: 'id', direction: 'desc',
  })
  const rows = sortRows(runs, sort, {
    id: (r) => r.id,
    profile: (r) => r.profile,
    status: (r) => r.status,
    started_at: (r) => r.started_at ? Date.parse(r.started_at) : null,
    duration: (r) => r.duration_ms,
    hosts_up: (r) => r.hosts_up,
  })
  return (
    <div className="flex flex-col gap-4">
      <SectionHeading
        aside={
          <Link to="/runs" className="font-medium">
            All runs
          </Link>
        }
      >
        Recent runs
      </SectionHeading>
      <Table minWidth={720} label="Recent runs">
        <thead>
          <THeadRow>
            <SortTh sort={sort} col="id">Run</SortTh>
            <SortTh sort={sort} col="profile">Profile</SortTh>
            <SortTh sort={sort} col="status">Status</SortTh>
            <SortTh sort={sort} col="started_at">Started</SortTh>
            <SortTh sort={sort} col="duration">Duration</SortTh>
            <SortTh sort={sort} col="hosts_up" className="text-right">Hosts up</SortTh>
          </THeadRow>
        </thead>
        <tbody>
          {rows.map((r) => (
            <Tr key={r.id}>
              <Td className="text-xl font-light">
                <Link to={`/runs/${r.id}`}>#{r.id}</Link>
              </Td>
              <Td>{r.profile}</Td>
              <Td>
                <StatusBadge status={r.status} />
                {r.batches_total > 0 && (
                  <div className="mt-1 text-[13px] text-muted">
                    {r.batches_done}/{r.batches_total} batches
                  </div>
                )}
              </Td>
              <Td className="font-mono text-[13px]">{r.started_at ? new Date(r.started_at).toLocaleString() : '—'}</Td>
              <Td>{formatDuration(r.duration_ms)}</Td>
              <Td className="text-right tabular-nums">
                {formatCount(r.hosts_up)} / {formatCount(r.hosts_total)}
              </Td>
            </Tr>
          ))}
          {runs.length === 0 && <EmptyRow colSpan={6}>No runs</EmptyRow>}
        </tbody>
      </Table>
    </div>
  )
}
