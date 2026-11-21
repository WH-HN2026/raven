import { useQuery } from '@tanstack/react-query'
import { Link, useLocation, useParams } from 'react-router'
import { ApiError, api, type Schemas } from '../../api/client'
import { card, chip, chipMuted, fmtTime, hostsKey, stateClass, td, th } from './ui'

type Service = Schemas['Service']
type HttpObservation = Schemas['HttpObservation']

export function HostDetailPage() {
  const { ip = '' } = useParams()
  const location = useLocation()
  const from = (location.state as { from?: string } | null)?.from
  const q = useQuery({
    queryKey: [...hostsKey, 'detail', ip],
    queryFn: () => api.get('/hosts/{ip}', { params: { ip } }),
    retry: (n, err) => !(err instanceof ApiError && err.status < 500) && n < 2,
  })
  const back = (
    <Link to={from ? `/hosts?${from}` : '/hosts'} className="text-sm text-brand hover:underline">
      ← All hosts
    </Link>
  )

  if (q.isPending) return <div className="space-y-3">{back}<p className="text-muted">Loading…</p></div>
  if (q.error) {
    const notFound = q.error instanceof ApiError && q.error.status === 404
    return (
      <div className="space-y-3">
        {back}
        <p className="text-danger">{notFound ? `Host ${ip} is not known.` : `Cannot load host: ${q.error.message}`}</p>
      </div>
    )
  }
  const h = q.data
  return (
    <div className="space-y-6">
      {back}
      <div className="flex flex-wrap items-baseline gap-3">
        <h1 className="font-mono text-2xl font-semibold text-ink">{h.ip}</h1>
        <span className={stateClass(h.state)}>{h.state}</span>
        {h.hostnames.length > 0 && <span className="text-graphite">{h.hostnames.join(', ')}</span>}
      </div>

      <section className={card}>
        <dl className="grid grid-cols-1 gap-x-6 gap-y-2 text-sm sm:grid-cols-2 lg:grid-cols-4">
          <Field label="First seen">{fmtTime(h.first_seen)}</Field>
          <Field label="Last seen">{fmtTime(h.last_seen)}</Field>
          <Field label="Missed runs">{h.miss_count}</Field>
          <Field label="Open services">{h.open_service_count}</Field>
          <Field label="Owner">{h.owner || <span className="text-muted">—</span>}</Field>
          <Field label="Criticality">{h.criticality || <span className="text-muted">—</span>}</Field>
          <Field label="Tags">
            {h.user_tags.length ? (
              <span className="flex flex-wrap gap-1">
                {h.user_tags.map((t) => (
                  <span key={t} className={chip}>
                    {t}
                  </span>
                ))}
              </span>
            ) : (
              <span className="text-muted">—</span>
            )}
          </Field>
          <Field label="Dojo asset">{h.dojo_asset_id ?? <span className="text-muted">—</span>}</Field>
        </dl>
        {h.notes && <p className="mt-3 whitespace-pre-wrap border-t border-line pt-3 text-sm text-graphite">{h.notes}</p>}
      </section>

      <ServicesTable services={h.services} />
      <HttpSection http={h.http} services={h.services} />
      <Timeline items={h.timeline} />
    </div>
  )
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <dt className="text-xs uppercase tracking-wide text-muted">{label}</dt>
      <dd className="text-ink">{children}</dd>
    </div>
  )
}

/** A service field with an "edited" marker when the user overrode the scan value. */
function Eff({ s, field }: { s: Service; field: 'name' | 'product' | 'version' }) {
  const over = s.overridden.includes(field)
  return (
    <>
      {s[field]}
      {over && (
        <span
          className="ml-1 rounded bg-accent-light px-1 text-xs text-accent-dark"
          title={`Scan value: ${s.scan[field] || '—'}`}
        >
          edited
        </span>
      )}
    </>
  )
}

function ServicesTable({ services }: { services: Service[] }) {
  return (
    <section className={card}>
      <h2 className="mb-3 text-lg font-semibold text-ink">Services</h2>
      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr>
              <th className={th}>Port</th>
              <th className={th}>State</th>
              <th className={th}>Name</th>
              <th className={th}>Product</th>
              <th className={th}>Version</th>
              <th className={th}>Banner</th>
              <th className={th}>First seen</th>
              <th className={th}>Last seen</th>
            </tr>
          </thead>
          <tbody>
            {services.map((s) => (
              <tr key={s.id} className={s.state === 'gone' ? 'text-muted' : ''}>
                <td className={td + ' font-mono whitespace-nowrap'}>
                  {s.port}/{s.proto}
                </td>
                <td className={td}>
                  <span className={s.state === 'open' ? stateClass('active') : stateClass('inactive')}>{s.state}</span>
                </td>
                <td className={td}>
                  <Eff s={s} field="name" />
                </td>
                <td className={td}>
                  <Eff s={s} field="product" />
                </td>
                <td className={td}>
                  <Eff s={s} field="version" />
                </td>
                <td className={td + ' max-w-md break-all font-mono text-xs'}>{s.banner}</td>
                <td className={td + ' whitespace-nowrap text-muted'}>{fmtTime(s.first_seen)}</td>
                <td className={td + ' whitespace-nowrap text-muted'}>{fmtTime(s.last_seen)}</td>
              </tr>
            ))}
            {services.length === 0 && (
              <tr>
                <td className={td + ' text-muted'} colSpan={8}>
                  No services.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </section>
  )
}

function HttpSection({ http, services }: { http: HttpObservation[]; services: Service[] }) {
  const port = new Map(services.map((s) => [s.id, `${s.port}/${s.proto}`]))
  return (
    <section className={card}>
      <h2 className="mb-3 text-lg font-semibold text-ink">HTTP observations</h2>
      {http.length === 0 ? (
        <p className="text-sm text-muted">No HTTP observations.</p>
      ) : (
        <div className="space-y-4">
          {http.map((o) => (
            <article key={o.id} className="rounded border border-line p-3">
              <div className="flex flex-wrap items-baseline gap-2">
                <span className="font-mono text-sm text-ink break-all">{o.url}</span>
                {o.status !== null && <span className={chipMuted}>{o.status}</span>}
                <span className="text-xs text-muted">
                  {port.get(o.service_id)} · observed {fmtTime(o.observed_at)}
                  {o.run_id !== null && ` · run #${o.run_id}`}
                </span>
              </div>
              {o.title && <p className="mt-1 text-sm text-graphite">{o.title}</p>}
              {o.technologies.length > 0 && (
                <div className="mt-2 flex flex-wrap gap-1">
                  {o.technologies.map((t) => (
                    <span key={t} className={chip}>
                      {t}
                    </span>
                  ))}
                </div>
              )}
              <div className="mt-2 grid gap-3 text-xs lg:grid-cols-2">
                {Object.keys(o.headers).length > 0 && (
                  <Block title="Headers">
                    <table className="w-full">
                      <tbody>
                        {Object.entries(o.headers)
                          .sort(([a], [b]) => a.localeCompare(b))
                          .map(([k, v]) => (
                            <tr key={k}>
                              <td className="pr-2 align-top font-mono text-muted whitespace-nowrap">{k}</td>
                              <td className="font-mono break-all text-ink">{v}</td>
                            </tr>
                          ))}
                      </tbody>
                    </table>
                  </Block>
                )}
                {o.cookies.length > 0 && (
                  <Block title="Cookies">
                    <ul className="font-mono break-all">
                      {o.cookies.map((c, i) => (
                        <li key={i}>{c}</li>
                      ))}
                    </ul>
                  </Block>
                )}
                {o.redirects.length > 0 && (
                  <Block title="Redirects">
                    <ol className="list-decimal pl-4 font-mono break-all">
                      {o.redirects.map((r, i) => (
                        <li key={i}>{r}</li>
                      ))}
                    </ol>
                  </Block>
                )}
                {o.tls_cert && (
                  <Block title="TLS certificate">
                    <pre className="whitespace-pre-wrap break-all font-mono">{o.tls_cert}</pre>
                  </Block>
                )}
                {o.favicon_hash && (
                  <Block title="Favicon hash">
                    <span className="font-mono">{o.favicon_hash}</span>
                  </Block>
                )}
              </div>
            </article>
          ))}
        </div>
      )}
    </section>
  )
}

function Block({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div>
      <h3 className="mb-1 font-semibold uppercase tracking-wide text-muted">{title}</h3>
      {children}
    </div>
  )
}

function Timeline({ items }: { items: Schemas['HostObservation'][] }) {
  return (
    <section className={card}>
      <h2 className="mb-3 text-lg font-semibold text-ink">Recent runs</h2>
      {items.length === 0 ? (
        <p className="text-sm text-muted">No run observations.</p>
      ) : (
        <ul className="space-y-1 text-sm" aria-label="Up/down timeline">
          {items.map((o) => (
            <li key={o.run_id} className="flex items-center gap-3">
              <span className={o.up ? stateClass('active') : 'rounded bg-accent-light px-1.5 py-0.5 text-xs font-medium text-accent-dark'}>
                {o.up ? 'up' : 'down'}
              </span>
              <span className="text-graphite">run #{o.run_id}</span>
              <span className="text-muted">{fmtTime(o.observed_at)}</span>
            </li>
          ))}
        </ul>
      )}
    </section>
  )
}
