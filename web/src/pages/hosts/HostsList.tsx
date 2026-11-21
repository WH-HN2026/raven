import { keepPreviousData, useQuery } from '@tanstack/react-query'
import { useState, type FormEvent } from 'react'
import { Link, useSearchParams } from 'react-router'
import { api } from '../../api/client'
import {
  PAGE,
  apiQuery,
  btnPrimary,
  btnSecondary,
  card,
  chip,
  chipMuted,
  filtersFromParams,
  fmtTime,
  hostStates,
  hostsKey,
  input,
  offsetFromParams,
  paramsFromFilters,
  portsSummary,
  stateClass,
  td,
  th,
  type HostFilters,
} from './ui'

export function HostsPage() {
  const [params, setParams] = useSearchParams()
  const filters = filtersFromParams(params)
  const offset = offsetFromParams(params)
  const query = apiQuery(filters, offset)
  const q = useQuery({
    queryKey: [...hostsKey, query],
    queryFn: () => api.get('/hosts', { query }),
    placeholderData: keepPreviousData,
  })
  const apply = (f: HostFilters, off = 0) => setParams(paramsFromFilters(f, off))

  const total = q.data?.total ?? 0
  const items = q.data?.items ?? []
  const filtered = Object.values(filters).some((v) => v !== '')

  return (
    <div className="space-y-4">
      <div className="flex items-baseline gap-3">
        <h1 className="text-2xl font-semibold text-ink">Hosts</h1>
        <span className="text-sm text-muted">{q.isSuccess ? `${total} ${filtered ? 'matching' : 'total'}` : ''}</span>
      </div>
      {/* key: re-initialise the inputs when the URL changes (back/forward, reset). */}
      <FilterForm key={params.toString()} initial={filters} onApply={apply} />
      <section className={card}>
        {q.error && <p className="mb-2 text-sm text-danger">Cannot load hosts: {q.error.message}</p>}
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr>
                <th className={th}>IP</th>
                <th className={th}>Hostnames</th>
                <th className={th}>State</th>
                <th className={th}>Open ports</th>
                <th className={th}>Technologies</th>
                <th className={th}>Tags</th>
                <th className={th}>Owner</th>
                <th className={th}>First seen</th>
                <th className={th}>Last seen</th>
                <th className={th}>Misses</th>
              </tr>
            </thead>
            <tbody>
              {items.map((h) => (
                <tr key={h.ip} className="hover:bg-canvas">
                  <td className={td + ' font-mono whitespace-nowrap'}>
                    <Link
                      className="text-brand hover:underline"
                      to={`/hosts/${encodeURIComponent(h.ip)}`}
                      state={{ from: params.toString() }}
                    >
                      {h.ip}
                    </Link>
                  </td>
                  <td className={td + ' text-graphite'}>{h.hostnames.join(', ')}</td>
                  <td className={td}>
                    <span className={stateClass(h.state)}>{h.state}</span>
                  </td>
                  <td className={td + ' font-mono'} title={h.open_ports.join(', ')}>
                    {portsSummary(h.open_ports)}
                    {h.open_service_count > h.open_ports.length && (
                      <span className="text-muted"> ({h.open_service_count} services)</span>
                    )}
                  </td>
                  <td className={td}>
                    <div className="flex flex-wrap gap-1">
                      {h.technologies.map((t) => (
                        <span key={t} className={chipMuted}>
                          {t}
                        </span>
                      ))}
                    </div>
                  </td>
                  <td className={td}>
                    <div className="flex flex-wrap gap-1">
                      {h.user_tags.map((t) => (
                        <span key={t} className={chip}>
                          {t}
                        </span>
                      ))}
                    </div>
                  </td>
                  <td className={td + ' text-graphite'}>
                    {h.owner}
                    {h.criticality && <span className="ml-1 text-xs text-muted">({h.criticality})</span>}
                  </td>
                  <td className={td + ' whitespace-nowrap text-muted'}>{fmtTime(h.first_seen)}</td>
                  <td className={td + ' whitespace-nowrap text-muted'}>{fmtTime(h.last_seen)}</td>
                  <td className={td + ' text-right'}>{h.miss_count}</td>
                </tr>
              ))}
              {q.isSuccess && items.length === 0 && (
                <tr>
                  <td className={td + ' text-muted'} colSpan={10}>
                    {filtered ? 'No hosts match these filters.' : 'No hosts yet. Run a scan to discover some.'}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
        {total > PAGE && (
          <div className="mt-3 flex items-center gap-2 text-sm text-graphite">
            <button
              className={btnSecondary}
              disabled={offset === 0}
              onClick={() => apply(filters, Math.max(0, offset - PAGE))}
            >
              Previous
            </button>
            <span>
              {Math.min(offset + 1, total)}–{Math.min(offset + PAGE, total)} of {total}
            </span>
            <button className={btnSecondary} disabled={offset + PAGE >= total} onClick={() => apply(filters, offset + PAGE)}>
              Next
            </button>
          </div>
        )}
      </section>
    </div>
  )
}

function FilterForm({ initial, onApply }: { initial: HostFilters; onApply: (f: HostFilters) => void }) {
  const [f, setF] = useState(initial)
  const set = (k: keyof HostFilters) => (e: { target: { value: string } }) => setF({ ...f, [k]: e.target.value })
  const submit = (e: FormEvent) => {
    e.preventDefault()
    onApply(f)
  }
  const portInvalid = f.port.trim() !== '' && !/^\d{1,5}$/.test(f.port.trim())
  return (
    <form className={card + ' flex flex-wrap items-end gap-3'} onSubmit={submit} role="search">
      <label className="flex flex-col gap-1 text-xs text-muted">
        Search
        <input
          className={input + ' w-56'}
          value={f.q}
          onChange={set('q')}
          placeholder="IP, CIDR or hostname"
        />
      </label>
      <label className="flex flex-col gap-1 text-xs text-muted">
        State
        <select
          className={input}
          value={f.state}
          onChange={(e) => {
            const next = { ...f, state: e.target.value }
            setF(next)
            onApply(next)
          }}
        >
          <option value="">any</option>
          {hostStates.map((s) => (
            <option key={s} value={s}>
              {s}
            </option>
          ))}
        </select>
      </label>
      <label className="flex flex-col gap-1 text-xs text-muted">
        Open port
        <input
          className={input + ' w-24'}
          value={f.port}
          onChange={set('port')}
          inputMode="numeric"
          placeholder="443"
          aria-invalid={portInvalid}
        />
      </label>
      <label className="flex flex-col gap-1 text-xs text-muted">
        Technology
        <input className={input + ' w-36'} value={f.tech} onChange={set('tech')} placeholder="WordPress" />
      </label>
      <label className="flex flex-col gap-1 text-xs text-muted">
        Tag
        <input className={input + ' w-32'} value={f.tag} onChange={set('tag')} />
      </label>
      <button type="submit" className={btnPrimary} disabled={portInvalid}>
        Apply
      </button>
      <button
        type="button"
        className={btnSecondary}
        onClick={() => onApply({ state: '', port: '', tech: '', tag: '', q: '' })}
      >
        Reset
      </button>
      {portInvalid && <span className="text-xs text-danger">Port must be a number 0–65535.</span>}
    </form>
  )
}
