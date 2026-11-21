import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'
import { Link } from 'react-router'
import { api, type Schemas } from '../../api/client'
import { useCan } from '../../auth/hooks'
import { PageHeader } from '../../components/PageHeader'
import {
  Alert,
  Badge,
  Button,
  buttonClass,
  EmptyRow,
  ErrorText,
  Field,
  FilterBar,
  inputClass,
  Section,
  SectionHeading,
  SeverityLabel,
  Table,
  Td,
  Th,
  THeadRow,
  ToggleGroup,
  Tr,
  type Severity,
} from '../../components/ui'
import { parseMeta, signaturesKey } from './meta'

type Source = 'all' | 'builtin' | 'custom'
type Sig = Schemas['Signature']

const severities: Severity[] = ['critical', 'high', 'medium', 'low', 'info']

function apiSeverity(s: string | undefined): Severity | null {
  const low = (s ?? '').toLowerCase() as Severity
  return severities.includes(low) ? low : null
}

export function EnabledToggle({ sig }: { sig: Sig }) {
  const qc = useQueryClient()
  const m = useMutation({
    mutationFn: (enabled: boolean) => api.put('/signatures/{id}', { params: { id: sig.id }, body: { enabled } }),
    onSuccess: () => qc.invalidateQueries({ queryKey: signaturesKey }),
  })
  return (
    <span className="inline-flex flex-col gap-1">
      <label className="inline-flex items-center gap-2">
        <input
          type="checkbox"
          className="size-4 accent-red"
          checked={sig.enabled}
          disabled={m.isPending || (!sig.valid && !sig.enabled)}
          onChange={(e) => m.mutate(e.target.checked)}
          aria-label={`Enabled ${sig.name}`}
        />
        <span>{sig.enabled ? 'Enabled' : 'Disabled'}</span>
      </label>
      {m.isError && <span className="text-[13px] text-red">{m.error.message}</span>}
    </span>
  )
}

export function SignaturesList() {
  const canWrite = useCan('signatures:write')
  const [source, setSource] = useState<Source>('all')
  const [q, setQ] = useState('')
  const [tag, setTag] = useState('')
  const trimmedTag = tag.trim()
  const list = useQuery({
    queryKey: [...signaturesKey, trimmedTag],
    queryFn: ({ signal }) =>
      api.get('/signatures', { query: { limit: 1000, tag: trimmedTag || undefined }, signal }),
  })
  const items = (list.data?.items ?? [])
    .map((s) => {
      const parsed = parseMeta(s.template_yaml)
      const severity = apiSeverity(s.severity) ?? parsed.severity
      const tags = s.tags && s.tags.length > 0 ? s.tags : parsed.tags
      return { sig: s, displayName: parsed.name || s.name, severity, tags }
    })
    .filter(({ sig }) => source === 'all' || sig.builtin === (source === 'builtin'))
    .filter(({ sig, displayName, tags }) => {
      const needle = q.trim().toLowerCase()
      if (!needle) return true
      return [sig.name, displayName, ...tags].some((x) => x.toLowerCase().includes(needle))
    })
  const all = list.data?.items ?? []
  const enabled = all.filter((s) => s.enabled).length
  const invalid = all.filter((s) => !s.valid).length

  return (
    <>
      <PageHeader
        title="Signatures"
        crumbs={[{ label: 'Signatures' }]}
        meta={list.data && `${all.length} signatures · ${enabled} enabled · ${invalid} invalid`}
      >
        {canWrite && (
          <Link to="/signatures/new" className={buttonClass('primary', 'lg')}>
            New signature
          </Link>
        )}
      </PageHeader>
      <FilterBar onSubmit={(e) => e.preventDefault()}>
        <Field label="Search" className="w-72">
          <input className={inputClass} value={q} onChange={(e) => setQ(e.target.value)} placeholder="Name, id or tag" />
        </Field>
        <Field label="Tag" className="w-48">
          <input className={inputClass} value={tag} onChange={(e) => setTag(e.target.value)} placeholder="panel" />
        </Field>
        <ToggleGroup<Source>
          label="Source"
          value={source}
          onChange={setSource}
          options={[
            { value: 'all', label: 'All' },
            { value: 'builtin', label: 'Built-in' },
            { value: 'custom', label: 'Custom' },
          ]}
        />
        {(q || tag || source !== 'all') && (
          <Button
            onClick={() => {
              setQ('')
              setTag('')
              setSource('all')
            }}
          >
            Reset
          </Button>
        )}
      </FilterBar>
      <Section className="flex flex-col gap-5">
        <SectionHeading aside={<span className="text-muted">{items.length} shown</span>}>Templates</SectionHeading>
        {list.isError && <ErrorText>{list.error.message}</ErrorText>}
        <Table label="Signatures" minWidth={860}>
          <thead>
            <THeadRow>
              <Th>Signature</Th>
              <Th>Severity</Th>
              <Th>Tags</Th>
              <Th>Source</Th>
              <Th>Validation</Th>
              <Th>Status</Th>
            </THeadRow>
          </thead>
          <tbody>
            {list.isPending && <EmptyRow colSpan={6}>Loading…</EmptyRow>}
            {list.isSuccess && items.length === 0 && <EmptyRow colSpan={6}>No signatures</EmptyRow>}
            {items.map(({ sig, displayName, severity, tags }) => (
              <Tr key={sig.id}>
                <Td>
                  <Link to={`/signatures/${sig.id}`} className="font-medium">
                    {displayName}
                  </Link>
                  <div className="font-mono text-xs text-muted">{sig.name}</div>
                </Td>
                <Td>{severity ? <SeverityLabel severity={severity} /> : <span className="text-muted">—</span>}</Td>
                <Td>
                  <div className="flex flex-wrap gap-1">
                    {tags.map((t) => {
                      const active = trimmedTag.toLowerCase() === t.toLowerCase()
                      return (
                        <button
                          key={t}
                          type="button"
                          onClick={() => setTag(active ? '' : t)}
                          className={
                            'px-2 py-px text-[13px] whitespace-nowrap ' +
                            (active
                              ? 'border border-black bg-black text-white'
                              : 'border border-line-strong bg-white text-ink hover:bg-band')
                          }
                        >
                          {t}
                        </button>
                      )
                    })}
                  </div>
                </Td>
                <Td>{sig.builtin ? <Badge tone="done">Built-in</Badge> : <Badge tone="outline">Custom</Badge>}</Td>
                <Td>
                  {sig.valid ? (
                    <Badge tone="new">Valid</Badge>
                  ) : (
                    <Badge tone="red" title={sig.validation_error}>
                      Invalid
                    </Badge>
                  )}
                </Td>
                <Td>
                  {canWrite ? (
                    <EnabledToggle sig={sig} />
                  ) : (
                    <span className={sig.enabled ? '' : 'text-muted'}>{sig.enabled ? 'Enabled' : 'Disabled'}</span>
                  )}
                </Td>
              </Tr>
            ))}
          </tbody>
        </Table>
        {list.isSuccess && list.data.total > all.length && (
          <Alert>Showing {all.length} of {list.data.total}</Alert>
        )}
      </Section>
    </>
  )
}
