import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'
import { useNavigate, useParams } from 'react-router'
import { api, ApiError, type Schemas } from '../../api/client'
import { useCan } from '../../auth/hooks'
import { PageHeader } from '../../components/PageHeader'
import {
  Alert,
  Badge,
  Button,
  ErrorText,
  Field,
  inputClass,
  Section,
  SectionHeading,
  SeverityLabel,
} from '../../components/ui'
import { IssueList } from './IssueList'
import { issuesOf, newTemplate, parseMeta, parseValidationError, signatureKey, signaturesKey, type Issue } from './meta'
import { EnabledToggle } from './SignaturesList'
import { YamlEditor, type GoTo } from './YamlEditor'

type Sig = Schemas['Signature']

/** Route element for /signatures/new and /signatures/:id. */
export function SignatureEditorPage() {
  const { id = 'new' } = useParams()
  const num = id === 'new' ? null : Number(id)
  const sig = useQuery({
    queryKey: signatureKey(num ?? 0),
    queryFn: ({ signal }) => api.get('/signatures/{id}', { params: { id: num! }, signal }),
    enabled: num !== null,
  })
  if (num === null) return <SignatureEditor key="new" sig={null} />
  if (sig.isPending)
    return (
      <>
        <PageHeader title="Signature" crumbs={[{ label: 'Signatures', to: '/signatures' }, { label: id }]} />
        <Section>
          <p className="m-0 text-muted">Loading…</p>
        </Section>
      </>
    )
  if (sig.isError)
    return (
      <>
        <PageHeader title="Signature" crumbs={[{ label: 'Signatures', to: '/signatures' }, { label: id }]} />
        <Section>
          <ErrorText>{sig.error.message}</ErrorText>
        </Section>
      </>
    )
  return <SignatureEditor key={sig.data.id} sig={sig.data} />
}

type Outcome = { kind: 'issues'; title: string; issues: Issue[] } | { kind: 'ok'; text: string } | null

export function SignatureEditor({ sig }: { sig: Sig | null }) {
  const canWrite = useCan('signatures:write')
  const readOnly = !canWrite || !!sig?.builtin
  const qc = useQueryClient()
  const navigate = useNavigate()
  const [draft, setDraft] = useState(sig?.template_yaml ?? newTemplate)
  const [outcome, setOutcome] = useState<Outcome>(null)
  const [goTo, setGoTo] = useState<GoTo | null>(null)
  const meta = parseMeta(draft)
  const dirty = sig ? draft !== sig.template_yaml : true
  const displaySeverity = !dirty && sig?.severity ? (sig.severity.toLowerCase() as typeof meta.severity) : meta.severity
  const displayTags = !dirty && sig?.tags && sig.tags.length > 0 ? sig.tags : meta.tags

  const stored: Issue[] = sig && !sig.valid && !dirty ? parseValidationError(sig.validation_error) : []
  const shownIssues = outcome?.kind === 'issues' ? outcome.issues : stored
  const issueLines = new Set(shownIssues.map((i) => i.line).filter((l) => l > 0))
  const go = (line: number) => setGoTo((g) => ({ line, seq: (g?.seq ?? 0) + 1 }))

  const validate = useMutation({
    mutationFn: () => api.post('/signatures/validate', { body: { template_yaml: draft } }),
    onSuccess: (r) =>
      setOutcome(r.valid ? { kind: 'ok', text: 'Valid' } : { kind: 'issues', title: 'Invalid', issues: r.issues }),
  })

  const onSaved = (s: Sig) => {
    qc.invalidateQueries({ queryKey: signaturesKey })
    setOutcome(
      s.valid
        ? { kind: 'ok', text: 'Saved' }
        : { kind: 'issues', title: 'Saved, disabled: invalid', issues: parseValidationError(s.validation_error) },
    )
  }
  const saveError = (e: Error) => {
    const issues = e instanceof ApiError ? issuesOf(e.body) : null
    if (issues && issues.length > 0) setOutcome({ kind: 'issues', title: 'Not saved', issues })
  }
  const create = useMutation({
    mutationFn: () => api.post('/signatures', { body: { template_yaml: draft } }),
    onSuccess: (s) => {
      onSaved(s)
      qc.setQueryData(signatureKey(s.id), s)
      navigate(`/signatures/${s.id}`)
    },
    onError: saveError,
  })
  const update = useMutation({
    mutationFn: () => api.put('/signatures/{id}', { params: { id: sig!.id }, body: { template_yaml: draft } }),
    onSuccess: (s) => {
      qc.setQueryData(signatureKey(s.id), s)
      onSaved(s)
    },
    onError: saveError,
  })
  const del = useMutation({
    mutationFn: () => api.delete('/signatures/{id}', { params: { id: sig!.id } }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: signaturesKey })
      navigate('/signatures')
    },
  })
  const save = sig ? update : create
  const mutationError = [save, del].find((m) => m.isError && !(m.error instanceof ApiError && issuesOf(m.error.body)))
    ?.error

  const title = sig ? parseMeta(sig.template_yaml).name || sig.name : 'New signature'
  return (
    <>
      <PageHeader
        title={title}
        crumbs={[{ label: 'Signatures', to: '/signatures' }, { label: sig ? sig.name : 'New' }]}
        badges={
          sig && (
            <>
              <Badge tone="outline-dark">{sig.builtin ? 'Built-in' : 'Custom'}</Badge>
              {sig.valid ? <Badge tone="new">Valid</Badge> : <Badge tone="red">Invalid</Badge>}
              {sig.enabled ? <Badge tone="new">Enabled</Badge> : <Badge tone="gone">Disabled</Badge>}
            </>
          )
        }
        meta={
          <span className="inline-flex flex-wrap items-center gap-x-4 gap-y-1">
            <span className="font-mono">{meta.id || '—'}</span>
            {displaySeverity && <SeverityLabel severity={displaySeverity} />}
            {displayTags.length > 0 && <span>{displayTags.join(', ')}</span>}
          </span>
        }
      />
      <Section className="flex flex-wrap items-start gap-12">
        <div className="flex min-w-0 flex-[2_1_640px] flex-col gap-5">
          <SectionHeading>Template</SectionHeading>
          <YamlEditor
            label="Template YAML"
            value={draft}
            onChange={(v) => {
              setDraft(v)
              if (outcome?.kind === 'ok') setOutcome(null)
            }}
            readOnly={readOnly}
            issueLines={issueLines}
            goTo={goTo}
          />
          {canWrite && (
            <div className="flex flex-wrap gap-3">
              <Button onClick={() => validate.mutate()} disabled={validate.isPending}>
                Validate
              </Button>
              {!readOnly && (
                <Button variant="primary" onClick={() => save.mutate()} disabled={save.isPending || (!!sig && !dirty)}>
                  {sig ? 'Save' : 'Create'}
                </Button>
              )}
              {sig && !sig.builtin && (
                <Button
                  variant="danger"
                  className="ml-auto"
                  disabled={del.isPending}
                  onClick={() => {
                    if (window.confirm(`Delete ${sig.name}?`)) del.mutate()
                  }}
                >
                  Delete
                </Button>
              )}
            </div>
          )}
          {outcome?.kind === 'ok' && <Alert tone="ok">{outcome.text}</Alert>}
          {shownIssues.length > 0 && (
            <IssueList
              issues={shownIssues}
              title={outcome?.kind === 'issues' ? outcome.title : 'Invalid'}
              onGo={go}
            />
          )}
          {validate.isError && <ErrorText>{validate.error.message}</ErrorText>}
          {mutationError && <ErrorText>{mutationError.message}</ErrorText>}
        </div>
        {sig && (
          <aside className="flex min-w-0 flex-[1_1_320px] flex-col gap-8">
            <section className="flex flex-col gap-4">
              <SectionHeading size="sm">Status</SectionHeading>
              {canWrite ? (
                <EnabledToggle sig={sig} />
              ) : (
                <span>{sig.enabled ? 'Enabled' : 'Disabled'}</span>
              )}
              <dl className="m-0 grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-sm">
                <dt className="text-muted">Source</dt>
                <dd className="m-0">{sig.builtin ? 'Built-in' : 'Custom'}</dd>
                <dt className="text-muted">Created</dt>
                <dd className="m-0">{new Date(sig.created_at).toLocaleString()}</dd>
              </dl>
            </section>
            {canWrite && <TestPanel id={sig.id} />}
          </aside>
        )}
      </Section>
    </>
  )
}

function TestPanel({ id }: { id: number }) {
  const [url, setUrl] = useState('')
  const test = useMutation({
    mutationFn: () => api.post('/signatures/{id}/test', { params: { id }, body: { url } }),
  })
  const unavailable = test.error instanceof ApiError && test.error.status === 501
  return (
    <section className="flex flex-col gap-4">
      <SectionHeading size="sm" aside={unavailable && <Badge tone="gone">Not available yet</Badge>}>
        Test
      </SectionHeading>
      <form
        className="flex flex-col gap-3"
        onSubmit={(e) => {
          e.preventDefault()
          test.mutate()
        }}
      >
        <Field label="Lab URL">
          <input
            className={inputClass + ' font-mono'}
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="http://172.30.0.10/"
            disabled={unavailable}
          />
        </Field>
        <div>
          <Button type="submit" disabled={unavailable || test.isPending || url.trim() === ''}>
            Test
          </Button>
        </div>
      </form>
      {test.isError && !unavailable && <ErrorText>{test.error.message}</ErrorText>}
      {test.isSuccess && <Alert tone="ok">Done</Alert>}
    </section>
  )
}
