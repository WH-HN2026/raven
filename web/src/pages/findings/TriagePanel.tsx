import { useMutation, useQueryClient } from '@tanstack/react-query'
import { useState, type FormEvent } from 'react'
import { Link } from 'react-router'
import { api } from '../../api/client'
import { useCan } from '../../auth/hooks'
import { Alert, Badge, Button, Field, inputClass, textareaClass, type BadgeTone } from '../../components/ui'
import {
  findingsKey,
  fmtDate,
  settableStatuses,
  severities,
  statusLabel,
  statusOf,
  statusTone,
  triagePatch,
  type Finding,
  type Severity,
  type Status,
} from './ui'

const sevTone: Record<Severity, BadgeTone> = {
  Critical: 'red',
  High: 'red',
  Medium: 'rose',
  Low: 'outline',
  Info: 'gone',
}

function PanelHeading({ children }: { children: string }) {
  return (
    <div className="border-b-2 border-black pb-1.5 text-xs font-medium tracking-[0.06em] text-muted uppercase">
      {children}
    </div>
  )
}

/** The selected finding: summary, Dojo link and (with findings:edit) the triage form. */
export function TriagePanel({ finding: f }: { finding: Finding }) {
  const canEdit = useCan('findings:edit')
  const st = statusOf(f)
  return (
    <>
      <div className="flex flex-col gap-2">
        <div className="flex flex-wrap items-center gap-2">
          <Badge tone={sevTone[f.severity]}>{f.severity}</Badge>
          <Badge tone={statusTone[st]}>{statusLabel[st]}</Badge>
          <span className="text-[13px] text-muted">
            DefectDojo #{f.id}
            {f.dojo_url && (
              <>
                {' · '}
                <a href={f.dojo_url} target="_blank" rel="noopener noreferrer">
                  open ↗
                </a>
              </>
            )}
          </span>
        </div>
        <h2 className="m-0 text-[26px] leading-[1.25] font-light break-words">{f.title}</h2>
        <p className="m-0 text-sm">
          {f.ip && (
            <Link className="font-mono" to={`/hosts/${encodeURIComponent(f.ip)}`}>
              {f.ip}
            </Link>
          )}
          {f.scanner && <span className="text-muted"> · {f.scanner}</span>}
          {f.date && <span className="text-muted"> · {fmtDate(f.date)}</span>}
        </p>
        {f.tags && f.tags.length > 0 && <p className="m-0 text-[13px] text-muted">{f.tags.join(', ')}</p>}
      </div>
      {canEdit && <TriageForm finding={f} />}
    </>
  )
}

function TriageForm({ finding: f }: { finding: Finding }) {
  const qc = useQueryClient()
  const [status, setStatus] = useState<Status>(statusOf(f))
  const [severity, setSeverity] = useState<Severity>(f.severity)
  const [note, setNote] = useState('')
  const [saved, setSaved] = useState(false)
  const patch = triagePatch(f, status, severity)
  const text = note.trim()

  const save = useMutation({
    mutationFn: async () => {
      if (patch) await api.patch('/findings/{id}', { params: { id: f.id }, body: patch })
      if (text) await api.post('/findings/{id}/notes', { params: { id: f.id }, body: { text } })
    },
    onSuccess: () => {
      setNote('')
      setSaved(true)
    },
    // Refetch after any outcome: a patch may have landed before the note failed.
    onSettled: () => qc.invalidateQueries({ queryKey: findingsKey }),
  })

  const submit = (e: FormEvent) => {
    e.preventDefault()
    setSaved(false)
    save.mutate()
  }
  // The current status stays selectable even when users can't set it (inactive).
  const options = settableStatuses.includes(statusOf(f)) ? settableStatuses : [statusOf(f), ...settableStatuses]

  return (
    <form aria-label="Triage" onSubmit={submit} className="flex flex-col gap-3.5">
      <PanelHeading>Triage</PanelHeading>
      <div className="flex flex-wrap gap-3">
        <Field label="Status" className="flex-[1_1_140px]">
          <select
            className={inputClass}
            value={status}
            onChange={(e) => {
              setStatus(e.target.value as Status)
              setSaved(false)
            }}
          >
            {options.map((s) => (
              <option key={s} value={s} disabled={!settableStatuses.includes(s)}>
                {statusLabel[s]}
              </option>
            ))}
          </select>
        </Field>
        <Field label="Severity" className="flex-[1_1_140px]">
          <select
            className={inputClass}
            value={severity}
            onChange={(e) => {
              setSeverity(e.target.value as Severity)
              setSaved(false)
            }}
          >
            {severities.map((s) => (
              <option key={s} value={s}>
                {s}
              </option>
            ))}
          </select>
        </Field>
      </div>
      <Field label="Add a note">
        <textarea
          className={textareaClass}
          rows={3}
          value={note}
          maxLength={20000}
          onChange={(e) => {
            setNote(e.target.value)
            setSaved(false)
          }}
        />
      </Field>
      {save.error && <Alert>{save.error.message}</Alert>}
      {saved && !save.isPending && <Alert tone="ok">Saved</Alert>}
      <div className="flex justify-end">
        <Button type="submit" variant="primary" size="lg" disabled={save.isPending || (!patch && !text)}>
          Save to DefectDojo
        </Button>
      </div>
    </form>
  )
}
