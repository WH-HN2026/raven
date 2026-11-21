import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useRef, useState, type FormEvent } from 'react'
import { Link } from 'react-router'
import { api, upload, type Schemas } from '../../api/client'
import { Alert, Badge, Button, Field, KeyNumber, KeyNumbers, inputClass } from '../../components/ui'
import {
  IMPORT_ACCEPT,
  MAX_IMPORT_BYTES,
  dojoPush,
  fmtBytes,
  importKinds,
  kindFromName,
  kindLabel,
  statNum,
  statStrings,
  type ImportKind,
} from './ui'

/** Upload a scan-result file → POST /api/import/results → the created run's counts. */
export function ImportPanel() {
  const qc = useQueryClient()
  const fileRef = useRef<HTMLInputElement>(null)
  const [file, setFile] = useState<File | null>(null)
  const [kind, setKind] = useState<ImportKind | ''>('')
  const [profile, setProfile] = useState('')

  const profiles = useQuery({ queryKey: ['profiles', 'all'], queryFn: () => api.get('/profiles', { query: { limit: 1000 } }) })

  const importer = useMutation({
    mutationFn: (f: File) => upload('/import/results', f, undefined, { kind: kind || undefined, profile: profile || undefined }),
    onSuccess: () => {
      void qc.invalidateQueries()
      setFile(null)
      if (fileRef.current) fileRef.current.value = ''
    },
  })

  const detected = file ? kindFromName(file.name) : undefined
  const tooLarge = file !== null && file.size > MAX_IMPORT_BYTES
  const submit = (e: FormEvent) => {
    e.preventDefault()
    if (file && !tooLarge) importer.mutate(file)
  }

  return (
    <div className="flex flex-col gap-5">
      <form onSubmit={submit} className="flex flex-col gap-4">
        <div className="flex flex-wrap items-end gap-4 border border-dashed border-line-strong px-5 py-[18px]">
          <label className="flex flex-[2_1_260px] flex-col gap-1.5 text-[13px] font-medium">
            File
            <input
              ref={fileRef}
              type="file"
              accept={IMPORT_ACCEPT}
              className="block text-sm font-normal file:mr-4 file:h-11 file:cursor-pointer file:border file:border-line-strong file:bg-white file:px-[18px] file:text-sm file:text-ink hover:file:bg-band"
              onChange={(e) => {
                setFile(e.target.files?.[0] ?? null)
                importer.reset()
              }}
            />
          </label>
          <Field label="File format" className="flex-[1_1_200px]">
            <select className={inputClass} value={kind} onChange={(e) => setKind(e.target.value as ImportKind | '')}>
              <option value="">Auto-detect{detected ? ` (${kindLabel(detected)})` : ''}</option>
              {importKinds.map((k) => (
                <option key={k.value} value={k.value}>
                  {k.label}
                </option>
              ))}
            </select>
          </Field>
          <Field label="Profile" className="flex-[1_1_180px]">
            <select className={inputClass} value={profile} onChange={(e) => setProfile(e.target.value)}>
              <option value="">default</option>
              {(profiles.data?.items ?? [])
                .filter((p) => p.name !== 'default')
                .map((p) => (
                  <option key={p.id} value={String(p.id)}>
                    {p.name}
                  </option>
                ))}
            </select>
          </Field>
        </div>
        {file && (
          <p className="m-0 text-sm text-muted">
            <span className="font-mono text-ink">{file.name}</span> · {fmtBytes(file.size)}
          </p>
        )}
        {tooLarge && <Alert>File is larger than 25 MiB.</Alert>}
        <div className="flex justify-end">
          <Button type="submit" variant="primary" size="lg" disabled={!file || tooLarge || importer.isPending}>
            {importer.isPending ? 'Importing…' : 'Import'}
          </Button>
        </div>
      </form>

      {importer.error && <Alert>Import failed: {importer.error.message}</Alert>}
      {importer.data && <ImportResult run={importer.data} />}
    </div>
  )
}

function ImportResult({ run }: { run: Schemas['Run'] }) {
  const warnings = statStrings(run, 'warnings')
  const reason = typeof run.stats['reason'] === 'string' ? run.stats['reason'] : ''
  const push = dojoPush(run)
  const kind = typeof run.stats['import_kind'] === 'string' ? run.stats['import_kind'] : ''
  const servicesOpen = statNum(run, 'services_open')
  return (
    <section aria-label="Import result" className="flex flex-col gap-5 bg-band px-5 py-4">
      <div className="flex flex-wrap items-center justify-between gap-3 border-b-2 border-black pb-2 text-[13px]">
        <span className="flex items-center gap-3">
          <span className="font-bold tracking-[0.06em] uppercase">Result</span>
          <Badge tone={run.status === 'done' ? 'done' : 'changed'}>{run.status}</Badge>
          {kind && <span>{kindLabel(kind)}</span>}
        </span>
        <Link to={`/runs/${run.id}`} className="font-medium">
          Run #{run.id}
        </Link>
      </div>
      <KeyNumbers min={140}>
        <KeyNumber size="md" edge="black" label="Hosts imported" value={run.hosts_total} />
        <KeyNumber size="md" edge="green" label="Hosts up" value={run.hosts_up} />
        {servicesOpen !== undefined && <KeyNumber size="md" edge="green" label="Open services" value={servicesOpen} />}
        <KeyNumber size="md" edge="black" label="In file" value={statNum(run, 'candidates') ?? 0} />
        <KeyNumber size="md" edge="rose" label="Not in scope" value={statNum(run, 'not_included') ?? 0} />
        <KeyNumber size="md" edge="red" label="Excluded" value={statNum(run, 'excluded') ?? 0} />
        <KeyNumber size="md" edge="red" label="Rejected" value={statNum(run, 'rejected') ?? 0} />
        {push && (
          <KeyNumber
            size="md"
            edge={push.failed > 0 ? 'red' : 'green'}
            label="DefectDojo push"
            value={`${push.ok} ok`}
            note={push.failed > 0 ? `${push.failed} failed` : undefined}
          />
        )}
      </KeyNumbers>
      {reason && <p className="m-0 text-sm text-muted">{reason}</p>}
      {warnings.length > 0 && (
        <div role="alert" className="border-l-2 border-red bg-white px-4 py-2.5 text-sm">
          <p className="m-0 font-medium">Warnings</p>
          <ul className="mt-1 space-y-0.5">
            {warnings.map((w, i) => (
              <li key={i} className="font-mono text-[13px]">
                {w}
              </li>
            ))}
          </ul>
        </div>
      )}
    </section>
  )
}
