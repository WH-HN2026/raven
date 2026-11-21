import { useMutation, useQueryClient } from '@tanstack/react-query'
import { useRef, useState } from 'react'
import { upload } from '../../api/client'
import { LineErrors } from '../../components/LineErrors'
import { btnPrimary, btnSecondary, card, td, th, targetsKey } from './ui'

const CSV_EXAMPLE = `value,tags,note
10.0.0.0/24,lab;web,main lab net
wordpress.lab,cms,
10.0.0.7`

const JSON_EXAMPLE = `[{"value": "10.0.0.0/24", "tags": ["lab"], "note": "main lab net"},
 {"value": "wordpress.lab"}]`

/** CSV/JSON upload: pick a file → dry-run preview → import the valid entries. */
export function UploadPanel() {
  const qc = useQueryClient()
  const fileRef = useRef<HTMLInputElement>(null)
  const [file, setFile] = useState<File | null>(null)

  const preview = useMutation({ mutationFn: (f: File) => upload('/targets/upload', f, { dry_run: true }) })
  const importer = useMutation({
    mutationFn: (f: File) => upload('/targets/upload', f),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: targetsKey })
      setFile(null)
      preview.reset()
      if (fileRef.current) fileRef.current.value = ''
    },
  })

  const pick = (f: File | null) => {
    setFile(f)
    importer.reset()
    preview.reset()
    if (f) preview.mutate(f)
  }
  const reset = () => pick(null)
  const p = preview.data
  const err = preview.error ?? importer.error

  return (
    <div className={card + ' space-y-3'}>
      <h2 className="text-lg font-semibold text-ink">Upload CSV / JSON</h2>
      <details className="text-sm text-graphite">
        <summary className="cursor-pointer">Accepted formats</summary>
        <div className="mt-2 space-y-2">
          <p>
            <b>CSV</b> (<code>.csv</code>/<code>.txt</code>): columns <code>value,tags,note</code>; the header row is
            optional, tags are separated by <code>;</code> or <code>|</code>, tags and note may be omitted, blank lines
            and <code>#</code> lines are skipped.
          </p>
          <pre className="overflow-x-auto rounded bg-canvas p-2 font-mono text-xs">{CSV_EXAMPLE}</pre>
          <p>
            <b>JSON</b> (<code>.json</code>): an array of <code>{'{value, tags?, note?, kind?}'}</code>.
          </p>
          <pre className="overflow-x-auto rounded bg-canvas p-2 font-mono text-xs">{JSON_EXAMPLE}</pre>
          <p>Max 10 MiB. Existing targets keep their entry and get the new tags merged.</p>
        </div>
      </details>
      <label className="block">
        <span className="text-sm text-graphite">File</span>
        <input
          ref={fileRef}
          type="file"
          accept=".csv,.txt,.json,text/csv,application/json,text/plain"
          className="mt-1 block text-sm"
          onChange={(e) => pick(e.target.files?.[0] ?? null)}
        />
      </label>

      {preview.isPending && <p className="text-sm text-muted">Parsing…</p>}
      {err && (
        <p role="alert" className="rounded bg-accent-light px-3 py-2 text-sm text-accent-dark">
          {err.message}
        </p>
      )}
      {importer.isSuccess && (
        <p role="status" className="text-sm text-ok">
          Imported {importer.data.created} target{importer.data.created === 1 ? '' : 's'}
          {importer.data.errors.length > 0 && ` (${importer.data.errors.length} bad lines skipped)`}.
        </p>
      )}

      {p && file && (
        <div className="space-y-3">
          <p className="text-sm text-graphite">
            Preview of <span className="font-mono">{file.name}</span> ({p.source.toUpperCase()}):{' '}
            {p.targets.length} valid entr{p.targets.length === 1 ? 'y' : 'ies'}, {p.errors.length} error
            {p.errors.length === 1 ? '' : 's'}. Nothing has been saved yet.
          </p>
          <LineErrors title="These lines will be skipped:" errors={p.errors} />
          {p.targets.length > 0 && (
            <div className="max-h-64 overflow-y-auto rounded border border-line">
              <table className="w-full text-sm">
                <thead className="sticky top-0 bg-surface">
                  <tr>
                    <th className={th}>Value</th>
                    <th className={th}>Kind</th>
                    <th className={th}>Tags</th>
                    <th className={th}>Note</th>
                  </tr>
                </thead>
                <tbody>
                  {p.targets.map((t) => (
                    <tr key={t.kind + t.value}>
                      <td className={td + ' font-mono'}>{t.value}</td>
                      <td className={td}>{t.kind}</td>
                      <td className={td}>{t.tags.join(', ')}</td>
                      <td className={td}>{t.note}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          <div className="flex gap-2">
            <button
              className={btnPrimary}
              disabled={p.targets.length === 0 || importer.isPending}
              onClick={() => importer.mutate(file)}
            >
              {importer.isPending
                ? 'Importing…'
                : `Import ${p.targets.length} valid entr${p.targets.length === 1 ? 'y' : 'ies'}`}
            </button>
            <button
              className={btnSecondary}
              onClick={() => {
                reset()
                if (fileRef.current) fileRef.current.value = ''
              }}
            >
              Cancel
            </button>
          </div>
        </div>
      )}
    </div>
  )
}
