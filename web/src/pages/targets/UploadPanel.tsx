import { useMutation, useQueryClient } from '@tanstack/react-query'
import { useRef, useState } from 'react'
import { upload } from '../../api/client'
import { LineErrors } from '../../components/LineErrors'
import { Alert, Button, EmptyRow, Table, Td, Th, THeadRow, Tr } from '../../components/ui'
import { targetsKey } from './ui'

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

  const clear = () => {
    reset()
    if (fileRef.current) fileRef.current.value = ''
  }

  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-wrap items-center gap-4 border border-dashed border-line-strong px-5 py-[18px]">
        <label className="flex flex-[1_1_240px] flex-col gap-1.5 text-[13px] font-medium">
          File
          <input
            ref={fileRef}
            type="file"
            accept=".csv,.txt,.json,text/csv,application/json,text/plain"
            className="block text-sm font-normal file:mr-4 file:h-11 file:cursor-pointer file:border file:border-line-strong file:bg-white file:px-[18px] file:text-sm file:text-ink hover:file:bg-band"
            onChange={(e) => pick(e.target.files?.[0] ?? null)}
          />
        </label>
        <details className="text-sm">
          <summary className="cursor-pointer underline decoration-red underline-offset-[3px]">Sample files</summary>
          <div className="mt-2 flex flex-col gap-2">
            <span className="text-xs font-medium tracking-[0.06em] text-muted uppercase">CSV</span>
            <pre className="m-0 overflow-x-auto bg-band p-2 font-mono text-xs">{CSV_EXAMPLE}</pre>
            <span className="text-xs font-medium tracking-[0.06em] text-muted uppercase">JSON</span>
            <pre className="m-0 overflow-x-auto bg-band p-2 font-mono text-xs">{JSON_EXAMPLE}</pre>
          </div>
        </details>
      </div>

      {preview.isPending && <p className="m-0 text-sm text-muted">Parsing…</p>}
      {err && <Alert>{err.message}</Alert>}
      {importer.isSuccess && (
        <Alert tone="ok">
          Imported {importer.data.created} target{importer.data.created === 1 ? '' : 's'}
          {importer.data.errors.length > 0 && ` (${importer.data.errors.length} bad lines skipped)`}.
        </Alert>
      )}

      {p && file && (
        <div className="flex flex-col gap-4">
          <LineErrors title="Skipped lines" errors={p.errors} />
          <div className="bg-band px-5 py-4">
            <div className="flex flex-wrap justify-between gap-3 border-b-2 border-black pb-2 text-[13px]">
              <span className="font-bold tracking-[0.06em] uppercase">Preview</span>
              <span>
                <span className="font-mono">{file.name}</span> · {p.source.toUpperCase()} · {p.targets.length} valid ·{' '}
                {p.errors.length} error{p.errors.length === 1 ? '' : 's'}
              </span>
            </div>
            <div className="max-h-64 overflow-y-auto">
              <Table label="Preview">
                <thead className="sr-only">
                  <THeadRow>
                    <Th>Value</Th>
                    <Th>Kind</Th>
                    <Th>Tags</Th>
                    <Th>Note</Th>
                  </THeadRow>
                </thead>
                <tbody>
                  {p.targets.map((t) => (
                    <Tr key={t.kind + t.value}>
                      <Td className="font-mono">{t.value}</Td>
                      <Td className="text-[13px] text-muted">{t.kind}</Td>
                      <Td className="text-[13px]">{t.tags.join(', ')}</Td>
                      <Td className="text-[13px] text-muted">{t.note}</Td>
                    </Tr>
                  ))}
                  {p.targets.length === 0 && <EmptyRow colSpan={4}>No valid entries.</EmptyRow>}
                </tbody>
              </Table>
            </div>
          </div>
          <div className="flex justify-end">
            <Button variant="secondary" size="lg" onClick={clear}>
              Cancel
            </Button>
            <Button
              variant="primary"
              size="lg"
              disabled={p.targets.length === 0 || importer.isPending}
              onClick={() => importer.mutate(file)}
            >
              {importer.isPending
                ? 'Importing…'
                : `Import ${p.targets.length} valid entr${p.targets.length === 1 ? 'y' : 'ies'}`}
            </Button>
          </div>
        </div>
      )}
    </div>
  )
}
