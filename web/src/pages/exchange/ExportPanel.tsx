import { useState } from 'react'
import { exportHref, type ExportFormat, type ExportKind } from '../../components/ExportButton'
import { Field, ToggleGroup, buttonClass, inputClass } from '../../components/ui'

const kinds: { value: ExportKind; label: string }[] = [
  { value: 'hosts', label: 'Hosts' },
  { value: 'services', label: 'Services' },
  { value: 'findings', label: 'Findings' },
  { value: 'changes', label: 'Changes (latest runs)' },
  { value: 'targets', label: 'Targets' },
]

const formats: { value: ExportFormat; label: string }[] = [
  { value: 'csv', label: 'CSV' },
  { value: 'json', label: 'JSON' },
]

/** Pick a dataset + format → download GET /api/export/{kind} (no filters). */
export function ExportPanel() {
  const [kind, setKind] = useState<ExportKind>('hosts')
  const [format, setFormat] = useState<ExportFormat>('csv')
  return (
    <div className="flex flex-wrap items-end gap-4">
      <Field label="Data" className="flex-[1_1_220px]">
        <select className={inputClass} value={kind} onChange={(e) => setKind(e.target.value as ExportKind)}>
          {kinds.map((k) => (
            <option key={k.value} value={k.value}>
              {k.label}
            </option>
          ))}
        </select>
      </Field>
      <div className="flex flex-col gap-1.5">
        <span className="text-[13px] font-medium">Format</span>
        <ToggleGroup label="Format" options={formats} value={format} onChange={setFormat} />
      </div>
      <a href={exportHref(kind, format)} download className={buttonClass('primary', 'md')}>
        Download
      </a>
    </div>
  )
}
