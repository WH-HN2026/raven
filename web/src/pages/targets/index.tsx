import { useState } from 'react'
import { useCan } from '../../auth/hooks'
import { ExportButton } from '../../components/ExportButton'
import { PageHeader } from '../../components/PageHeader'
import { Section, SectionHeading, ToggleGroup } from '../../components/ui'
import type { AppRoute } from '../types'
import { ManualForm } from './ManualForm'
import { ScopeEditor } from './ScopeEditor'
import { TargetsTable } from './TargetsTable'
import { UploadPanel } from './UploadPanel'

type Mode = 'manual' | 'upload'

export function TargetsPage() {
  const canWrite = useCan('targets:write')
  const canImport = useCan('import')
  const modes: { value: Mode; label: string }[] = [
    ...(canWrite ? [{ value: 'manual' as const, label: 'Enter manually' }] : []),
    ...(canImport ? [{ value: 'upload' as const, label: 'Upload CSV / JSON' }] : []),
  ]
  const [picked, setPicked] = useState<Mode | null>(null)
  const mode = picked ?? modes[0]?.value
  return (
    <>
      <PageHeader title="Targets & scope" crumbs={[{ label: 'Targets & scope' }]}>
        <ExportButton kind="targets" onDark />
      </PageHeader>
      <Section className="flex flex-wrap items-start gap-12">
        {mode && (
          <section className="flex min-w-0 flex-[1_1_520px] flex-col gap-5">
            <SectionHeading>Add targets</SectionHeading>
            {modes.length > 1 && <ToggleGroup label="Add targets" options={modes} value={mode} onChange={setPicked} />}
            {mode === 'manual' ? <ManualForm /> : <UploadPanel />}
          </section>
        )}
        <div className="flex min-w-0 flex-[1_1_520px] flex-col gap-10">
          <ScopeEditor />
        </div>
      </Section>
      <Section band className="pb-16">
        <TargetsTable />
      </Section>
    </>
  )
}

export const routes: AppRoute[] = [
  {
    path: '/targets',
    element: <TargetsPage />,
    perm: 'read',
    nav: { label: 'Targets', order: 70 },
  },
]
