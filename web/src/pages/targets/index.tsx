import { useMutation, useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'
import { api } from '../../api/client'
import { useCan } from '../../auth/hooks'
import { ExportButton } from '../../components/ExportButton'
import { PageHeader } from '../../components/PageHeader'
import { Alert, Button, Section, SectionHeading, ToggleGroup } from '../../components/ui'
import type { AppRoute } from '../types'
import { ManualForm } from './ManualForm'
import { ScopeEditor } from './ScopeEditor'
import { TargetsTable } from './TargetsTable'
import { targetsKey } from './ui'
import { UploadPanel } from './UploadPanel'

type Mode = 'manual' | 'upload'

export function TargetsPage() {
  const qc = useQueryClient()
  const canWrite = useCan('targets:write')
  const canImport = useCan('import')
  const modes: { value: Mode; label: string }[] = [
    ...(canWrite ? [{ value: 'manual' as const, label: 'Enter manually' }] : []),
    ...(canImport ? [{ value: 'upload' as const, label: 'Upload CSV / JSON' }] : []),
  ]
  const [picked, setPicked] = useState<Mode | null>(null)
  const mode = picked ?? modes[0]?.value

  const importDojo = useMutation({
    mutationFn: () => api.post('/targets/import-dojo'),
    onSuccess: () => qc.invalidateQueries({ queryKey: targetsKey }),
  })

  return (
    <>
      <PageHeader title="Targets & scope">
        {canImport && (
          <Button
            variant="primary"
            size="md"
            disabled={importDojo.isPending}
            onClick={() => importDojo.mutate()}
          >
            {importDojo.isPending ? 'Importing…' : 'Import from Dojo'}
          </Button>
        )}
        <ExportButton kind="targets" onDark />
      </PageHeader>
      <Section className="flex flex-col gap-6">
        {importDojo.error && <Alert>{importDojo.error.message}</Alert>}
        {importDojo.isSuccess && (
          <Alert tone="ok">
            {importDojo.data.imported > 0
              ? `Imported ${importDojo.data.imported} target${importDojo.data.imported === 1 ? '' : 's'}`
              : 'No targets in Dojo'}
            {importDojo.data.skipped > 0 && ` (${importDojo.data.skipped} skipped)`}
          </Alert>
        )}
        <div className="flex flex-wrap items-start gap-12">
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
