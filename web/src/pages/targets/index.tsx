import { useCan } from '../../auth/hooks'
import type { AppRoute } from '../types'
import { ManualForm } from './ManualForm'
import { ScopeEditor } from './ScopeEditor'
import { TargetsTable } from './TargetsTable'
import { UploadPanel } from './UploadPanel'

export function TargetsPage() {
  const canWrite = useCan('targets:write')
  const canImport = useCan('import')
  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-semibold text-ink">Targets &amp; Scope</h1>
      {(canWrite || canImport) && (
        <div className="grid gap-4 xl:grid-cols-2">
          {canWrite && <ManualForm />}
          {canImport && <UploadPanel />}
        </div>
      )}
      <TargetsTable />
      <ScopeEditor />
    </div>
  )
}

export const routes: AppRoute[] = [
  {
    path: '/targets',
    element: <TargetsPage />,
    perm: 'read',
    nav: { label: 'Targets & Scope', order: 70 },
  },
]
