import { useCan } from '../../auth/hooks'
import { PageHeader } from '../../components/PageHeader'
import { Section, SectionHeading } from '../../components/ui'
import type { AppRoute } from '../types'
import { ExportPanel } from './ExportPanel'
import { ImportPanel } from './ImportPanel'

export function ExchangePage() {
  const canImport = useCan('import')
  return (
    <>
      <PageHeader title="Import / Export" crumbs={[{ label: 'Import / Export' }]} />
      {canImport && (
        <Section className="flex flex-col gap-5">
          <SectionHeading>Import scan results</SectionHeading>
          <ImportPanel />
        </Section>
      )}
      <Section band={canImport} className="flex flex-col gap-5 pb-16">
        <SectionHeading>Export</SectionHeading>
        <ExportPanel />
      </Section>
    </>
  )
}

export const routes: AppRoute[] = [
  {
    path: '/exchange',
    element: <ExchangePage />,
    perm: 'export',
    nav: { label: 'Import/Export', order: 100 },
  },
]
