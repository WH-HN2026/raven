import { PageHeader } from './PageHeader'
import { Section } from './ui'

/** A page that isn't built yet: the shared frame with the roadmap task id. */
export function Placeholder({ title, task, children }: { title: string; task: string; children?: React.ReactNode }) {
  return (
    <>
      <PageHeader title={title} crumbs={title === 'Dashboard' ? undefined : [{ label: title }]} />
      <Section>
        <p className="m-0 text-muted">
          Roadmap task <span className="font-mono text-ink">{task}</span>
        </p>
        {children}
      </Section>
    </>
  )
}
