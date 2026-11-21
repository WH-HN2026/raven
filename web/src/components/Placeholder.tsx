export function Placeholder({ title, task, children }: { title: string; task: string; children?: React.ReactNode }) {
  return (
    <section>
      <h1 className="text-2xl font-semibold text-ink">{title}</h1>
      <p className="mt-2 text-muted">
        Coming in roadmap task <span className="font-mono text-graphite">{task}</span>.
      </p>
      {children}
    </section>
  )
}
