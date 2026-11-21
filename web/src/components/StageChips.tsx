import { Chip } from './ui'

const DEFAULT_STAGES = ['nmap', 'httpx', 'nuclei'] as const
const AGGRESSIVE_STAGES = new Set(['nuclei_active', 'nikto', 'wpscan', 'zap'])

/** True when stages are empty/unset (legacy default) or match the Default preset. */
export function isDefaultStages(stages?: readonly string[] | null): boolean {
  if (!stages || stages.length === 0) return true
  return stages.length === DEFAULT_STAGES.length && DEFAULT_STAGES.every((s, i) => stages[i] === s)
}

/** Compact stage chips for profile/run lists and run detail; collapses the Default preset to "Default". */
export function StageChips({ stages }: { stages?: readonly string[] | null }) {
  if (isDefaultStages(stages)) {
    return <Chip>Default</Chip>
  }
  return (
    <div className="flex flex-wrap gap-1">
      {stages!.map((s) => (
        <Chip key={s} mono variant={AGGRESSIVE_STAGES.has(s) ? 'filled' : 'outline'}>
          {s}
        </Chip>
      ))}
    </div>
  )
}
