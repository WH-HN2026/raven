import { ErrorText } from '../../components/ui'
import { useStages, type StageInfo, type StageName } from './ui'

export interface WorkflowBuilderProps {
  value: readonly string[]
  onChange: (stages: StageName[]) => void
  disabled?: boolean
  aggressiveAllowed?: boolean
}

function sameStageSet(a: readonly string[], b: readonly string[]): boolean {
  if (a.length !== b.length) return false
  const set = new Set(a)
  return b.every((s) => set.has(s))
}

/** Stages from `preset` that are available, allowed, and have all needs satisfied, in registry order. */
function resolvePreset(
  preset: readonly StageName[],
  registry: readonly StageInfo[],
  aggressiveAllowed: boolean,
): StageName[] {
  const wanted = new Set<string>(preset)
  const kept = new Set<string>()
  let changed = true
  while (changed) {
    changed = false
    for (const s of registry) {
      if (kept.has(s.name) || !wanted.has(s.name)) continue
      if (!s.available) continue
      if (s.aggressive && !aggressiveAllowed) continue
      if (s.needs.every((n) => kept.has(n))) {
        kept.add(s.name)
        changed = true
      }
    }
  }
  return registry.filter((s) => kept.has(s.name)).map((s) => s.name)
}

/** Remove `stageName` and every stage that transitively needs it; keep nmap and canonical order. */
function removeWithDependents(
  current: ReadonlySet<string>,
  stageName: string,
  registry: readonly StageInfo[],
): StageName[] {
  const toRemove = new Set<string>([stageName])
  let changed = true
  while (changed) {
    changed = false
    for (const s of registry) {
      if (!toRemove.has(s.name) && s.needs.some((n) => toRemove.has(n))) {
        toRemove.add(s.name)
        changed = true
      }
    }
  }
  return registry
    .filter((s) => s.name === 'nmap' || (current.has(s.name) && !toRemove.has(s.name)))
    .map((s) => s.name)
}

function addStage(
  current: ReadonlySet<string>,
  stageName: StageName,
  registry: readonly StageInfo[],
): StageName[] {
  const next = new Set(current)
  next.add('nmap')
  next.add(stageName)
  return registry.filter((s) => next.has(s.name)).map((s) => s.name)
}

export function WorkflowBuilder({
  value,
  onChange,
  disabled = false,
  aggressiveAllowed = true,
}: WorkflowBuilderProps) {
  const q = useStages()
  if (q.error) return <ErrorText>Cannot load stages: {q.error.message}</ErrorText>
  if (!q.data) return <p className="m-0 text-sm text-muted">Loading stages…</p>

  const { stages, presets } = q.data
  const active = new Set<string>(['nmap', ...value])
  const defaultStages = stages.filter((s) => !s.aggressive)
  const aggressiveStages = stages.filter((s) => s.aggressive)

  const defaultPreset = resolvePreset(presets.default, stages, aggressiveAllowed)
  const aggressivePreset = resolvePreset(presets.aggressive, stages, aggressiveAllowed)
  const defaultSet = new Set<string>(defaultPreset)
  const aggressiveAdds = aggressivePreset.some((s) => !defaultSet.has(s))

  const isDefaultActive = sameStageSet(value, defaultPreset)
  const isAggressiveActive = aggressiveAdds && sameStageSet(value, aggressivePreset)

  const toggle = (stage: StageInfo, checked: boolean) => {
    if (disabled || stage.name === 'nmap' || !stage.available) return
    if (stage.aggressive && !aggressiveAllowed) return
    if (checked) {
      if (!stage.needs.every((n) => active.has(n))) return
      onChange(addStage(active, stage.name, stages))
    } else {
      onChange(removeWithDependents(active, stage.name, stages))
    }
  }

  return (
    <div className="flex flex-col gap-4">
      {!disabled && (
        <div role="group" aria-label="Workflow presets" className="flex flex-wrap items-center">
          <button
            type="button"
            aria-pressed={isDefaultActive}
            onClick={() => onChange(defaultPreset)}
            className={
              'h-9 border border-black px-3.5 text-[13px] font-medium ' +
              (isDefaultActive ? 'bg-black text-white' : 'bg-white text-ink hover:bg-band')
            }
          >
            Default
          </button>
          <button
            type="button"
            aria-pressed={isAggressiveActive}
            disabled={!aggressiveAdds}
            onClick={() => onChange(aggressivePreset)}
            className={
              'h-9 border border-l-0 border-black px-3.5 text-[13px] font-medium disabled:cursor-not-allowed disabled:opacity-50 ' +
              (isAggressiveActive ? 'bg-red text-white' : 'bg-white text-ink hover:bg-band')
            }
          >
            Aggressive
          </button>
        </div>
      )}

      <div className="flex flex-wrap items-stretch gap-2" role="group" aria-label="Default stages">
        {defaultStages.map((stage, i) => (
          <div key={stage.name} className="flex items-center gap-2">
            {i > 0 && (
              <span aria-hidden="true" className="font-mono text-sm text-muted select-none">
                →
              </span>
            )}
            <StageCard
              stage={stage}
              checked={stage.name === 'nmap' ? true : active.has(stage.name)}
              active={active}
              disabled={disabled}
              aggressiveAllowed={aggressiveAllowed}
              onToggle={(checked) => toggle(stage, checked)}
            />
          </div>
        ))}
      </div>

      {aggressiveStages.length > 0 && (
        <div className="flex flex-col gap-2 border-l-2 border-red pl-4" role="group" aria-label="Aggressive">
          <div className="flex items-center gap-2 text-xs font-medium tracking-[0.06em] text-red uppercase">
            <span aria-hidden="true" className="size-2 flex-none bg-red" />
            Aggressive
          </div>
          <div className="flex flex-wrap items-stretch gap-2">
            {aggressiveStages.map((stage) => (
              <StageCard
                key={stage.name}
                stage={stage}
                checked={active.has(stage.name)}
                active={active}
                disabled={disabled}
                aggressiveAllowed={aggressiveAllowed}
                onToggle={(checked) => toggle(stage, checked)}
              />
            ))}
          </div>
        </div>
      )}
    </div>
  )
}

function StageCard({
  stage,
  checked,
  active,
  disabled,
  aggressiveAllowed,
  onToggle,
}: {
  stage: StageInfo
  checked: boolean
  active: ReadonlySet<string>
  disabled: boolean
  aggressiveAllowed: boolean
  onToggle: (checked: boolean) => void
}) {
  const isLocked = stage.name === 'nmap'
  const missingNeeds = stage.needs.filter((n) => !active.has(n))
  const restricted = stage.aggressive && !aggressiveAllowed
  const switchDisabled = disabled || isLocked || !stage.available || restricted || missingNeeds.length > 0

  let note: string | null = null
  if (!stage.available) note = 'Not available'
  else if (missingNeeds.length > 0) note = `needs ${missingNeeds.join(', ')}`
  else if (restricted) note = 'Admin only'
  else if (isLocked) note = 'Always on'

  const borderClass = stage.aggressive
    ? 'border border-line border-l-2 border-l-red'
    : checked
      ? 'border border-line-strong'
      : 'border border-line'
  const bgClass = !stage.available || missingNeeds.length > 0 || restricted ? 'bg-band' : 'bg-white'

  return (
    <div className={`flex min-w-[132px] flex-col justify-between gap-2 px-3 py-2.5 ${borderClass} ${bgClass}`}>
      <label className="flex items-center justify-between gap-3">
        <span className="font-mono text-sm font-medium text-ink">{stage.name}</span>
        <input
          type="checkbox"
          role="switch"
          className="peer sr-only"
          checked={checked}
          disabled={switchDisabled}
          onChange={(e) => onToggle(e.target.checked)}
        />
        <span
          aria-hidden="true"
          className="flex h-5 w-9 flex-none items-center border border-line-strong bg-band p-0.5 before:size-3.5 before:bg-ink peer-checked:justify-end peer-checked:bg-black peer-checked:before:bg-white peer-focus-visible:outline-2 peer-focus-visible:outline-offset-2 peer-focus-visible:outline-red peer-disabled:opacity-60"
        />
      </label>
      {note && <span className="text-xs text-muted">{note}</span>}
    </div>
  )
}
