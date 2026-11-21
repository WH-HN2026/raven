import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useState, type FormEvent } from 'react'
import { useNavigate, useParams } from 'react-router'
import { ApiError, api, type Schemas } from '../../api/client'
import { useCan } from '../../auth/hooks'
import { PageHeader } from '../../components/PageHeader'
import { Alert, Button, ErrorText, Field, Section, SectionHeading, inputClass } from '../../components/ui'
import { ScopeList } from '../targets/ScopeEditor'
import { NUCLEI_TAGS, PROFILE_DEFAULTS, batchMinutes, checkPorts, profileScopeKey, profilesKey, useProfiles, type Profile, type StageName } from './ui'
import { WorkflowBuilder } from './WorkflowBuilder'

type Input = Schemas['ProfileInput']

/** /profiles/new and /profiles/:id. Viewers see the same form, disabled. */
export function ProfileEditorPage() {
  const { id } = useParams()
  const isNew = id === undefined
  const profiles = useProfiles()
  const profile = isNew ? undefined : profiles.data?.items.find((p) => String(p.id) === id)
  const title = isNew ? 'New profile' : (profile?.name ?? `Profile ${id}`)

  return (
    <>
      <PageHeader
        title={title}
        crumbs={[{ label: 'Profiles', to: '/profiles' }, { label: title }]}
      />
      {profiles.error && (
        <Section>
          <ErrorText>Cannot load profiles: {profiles.error.message}</ErrorText>
        </Section>
      )}
      {!isNew && profiles.data && !profile && (
        <Section>
          <ErrorText>Profile {id} not found</ErrorText>
        </Section>
      )}
      {(isNew || profile) && (
        <Section className="flex flex-wrap items-start gap-12">
          <div className="flex min-w-0 flex-[1_1_520px] flex-col gap-5">
            <SectionHeading>Settings</SectionHeading>
            <ProfileForm key={profile?.id ?? 'new'} profile={profile} />
          </div>
          {profile && (
            <div className="flex min-w-0 flex-[1_1_420px] flex-col gap-10">
              <ProfileScope profileId={profile.id} />
            </div>
          )}
        </Section>
      )}
    </>
  )
}

function ProfileForm({ profile }: { profile?: Profile }) {
  const canWrite = useCan('profiles:write')
  const qc = useQueryClient()
  const navigate = useNavigate()
  const [name, setName] = useState(profile?.name ?? '')
  const [ports, setPorts] = useState(profile?.ports ?? '')
  const [nmapRate, setNmapRate] = useState(String(profile?.nmap_max_rate ?? PROFILE_DEFAULTS.nmap_max_rate))
  const [nucleiRate, setNucleiRate] = useState(String(profile?.nuclei_rate ?? PROFILE_DEFAULTS.nuclei_rate))
  const [tags, setTags] = useState<string[]>(profile?.nuclei_tags ?? [])
  const [miss, setMiss] = useState(String(profile?.miss_threshold ?? PROFILE_DEFAULTS.miss_threshold))
  const [batch, setBatch] = useState(String(batchMinutes(profile?.target_batch_seconds ?? PROFILE_DEFAULTS.target_batch_seconds)))
  const [enabled, setEnabled] = useState(profile?.enabled ?? true)
  const [stages, setStages] = useState<StageName[]>(
    profile?.stages && profile.stages.length > 0 ? profile.stages : [...PROFILE_DEFAULTS.stages],
  )
  const [clientErr, setClientErr] = useState<string | null>(null)
  const [saved, setSaved] = useState(false)

  const save = useMutation({
    mutationFn: (body: Input) =>
      profile ? api.put('/profiles/{id}', { params: { id: profile.id }, body }) : api.post('/profiles', { body }),
    onSuccess: (p) => {
      void qc.invalidateQueries({ queryKey: profilesKey })
      if (profile) setSaved(true)
      else void navigate(`/profiles/${p.id}`)
    },
  })

  const onSubmit = (e: FormEvent) => {
    e.preventDefault()
    setSaved(false)
    const spec = ports.trim()
    const batchSeconds = Math.round(Number(batch) * 60)
    const numbers: [string, string, number, number][] = [
      ['nmap max rate', nmapRate, 1, 1_000_000],
      ['nuclei rate', nucleiRate, 1, Infinity],
      ['miss threshold', miss, 1, Infinity],
    ]
    let err = name.trim() ? checkPorts(spec) : 'Name is required'
    for (const [label, v, min, max] of numbers) {
      const n = Number(v)
      if (!err && !(v.trim() !== '' && Number.isInteger(n) && n >= min && n <= max))
        err = `${label} must be a whole number${max === Infinity ? ' ≥ 1' : ` between ${min} and ${max}`}`
    }
    if (!err && (batchSeconds < 1 || !Number.isFinite(batchSeconds) || batchSeconds > 2_147_483_647))
      err = 'Invalid batch duration'
    setClientErr(err)
    if (err) return
    save.mutate({
      name: name.trim(),
      ports: spec,
      nmap_max_rate: Number(nmapRate),
      nuclei_rate: Number(nucleiRate),
      nuclei_tags: tags,
      miss_threshold: Number(miss),
      target_batch_seconds: batchSeconds,
      enabled,
      stages,
    })
  }

  const toggleTag = (t: string) => setTags((cur) => (cur.includes(t) ? cur.filter((x) => x !== t) : [...cur, t]))
  const serverErr = save.error
  const serverMsg = serverErr instanceof ApiError ? serverErr.message : serverErr?.message

  return (
    <form aria-label="Profile" onSubmit={onSubmit} className="flex flex-col gap-4">
      <fieldset disabled={!canWrite} className="m-0 flex flex-col gap-4 border-0 p-0">
        <Field label="Name">
          <input className={inputClass} value={name} onChange={(e) => setName(e.target.value)} />
        </Field>
        <Field label="Ports">
          <input
            className={inputClass + ' font-mono'}
            placeholder="22,80,443,8000-8100"
            value={ports}
            onChange={(e) => setPorts(e.target.value)}
          />
        </Field>
        <div className="flex flex-wrap gap-4">
          <Field label="nmap max rate (pps)" className="flex-[1_1_160px]">
            <input className={inputClass} type="number" min={1} max={1000000} value={nmapRate} onChange={(e) => setNmapRate(e.target.value)} />
          </Field>
          <Field label="nuclei rate (req/s)" className="flex-[1_1_160px]">
            <input className={inputClass} type="number" min={1} value={nucleiRate} onChange={(e) => setNucleiRate(e.target.value)} />
          </Field>
        </div>
        <div className="flex flex-col gap-2">
          <span className="text-[13px] font-medium">Nuclei tags</span>
          <div role="group" aria-label="Nuclei tags" className="flex flex-wrap gap-4">
            {NUCLEI_TAGS.map((t) => (
              <label key={t} className="flex items-center gap-2 font-mono text-sm">
                <input type="checkbox" checked={tags.includes(t)} onChange={() => toggleTag(t)} />
                {t}
              </label>
            ))}
          </div>
        </div>
        <div className="flex flex-wrap gap-4">
          <Field label="Miss threshold (runs)" className="flex-[1_1_160px]">
            <input className={inputClass} type="number" min={1} value={miss} onChange={(e) => setMiss(e.target.value)} />
          </Field>
          <Field label="Batch duration (min)" className="flex-[1_1_160px]">
            <input className={inputClass} type="number" min={0} step="any" value={batch} onChange={(e) => setBatch(e.target.value)} />
          </Field>
        </div>
        <label className="flex items-center gap-2 text-sm font-medium">
          <input type="checkbox" role="switch" className="peer sr-only" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} />
          <span
            aria-hidden="true"
            className="flex h-5 w-9 items-center border border-line-strong bg-band p-0.5 before:size-3.5 before:bg-ink peer-checked:justify-end peer-checked:bg-black peer-checked:before:bg-white peer-focus-visible:outline-2 peer-focus-visible:outline-offset-2 peer-focus-visible:outline-red peer-disabled:opacity-60"
          />
          Profile enabled
        </label>
      </fieldset>
      <div className="flex flex-col gap-3 border-t border-line pt-5">
        <SectionHeading size="sm">Workflow</SectionHeading>
        <WorkflowBuilder value={stages} onChange={setStages} disabled={!canWrite} />
      </div>
      {(clientErr || serverMsg) && <Alert>{clientErr ?? serverMsg}</Alert>}
      {saved && <Alert tone="ok">Saved</Alert>}
      {canWrite && (
        <div className="flex flex-wrap items-start gap-2">
          <Button type="submit" variant="primary" disabled={save.isPending}>
            {profile ? 'Save profile' : 'Create profile'}
          </Button>
          {profile && <DeleteProfile profile={profile} />}
        </div>
      )}
    </form>
  )
}

function DeleteProfile({ profile }: { profile: Profile }) {
  const qc = useQueryClient()
  const navigate = useNavigate()
  const [confirming, setConfirming] = useState(false)
  const del = useMutation({
    mutationFn: () => api.delete('/profiles/{id}', { params: { id: profile.id } }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: profilesKey })
      void navigate('/profiles')
    },
  })
  return (
    <div className="flex flex-col gap-2">
      {!confirming ? (
        <Button type="button" variant="danger" onClick={() => setConfirming(true)}>
          Delete profile
        </Button>
      ) : (
        <div role="dialog" aria-label="Confirm delete" className="flex flex-col gap-3 border-2 border-red bg-white p-4">
          <p className="m-0 font-medium">Delete profile {profile.name}?</p>
          <div className="flex gap-2">
            <Button type="button" onClick={() => setConfirming(false)} disabled={del.isPending}>
              Cancel
            </Button>
            <Button type="button" variant="primary" onClick={() => del.mutate()} disabled={del.isPending}>
              Confirm delete
            </Button>
          </div>
        </div>
      )}
      {del.error && <Alert>Delete failed: {del.error.message}</Alert>}
    </div>
  )
}

/** Profile-specific include / exclude entries (scope:write). */
function ProfileScope({ profileId }: { profileId: number }) {
  const canEdit = useCan('scope:write')
  const q = useQuery({
    queryKey: profileScopeKey(profileId),
    queryFn: () => api.get('/scope', { query: { profile_id: profileId, limit: 1000 } }),
  })
  const items = q.data?.items ?? []
  return (
    <>
      {q.error && <ErrorText>Cannot load scope: {q.error.message}</ErrorText>}
      <ScopeList
        list="include"
        title="Profile include"
        items={items.filter((e) => e.list === 'include')}
        canEdit={canEdit}
        profileId={profileId}
      />
      <ScopeList
        list="exclude"
        title="Profile exclude"
        items={items.filter((e) => e.list === 'exclude')}
        canEdit={canEdit}
        profileId={profileId}
      />
    </>
  )
}
