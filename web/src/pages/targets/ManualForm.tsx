import { useMutation, useQueryClient } from '@tanstack/react-query'
import { useState, type FormEvent } from 'react'
import { ApiError, api, type Schemas } from '../../api/client'
import { LineErrors } from '../../components/LineErrors'
import { Alert, Button, Field, inputClass, textareaClass } from '../../components/ui'
import { splitTags, targetsKey } from './ui'

export interface InputLine {
  /** 1-based line number in the textarea. */
  line: number
  value: string
}

/** Non-blank textarea lines, each one target, with their textarea line numbers. */
export function parseLines(text: string): InputLine[] {
  return text
    .split('\n')
    .map((v, i) => ({ line: i + 1, value: v.trim() }))
    .filter((l) => l.value !== '')
}

/** Maps the API's item-indexed errors (line = 1-based item index) to textarea lines. */
export function toTextareaErrors(errors: Schemas['LineError'][], lines: InputLine[]): Schemas['LineError'][] {
  return errors.map((e) => ({ line: lines[e.line - 1]?.line ?? e.line, message: e.message }))
}

function isInputErrors(b: unknown): b is Schemas['TargetInputErrors'] {
  return typeof b === 'object' && b !== null && Array.isArray((b as { errors?: unknown }).errors)
}

/** Manual entry: one target per line, shared optional tags and note. */
export function ManualForm() {
  const qc = useQueryClient()
  const [text, setText] = useState('')
  const [tags, setTags] = useState('')
  const [note, setNote] = useState('')
  const [sent, setSent] = useState<InputLine[]>([])

  const create = useMutation({
    mutationFn: (lines: InputLine[]) => {
      const t = splitTags(tags)
      return api.post('/targets', {
        body: {
          targets: lines.map((l) => ({
            value: l.value,
            ...(t.length ? { tags: t } : {}),
            ...(note.trim() ? { note: note.trim() } : {}),
          })),
        },
      })
    },
    onSuccess: () => {
      setText('')
      void qc.invalidateQueries({ queryKey: targetsKey })
    },
  })

  const onSubmit = (e: FormEvent) => {
    e.preventDefault()
    const lines = parseLines(text)
    if (lines.length === 0) return
    setSent(lines)
    create.mutate(lines)
  }

  const err = create.error
  const lineErrors =
    err instanceof ApiError && err.status === 400 && isInputErrors(err.body)
      ? toTextareaErrors(err.body.errors, sent)
      : null
  const byLine = new Map(sent.map((l) => [l.line, l.value]))

  return (
    <form onSubmit={onSubmit} className="flex flex-col gap-4">
      <Field label="Targets, one per line">
        <textarea
          rows={5}
          className={textareaClass + ' font-mono'}
          placeholder={'10.0.0.0/24\n10.0.0.7\nwordpress.lab'}
          value={text}
          onChange={(e) => setText(e.target.value)}
        />
      </Field>
      <div className="flex flex-wrap gap-4">
        <Field label="Tags" className="flex-[1_1_200px]">
          <input className={inputClass} placeholder="lab, web" value={tags} onChange={(e) => setTags(e.target.value)} />
        </Field>
        <Field label="Note" className="flex-[1_1_200px]">
          <input className={inputClass} value={note} onChange={(e) => setNote(e.target.value)} />
        </Field>
      </div>
      {lineErrors && (
        <LineErrors
          title="Nothing was added; fix these lines:"
          errors={lineErrors}
          inputOf={(line) => byLine.get(line)}
        />
      )}
      {err && !lineErrors && <Alert>{err.message}</Alert>}
      {create.isSuccess && (
        <Alert tone="ok">
          Added {create.data.total} target{create.data.total === 1 ? '' : 's'}.
        </Alert>
      )}
      <div className="flex justify-end">
        <Button
          variant="secondary"
          size="lg"
          disabled={create.isPending || text === ''}
          onClick={() => {
            setText('')
            create.reset()
          }}
        >
          Clear
        </Button>
        <Button type="submit" variant="primary" size="lg" disabled={create.isPending || parseLines(text).length === 0}>
          {create.isPending ? 'Adding…' : 'Add targets'}
        </Button>
      </div>
    </form>
  )
}
