import { useEffect, useRef, useState } from 'react'

export function useInstantFilters<F>(
  initial: F,
  onCommit: (value: F, replace: boolean) => void,
  keyOf: (value: F) => string,
  validFilters: (draft: F, applied: F) => F,
) {
  const key = keyOf(initial)
  const [state, setState] = useState({ key, expected: key, value: initial })
  const timer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined)
  const commit = useRef(onCommit)
  useEffect(() => {
    commit.current = onCommit
  }, [onCommit])
  useEffect(() => () => clearTimeout(timer.current), [key])

  const draft = state.key === key || state.expected === key ? state.value : initial
  if (state.key !== key) setState({ key, expected: key, value: draft })

  function update(value: F, debounce = false) {
    clearTimeout(timer.current)
    const applied = validFilters(value, initial)
    const expected = keyOf(applied)
    setState({ key, expected, value })
    if (expected === key) return
    const apply = () => commit.current(applied, debounce)
    if (debounce) timer.current = setTimeout(apply, 300)
    else apply()
  }

  return { draft, update }
}

// Update a page's filters and paging while preserving its independent sort.
export function listParams(current: URLSearchParams, filters: URLSearchParams): URLSearchParams {
  for (const key of ['sort', 'dir', 'order', 'tech_sort', 'tech_dir']) {
    const value = current.get(key)
    if (value !== null) filters.set(key, value)
  }
  return filters
}

export function validPortFilter(raw: string): boolean {
  const value = raw.trim()
  return value === '' || (/^\d{1,5}$/.test(value) && Number(value) <= 65535)
}

export function validIPFilter(raw: string): boolean {
  const value = raw.trim()
  if (!value) return true
  const [ip, prefix, ...rest] = value.split('/')
  if (!ip || rest.length || !/^[0-9a-fA-F:.]+$/.test(ip)) return false
  const v6 = ip.includes(':')
  if (prefix !== undefined && (!/^(0|[1-9]\d{0,2})$/.test(prefix) || Number(prefix) > (v6 ? 128 : 32))) return false
  if (!v6) {
    const octets = ip.split('.')
    return octets.length === 4 && octets.every((n) => /^(0|[1-9]\d{0,2})$/.test(n) && Number(n) <= 255)
  }
  try {
    return new URL(`http://[${ip}]/`).hostname.startsWith('[')
  } catch {
    return false
  }
}
