// Small typed fetch wrapper over the generated OpenAPI types (schema.d.ts).
// It always sends the session cookie and, on unsafe methods, the CSRF header
// the backend requires (see internal/auth/middleware.go).
import type { components, paths } from './schema'

export type Schemas = components['schemas']

type Method = 'get' | 'post' | 'put' | 'patch' | 'delete'
type Op<P extends keyof paths, M extends Method> = paths[P][M]

type JsonOf<R> = R extends { content: { 'application/json': infer T } } ? T : void
type Responses<O> = O extends { responses: infer R } ? R : never
type SuccessOf<O> =
  Responses<O> extends { 200: infer R }
    ? JsonOf<R>
    : Responses<O> extends { 201: infer R }
      ? JsonOf<R>
      : Responses<O> extends { 202: infer R }
        ? JsonOf<R>
        : void
type BodyOf<O> = O extends { requestBody: { content: { 'application/json': infer B } } } ? B : never
type QueryOf<O> = O extends { parameters: { query?: infer Q } } ? Q : never

// Paths that support method M.
type PathsWith<M extends Method> = {
  [P in keyof paths]: paths[P][M] extends undefined | never ? never : P
}[keyof paths]

export interface RequestOptions<O> {
  params?: Record<string, string | number>
  query?: QueryOf<O>
  body?: BodyOf<O>
  signal?: AbortSignal
}

export class ApiError extends Error {
  readonly status: number
  readonly code: string
  constructor(status: number, code: string, message: string) {
    super(message)
    this.status = status
    this.code = code
  }
}

export const CSRF_HEADER = 'X-ASI-CSRF'

export async function request<P extends PathsWith<M>, M extends Method>(
  method: M,
  path: P,
  opts: RequestOptions<Op<P, M>> = {},
): Promise<SuccessOf<Op<P, M>>> {
  let url = '/api' + String(path).replace(/\{(\w+)\}/g, (_, k: string) => {
    const v = opts.params?.[k]
    if (v === undefined) throw new Error(`missing path param ${k}`)
    return encodeURIComponent(String(v))
  })
  if (opts.query) {
    const qs = new URLSearchParams()
    for (const [k, v] of Object.entries(opts.query as Record<string, unknown>)) {
      if (v !== undefined && v !== null && v !== '') qs.set(k, String(v))
    }
    const s = qs.toString()
    if (s) url += '?' + s
  }
  const headers: Record<string, string> = { Accept: 'application/json' }
  if (method !== 'get') headers[CSRF_HEADER] = '1'
  if (opts.body !== undefined) headers['Content-Type'] = 'application/json'

  const res = await fetch(url, {
    method: method.toUpperCase(),
    headers,
    credentials: 'same-origin',
    body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
    signal: opts.signal,
  })
  if (!res.ok) {
    let code = 'http_' + res.status
    let message = res.statusText
    try {
      const e = (await res.json()) as Schemas['Error']
      code = e.error.code
      message = e.error.message
    } catch {
      // non-JSON error body
    }
    throw new ApiError(res.status, code, message)
  }
  if (res.status === 204) return undefined as SuccessOf<Op<P, M>>
  return (await res.json()) as SuccessOf<Op<P, M>>
}

export const api = {
  get: <P extends PathsWith<'get'>>(path: P, opts?: RequestOptions<Op<P, 'get'>>) => request('get', path, opts),
  post: <P extends PathsWith<'post'>>(path: P, opts?: RequestOptions<Op<P, 'post'>>) => request('post', path, opts),
  put: <P extends PathsWith<'put'>>(path: P, opts?: RequestOptions<Op<P, 'put'>>) => request('put', path, opts),
  patch: <P extends PathsWith<'patch'>>(path: P, opts?: RequestOptions<Op<P, 'patch'>>) =>
    request('patch', path, opts),
  delete: <P extends PathsWith<'delete'>>(path: P, opts?: RequestOptions<Op<P, 'delete'>>) =>
    request('delete', path, opts),
}
