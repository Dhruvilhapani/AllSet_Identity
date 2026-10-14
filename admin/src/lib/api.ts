// The one place the console talks to AllSet Identity.

import { clearTokens, getAccessToken, getRefreshToken, setTokens } from './session'
import type { Session } from './types'

/**
 * The API prefix for wherever the console is being served from: /admin/ on
 * Identity itself, or /identity/admin/ through the Firebase rewrite, which
 * forwards /identity/** unchanged.
 */
export function apiBase(pathname: string): string {
  return pathname.startsWith('/identity/') ? '/identity/v1' : '/v1'
}

const BASE = typeof window === 'undefined' ? '/v1' : apiBase(window.location.pathname)

export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message)
  }
}

/** FastAPI answers {detail: string}, or a list of validation errors on 422. */
export function errorMessage(status: number, body: unknown): string {
  if (body && typeof body === 'object' && 'detail' in body) {
    const detail = (body as { detail: unknown }).detail
    if (typeof detail === 'string') return detail
    if (Array.isArray(detail)) {
      return detail
        .map((item) => {
          const entry = item as { loc?: unknown[]; msg?: string }
          const field = Array.isArray(entry.loc) ? entry.loc.slice(1).join('.') : ''
          return field ? `${field}: ${entry.msg}` : entry.msg
        })
        .join('; ')
    }
  }
  if (status === 503) return 'Identity is unavailable. Try again in a moment.'
  return `Request failed (${status})`
}

// Fired when the session can no longer be used; AuthProvider signs out.
export const SESSION_EXPIRED = 'allset-session-expired'

let refreshInFlight: Promise<boolean> | null = null

// Coalesced: a page that fires several requests on an expired token must not
// rotate the refresh token several times, which would make all but one fail.
async function refresh(): Promise<boolean> {
  const refreshToken = getRefreshToken()
  if (!refreshToken) return false
  if (!refreshInFlight) {
    refreshInFlight = fetch(`${BASE}/auth/refresh`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ refresh_token: refreshToken }),
    })
      .then(async (res) => {
        if (!res.ok) return false
        const session = (await res.json()) as Session
        setTokens(session.access_token, session.refresh_token)
        return true
      })
      .catch(() => false)
      .finally(() => {
        refreshInFlight = null
      })
  }
  return refreshInFlight
}

interface RequestOptions {
  body?: unknown
  headers?: Record<string, string>
  auth?: boolean
}

export interface Reply<T> {
  data: T
  headers: Headers
}

async function request<T>(method: string, path: string, options: RequestOptions = {}, retry = true): Promise<Reply<T>> {
  const headers: Record<string, string> = { ...(options.headers ?? {}) }
  if (options.body !== undefined) headers['Content-Type'] = 'application/json'
  const token = getAccessToken()
  if (options.auth !== false && token) headers.Authorization = `Bearer ${token}`

  let res: Response
  try {
    res = await fetch(`${BASE}${path}`, {
      method,
      headers,
      body: options.body === undefined ? undefined : JSON.stringify(options.body),
    })
  } catch {
    throw new ApiError(0, 'Could not reach Identity. Check your connection.')
  }

  if (res.status === 401 && options.auth !== false && retry) {
    if (await refresh()) return request<T>(method, path, options, false)
    clearTokens()
    window.dispatchEvent(new Event(SESSION_EXPIRED))
  }

  const text = await res.text()
  let body: unknown = null
  if (text) {
    try {
      body = JSON.parse(text)
    } catch {
      body = text
    }
  }
  if (!res.ok) throw new ApiError(res.status, errorMessage(res.status, body))
  return { data: body as T, headers: res.headers }
}

export const api = {
  get: <T>(path: string) => request<T>('GET', path).then((r) => r.data),
  getWithHeaders: <T>(path: string) => request<T>('GET', path),
  post: <T>(path: string, body?: unknown, options: RequestOptions = {}) =>
    request<T>('POST', path, { ...options, body }).then((r) => r.data),
  patch: <T>(path: string, body: unknown) => request<T>('PATCH', path, { body }).then((r) => r.data),
  put: <T>(path: string, body: unknown, headers?: Record<string, string>) =>
    request<T>('PUT', path, { body, headers }).then((r) => r.data),
  del: (path: string) => request<null>('DELETE', path).then(() => undefined),
}
