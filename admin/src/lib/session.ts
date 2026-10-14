// Token storage, shared with the CMS admin panel and Broker Tools.
//
// On the shared Firebase site every AllSet app is served from one origin, so
// these localStorage keys are one namespace: signing in to any app signs you in
// here too, as long as your roles grant the console. The same keys as
// AllSet_CMS admin_ui/src/auth/session.ts, deliberately.

const ACCESS_KEY = 'allset_access_token'
const REFRESH_KEY = 'allset_refresh_token'

function read(key: string): string | null {
  try {
    return localStorage.getItem(key)
  } catch {
    // Private browsing or blocked site data: treated as signed out.
    return null
  }
}

function write(key: string, value: string | null): void {
  try {
    if (value === null) localStorage.removeItem(key)
    else localStorage.setItem(key, value)
  } catch {
    // The session simply will not survive a reload.
  }
}

export function getAccessToken(): string | null {
  return read(ACCESS_KEY)
}

export function getRefreshToken(): string | null {
  return read(REFRESH_KEY)
}

export function setTokens(accessToken: string, refreshToken?: string | null): void {
  write(ACCESS_KEY, accessToken)
  if (refreshToken) write(REFRESH_KEY, refreshToken)
}

export function clearTokens(): void {
  write(ACCESS_KEY, null)
  write(REFRESH_KEY, null)
}
