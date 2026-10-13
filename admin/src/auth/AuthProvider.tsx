import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from 'react'

import { api, SESSION_EXPIRED } from '../lib/api'
import { clearTokens, getAccessToken, setTokens } from '../lib/session'
import type { IdentityUser, Session } from '../lib/types'

/** identity.console.use: admin (as superuser) and tech in the seed. */
export function canUseConsole(user: IdentityUser | null): boolean {
  return Boolean(user?.apps.identity?.permissions?.console?.use?.length)
}

interface AuthState {
  user: IdentityUser | null
  checking: boolean
  signIn: (email: string, password: string) => Promise<void>
  signOut: () => Promise<void>
}

const AuthContext = createContext<AuthState | null>(null)

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<IdentityUser | null>(null)
  const [checking, setChecking] = useState(Boolean(getAccessToken()))

  useEffect(() => {
    if (!getAccessToken()) return
    api.get<IdentityUser>('/auth/me')
      .then(setUser)
      .catch(() => clearTokens())
      .finally(() => setChecking(false))
  }, [])

  useEffect(() => {
    const expired = () => setUser(null)
    window.addEventListener(SESSION_EXPIRED, expired)
    return () => window.removeEventListener(SESSION_EXPIRED, expired)
  }, [])

  const signIn = useCallback(async (email: string, password: string) => {
    const session = await api.post<Session>('/auth/login', { email, password }, { auth: false })
    setTokens(session.access_token, session.refresh_token)
    setUser(session.user)
  }, [])

  const signOut = useCallback(async () => {
    try {
      await api.post('/auth/logout')
    } catch {
      // Signing out locally must not depend on the network.
    }
    clearTokens()
    setUser(null)
  }, [])

  const value = useMemo(() => ({ user, checking, signIn, signOut }), [user, checking, signIn, signOut])
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}

export function useAuth(): AuthState {
  const state = useContext(AuthContext)
  if (!state) throw new Error('useAuth outside AuthProvider')
  return state
}
