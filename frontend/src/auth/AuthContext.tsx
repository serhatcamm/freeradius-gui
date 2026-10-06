import { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react'
import type { ReactNode } from 'react'

import { ApiError, api } from '../api'
import type { Administrator } from '../types'

interface AuthState {
  admin: Administrator | null
  loading: boolean
  login: (username: string, password: string) => Promise<void>
  logout: () => Promise<void>
  /** Set when the session ended unexpectedly, so the UI can explain itself. */
  expired: boolean
  /** Clear the expired flag after a successful login. */
  setExpired: (value: boolean) => void
}

const AuthContext = createContext<AuthState | null>(null)

export function AuthProvider({ children }: { children: ReactNode }) {
  const [admin, setAdmin] = useState<Administrator | null>(null)
  const [loading, setLoading] = useState(true)
  const [expired, setExpired] = useState(false)

  // Restore the session on load; a 401 here just means "not signed in".
  useEffect(() => {
    let cancelled = false
    api
      .me()
      .then((me) => {
        if (!cancelled) setAdmin(me)
      })
      .catch((error: unknown) => {
        if (cancelled) return
        if (error instanceof ApiError && error.isUnauthorized) {
          setAdmin(null)
        } else {
          // A network error is worth surfacing rather than showing a login
          // form that cannot possibly work.
          console.error('session check failed', error)
        }
      })
      .finally(() => {
        if (!cancelled) setLoading(false)
      })
    return () => {
      cancelled = true
    }
  }, [])

  const login = useCallback(async (username: string, password: string) => {
    const result = await api.login(username, password)
    setAdmin(result.administrator)
    setExpired(false)
  }, [])

  const logout = useCallback(async () => {
    try {
      await api.logout()
    } finally {
      setAdmin(null)
    }
  }, [])

  const value = useMemo<AuthState>(
    () => ({ admin, loading, login, logout, expired, setExpired }),
    [admin, loading, login, logout, expired],
  )

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}

export function useAuth(): AuthState {
  const context = useContext(AuthContext)
  if (!context) {
    throw new Error('useAuth must be used inside AuthProvider')
  }
  return context
}

/** Role helpers, kept in one place so checks cannot drift between pages. */
export function useCan() {
  const { admin } = useAuth()
  const rank: Record<string, number> = { viewer: 0, operator: 1, admin: 2 }
  const level = admin ? (rank[admin.role] ?? -1) : -1
  return {
    role: admin?.role ?? null,
    isViewer: level >= 0,
    canOperate: level >= 1,
    isAdmin: level >= 2,
  }
}