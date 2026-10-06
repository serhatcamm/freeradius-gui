import { useState } from 'react'
import type { FormEvent } from 'react'

import { useAuth } from '../auth/AuthContext'
import { ApiError } from '../api'
import { Notice } from '../components/ui'

export function LogInPage() {
  const { login } = useAuth()
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [pending, setPending] = useState(false)

  async function onSubmit(event: FormEvent) {
    event.preventDefault()
    setPending(true)
    setError(null)
    try {
      await login(username, password)
    } catch (caught) {
      if (caught instanceof ApiError) {
        // Deliberately vague, matching the server: never reveal which half
        // of the credential was wrong.
        setError(caught.message)
      } else {
        setError('Could not reach the server')
      }
    } finally {
      setPending(false)
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center px-4">
      <form className="card w-full max-w-sm space-y-4 p-6" onSubmit={onSubmit}>
        <div>
          <h1 className="text-xl font-semibold">FreeRADIUS panel</h1>
          <p className="mt-1 text-sm text-slate-400">Sign in to continue</p>
        </div>

        {error ? <Notice kind="error">{error}</Notice> : null}

        <div>
          <label className="label" htmlFor="username">
            Username
          </label>
          <input
            id="username"
            className="input"
            autoComplete="username"
            autoFocus
            value={username}
            onChange={(event) => setUsername(event.target.value)}
            required
          />
        </div>

        <div>
          <label className="label" htmlFor="password">
            Password
          </label>
          <input
            id="password"
            className="input"
            type="password"
            autoComplete="current-password"
            value={password}
            onChange={(event) => setPassword(event.target.value)}
            required
          />
        </div>

        <button type="submit" className="btn-primary w-full" disabled={pending}>
          {pending ? 'Signing in…' : 'Sign in'}
        </button>
      </form>
    </div>
  )
}