import { useState } from 'react'
import type { FormEvent } from 'react'

import { api } from '../api'
import { useAuth, useCan } from '../auth/AuthContext'
import { ErrorBanner, Notice, Spinner } from '../components/ui'
import { useAction, useAsync } from '../lib/hooks'

export function SettingsPage() {
  const can = useCan()
  const { admin } = useAuth()
  const settings = useAsync(() => api.settings(), [])

  return (
    <div className="space-y-6">
      <h1 className="text-xl font-semibold">Settings</h1>

      <section className="card p-5">
        <h2 className="text-sm font-semibold uppercase tracking-wide text-slate-400">Panel</h2>
        {settings.loading ? (
          <Spinner />
        ) : settings.error ? (
          <ErrorBanner message={settings.error} onRetry={() => void settings.reload()} />
        ) : settings.data ? (
          <dl className="mt-3 space-y-2 text-sm">
            <Row label="Environment" value={settings.data.environment ?? '—'} />
            <Row label="Radius directory" value={settings.data.raddb_dir ?? '—'} />
            <Row label="Backup directory" value={settings.data.backup_dir ?? '—'} />
            <Row label="Log directory" value={settings.data.log_dir ?? '—'} />
            <Row label="Database" value={settings.data.database ?? '—'} />
            <Row
              label="Session lifetime"
              value={
                settings.data.session_timeout_seconds != null
                  ? `${Math.round(settings.data.session_timeout_seconds / 60)} minutes`
                  : '—'
              }
            />
            <Row
              label="Idle timeout"
              value={
                settings.data.idle_timeout_seconds != null
                  ? `${Math.round(settings.data.idle_timeout_seconds / 60)} minutes`
                  : '—'
              }
            />
            <Row
              label="Secure cookies"
              value={settings.data.cookie_secure === undefined ? '—' : String(settings.data.cookie_secure)}
            />
            {/* managed_files is a name -> path mapping, so join the values. */}
            <Row
              label="Managed files"
              value={
                settings.data.managed_files
                  ? Object.entries(settings.data.managed_files)
                      .map(([name, path]) => `${name}: ${path}`)
                      .join(', ')
                  : '—'
              }
            />
          </dl>
        ) : null}
      </section>

      <section className="card p-5">
        <h2 className="text-sm font-semibold uppercase tracking-wide text-slate-400">Your account</h2>
        <dl className="mt-3 space-y-2 text-sm">
          <Row label="Username" value={admin?.username ?? '—'} />
          <Row label="Full name" value={admin?.full_name ?? '—'} />
          <Row label="Role" value={admin?.role ?? '—'} />
          <Row label="Last sign-in" value={admin?.last_login_at ?? '—'} />
        </dl>
        {!can.isAdmin ? (
          <p className="mt-3 text-xs text-slate-500">
            Role changes are not available in the panel; edit them with the CLI on the host.
          </p>
        ) : null}
      </section>

      <ChangePasswordCard />
    </div>
  )
}

function Row({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex justify-between gap-6 border-b border-slate-800 py-1 last:border-0">
      <dt className="text-slate-400">{label}</dt>
      <dd className="truncate text-right font-mono text-xs text-slate-200">{value}</dd>
    </div>
  )
}

function ChangePasswordCard() {
  const [current, setCurrent] = useState('')
  const [next, setNext] = useState('')
  const [confirm, setConfirm] = useState('')
  const [done, setDone] = useState(false)
  const { run, pending, error } = useAction()

  async function onSubmit(event: FormEvent) {
    event.preventDefault()
    if (next !== confirm) {
      return
    }
    const result = await run(() => api.changePassword(current, next))
    if (result?.ok) {
      setCurrent('')
      setNext('')
      setConfirm('')
      setDone(true)
    }
  }

  const mismatch = confirm.length > 0 && next !== confirm

  return (
    <section className="card p-5">
      <h2 className="text-sm font-semibold uppercase tracking-wide text-slate-400">
        Change your password
      </h2>
      {done ? (
        <div className="mt-3">
          <Notice onDismiss={() => setDone(false)}>Password updated.</Notice>
        </div>
      ) : null}
      <form className="mt-4 grid max-w-md gap-4" onSubmit={onSubmit}>
        {error ? <ErrorBanner message={error} /> : null}
        <div>
          <label className="label" htmlFor="current-password">
            Current password
          </label>
          <input
            id="current-password"
            className="input"
            type="password"
            autoComplete="current-password"
            value={current}
            onChange={(event) => setCurrent(event.target.value)}
            required
          />
        </div>
        <div>
          <label className="label" htmlFor="next-password">
            New password
          </label>
          <input
            id="next-password"
            className="input"
            type="password"
            autoComplete="new-password"
            value={next}
            onChange={(event) => setNext(event.target.value)}
            required
            minLength={12}
          />
        </div>
        <div>
          <label className="label" htmlFor="confirm-password">
            Confirm new password
          </label>
          <input
            id="confirm-password"
            className="input"
            type="password"
            autoComplete="new-password"
            value={confirm}
            onChange={(event) => setConfirm(event.target.value)}
            required
            minLength={12}
          />
          {mismatch ? (
            <p className="mt-1 text-xs text-red-300">The two passwords do not match.</p>
          ) : null}
        </div>
        <button type="submit" className="btn-primary" disabled={pending || mismatch}>
          {pending ? 'Updating…' : 'Update password'}
        </button>
      </form>
    </section>
  )
}