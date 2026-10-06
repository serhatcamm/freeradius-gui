import { useState } from 'react'
import type { FormEvent } from 'react'

import { api } from '../api'
import { useCan } from '../auth/AuthContext'
import {
  ConfirmDialog,
  EmptyState,
  ErrorBanner,
  Modal,
  Notice,
  Spinner,
  formatTimestamp,
} from '../components/ui'
import { useAction, useAsync } from '../lib/hooks'
import type { AdministratorRecord, Role } from '../types'

const ROLE_LABELS: Record<Role, string> = {
  viewer: 'Viewer',
  operator: 'Operator',
  admin: 'Admin',
}

const ROLE_HELP: Record<Role, string> = {
  viewer: 'Read-only access to every page.',
  operator: 'May change users, clients, groups and secrets.',
  admin: 'Everything, including service control, backups and administrators.',
}

interface NewAdmin {
  username: string
  full_name: string
  role: Role
  password: string
  confirm: string
}

function emptyForm(): NewAdmin {
  return { username: '', full_name: '', role: 'viewer', password: '', confirm: '' }
}

export function AdministratorsPage() {
  const can = useCan()
  const status = useAsync(() => api.administrators(), [])
  const { run, pending, error: actionError } = useAction()
  const [notice, setNotice] = useState<{ kind: 'ok' | 'warn'; text: string } | null>(null)
  const [creating, setCreating] = useState(false)
  const [resetting, setResetting] = useState<AdministratorRecord | null>(null)
  const [deactivating, setDeactivating] = useState<AdministratorRecord | null>(null)

  const rows = status.data?.administrators ?? []
  const activeAdmins = status.data?.active_admin_count ?? 0

  // The self row is read-only: the server refuses those changes, so offering
  // them would only produce errors.
  const lastAdmin =
    activeAdmins <= 1 && deactivating?.role === 'admin' && deactivating.is_active

  async function changeRole(target: AdministratorRecord, role: Role) {
    if (role === target.role) return
    const outcome = await run(() =>
      api.updateAdministrator(target.username, { role }),
    )
    if (outcome) {
      setNotice({ kind: 'ok', text: `${target.username} is now ${ROLE_LABELS[role]}.` })
      await status.reload()
    }
  }

  async function unlock(target: AdministratorRecord) {
    const outcome = await run(() => api.unlockAdministrator(target.username))
    if (outcome) {
      setNotice({ kind: 'ok', text: `${target.username} unlocked.` })
      await status.reload()
    }
  }

  async function confirmDeactivate() {
    if (!deactivating) return
    const name = deactivating.username
    setDeactivating(null)
    const outcome = await run(() => api.deactivateAdministrator(name))
    if (outcome) {
      setNotice({
        kind: 'warn',
        text: `${name} deactivated. Their active sessions were signed out immediately.`,
      })
      await status.reload()
    }
  }

  async function create(form: NewAdmin) {
    const outcome = await run(() =>
      api.createAdministrator({
        username: form.username.trim(),
        password: form.password,
        role: form.role,
        full_name: form.full_name.trim() || null,
      }),
    )
    if (outcome) {
      setCreating(false)
      setNotice({ kind: 'ok', text: `Administrator ${outcome.username} created.` })
      await status.reload()
    }
  }

  return (
    <div className="space-y-6">
      <header className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-lg font-semibold text-slate-100">Administrators</h1>
          <p className="text-sm text-slate-400">
            Who can sign in to this panel. These are panel accounts, separate from RADIUS users.
          </p>
        </div>
        {can.isAdmin ? (
          <button type="button" className="btn-primary" onClick={() => setCreating(true)}>
            Add administrator
          </button>
        ) : null}
      </header>

      {notice ? (
        <Notice kind={notice.kind} onDismiss={() => setNotice(null)}>
          {notice.text}
        </Notice>
      ) : null}
      {actionError ? <ErrorBanner message={actionError} /> : null}
      {status.error ? (
        <ErrorBanner message={status.error} onRetry={() => void status.reload()} />
      ) : null}

      {status.loading ? <Spinner label="Loading administrators" /> : null}

      {!status.loading && rows.length === 0 ? (
        <EmptyState>No administrators found.</EmptyState>
      ) : null}

      {rows.length > 0 ? (
        <div className="table-wrap">
          <table className="min-w-full">
            <thead className="bg-slate-800">
              <tr>
                <th className="px-4 py-2 text-left text-xs font-semibold uppercase text-slate-300">
                  Username
                </th>
                <th className="px-4 py-2 text-left text-xs font-semibold uppercase text-slate-300">
                  Role
                </th>
                <th className="px-4 py-2 text-left text-xs font-semibold uppercase text-slate-300">
                  Last login
                </th>
                <th className="px-4 py-2 text-left text-xs font-semibold uppercase text-slate-300">
                  State
                </th>
                {can.isAdmin ? (
                  <th className="px-4 py-2 text-right text-xs font-semibold uppercase text-slate-300">
                    Actions
                  </th>
                ) : null}
              </tr>
            </thead>
            <tbody>
              {rows.map((row) => (
                <tr key={row.username} className="border-t border-slate-700">
                  <td className="px-4 py-2 text-sm text-slate-100">
                    <span className="font-medium">{row.username}</span>
                    {row.is_self ? <span className="ml-2 text-xs text-slate-400">(you)</span> : null}
                    {row.full_name ? (
                      <div className="text-xs text-slate-400">{row.full_name}</div>
                    ) : null}
                  </td>
                  <td className="px-4 py-2 text-sm text-slate-300">
                    {can.isAdmin && !row.is_self ? (
                      <select
                        className="input"
                        aria-label={`Role for ${row.username}`}
                        value={row.role}
                        disabled={pending}
                        onChange={(event) =>
                          void changeRole(row, event.target.value as Role)
                        }
                      >
                        {(Object.keys(ROLE_LABELS) as Role[]).map((role) => (
                          <option key={role} value={role}>
                            {ROLE_LABELS[role]}
                          </option>
                        ))}
                      </select>
                    ) : (
                      <span title={ROLE_HELP[row.role]}>{ROLE_LABELS[row.role]}</span>
                    )}
                  </td>
                  <td className="px-4 py-2 text-sm text-slate-400">
                    {row.last_login_at ? formatTimestamp(row.last_login_at) : 'never'}
                    {row.last_login_ip ? (
                      <div className="text-xs text-slate-500">{row.last_login_ip}</div>
                    ) : null}
                  </td>
                  <td className="px-4 py-2 text-sm">
                    {!row.is_active ? (
                      <span className="badge-warn">deactivated</span>
                    ) : row.locked_until ? (
                      <span className="badge-warn">locked</span>
                    ) : row.failed_attempts > 0 ? (
                      <span className="badge-muted">{row.failed_attempts} failed</span>
                    ) : (
                      <span className="badge-muted">
                        {row.session_count} session{row.session_count === 1 ? '' : 's'}
                      </span>
                    )}
                  </td>
                  {can.isAdmin ? (
                    <td className="px-4 py-2 text-right">
                      <div className="flex justify-end gap-2">
                        {row.failed_attempts > 0 || row.locked_until ? (
                          <button
                            type="button"
                            className="btn-ghost"
                            disabled={pending}
                            onClick={() => void unlock(row)}
                          >
                            Unlock
                          </button>
                        ) : null}
                        <button
                          type="button"
                          className="btn-ghost"
                          disabled={pending || row.is_self}
                          title={row.is_self ? 'You cannot reset your own password here' : undefined}
                          onClick={() => setResetting(row)}
                        >
                          Reset password
                        </button>
                        <button
                          type="button"
                          className="btn-ghost"
                          disabled={pending || row.is_self || !row.is_active}
                          title={row.is_self ? 'You cannot deactivate yourself' : undefined}
                          onClick={() => setDeactivating(row)}
                        >
                          {row.is_active ? 'Deactivate' : 'Deactivated'}
                        </button>
                      </div>
                    </td>
                  ) : null}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}

      {activeAdmins <= 1 ? (
        <Notice kind="warn">
          <strong>Only one administrator holds the admin role.</strong> Create a second admin
          before changing or removing this one, otherwise nobody can manage the panel.
        </Notice>
      ) : null}

      {creating ? (
        <CreateDialog
          pending={pending}
          error={actionError}
          onCancel={() => setCreating(false)}
          onCreate={create}
        />
      ) : null}

      {resetting ? (
        <ResetPasswordDialog
          target={resetting}
          pending={pending}
          error={actionError}
          onCancel={() => setResetting(null)}
          onDone={async () => {
            const name = resetting.username
            setResetting(null)
            setNotice({
              kind: 'warn',
              text: `Password reset for ${name}. Their active sessions were signed out.`,
            })
            await status.reload()
          }}
        />
      ) : null}

      {deactivating ? (
        <ConfirmDialog
          title={`Deactivate ${deactivating.username}?`}
          confirmLabel="Deactivate"
          pending={pending}
          onCancel={() => setDeactivating(null)}
          onConfirm={() => void confirmDeactivate()}
          message={
            <>
              <p>
                {deactivating.username} will no longer be able to sign in, and their active
                sessions are signed out immediately.
              </p>
              <p className="mt-2 text-slate-400">
                The account and its audit history are kept. It can be reactivated at any time.
              </p>
              {lastAdmin ? (
                <p className="mt-2 text-amber-300">
                  This is the last administrator with the admin role. Deactivating it would leave
                  the panel unmanageable.
                </p>
              ) : null}
            </>
          }
        />
      ) : null}
    </div>
  )
}

function CreateDialog({
  pending,
  error,
  onCancel,
  onCreate,
}: {
  pending: boolean
  error: string | null
  onCancel: () => void
  onCreate: (form: NewAdmin) => void
}) {
  const [form, setForm] = useState<NewAdmin>(emptyForm())
  const [formError, setFormError] = useState<string | null>(null)

  function submit(event: FormEvent) {
    event.preventDefault()
    if (!form.username.trim()) {
      setFormError('Username is required')
      return
    }
    if (form.password.length < 12) {
      setFormError('Password must be at least 12 characters')
      return
    }
    if (form.password !== form.confirm) {
      setFormError('The two passwords do not match')
      return
    }
    setFormError(null)
    onCreate(form)
  }

  return (
    <Modal
      title="Add administrator"
      onClose={onCancel}
      footer={
        <>
          <button type="button" className="btn-ghost" onClick={onCancel} disabled={pending}>
            Cancel
          </button>
          <button type="submit" form="admin-create" className="btn-primary" disabled={pending}>
            {pending ? 'Creating…' : 'Create'}
          </button>
        </>
      }
    >
      <form id="admin-create" className="space-y-4" onSubmit={submit}>
        <div>
          <label className="label" htmlFor="admin-username">
            Username
          </label>
          <input
            id="admin-username"
            className="input"
            value={form.username}
            autoComplete="off"
            onChange={(event) => setForm({ ...form, username: event.target.value })}
          />
        </div>
        <div>
          <label className="label" htmlFor="admin-fullname">
            Full name <span className="font-normal text-slate-500">(optional)</span>
          </label>
          <input
            id="admin-fullname"
            className="input"
            value={form.full_name}
            autoComplete="off"
            onChange={(event) => setForm({ ...form, full_name: event.target.value })}
          />
        </div>
        <div>
          <label className="label" htmlFor="admin-role">
            Role
          </label>
          <select
            id="admin-role"
            className="input"
            value={form.role}
            onChange={(event) => setForm({ ...form, role: event.target.value as Role })}
          >
            {(Object.keys(ROLE_LABELS) as Role[]).map((role) => (
              <option key={role} value={role}>
                {ROLE_LABELS[role]}
              </option>
            ))}
          </select>
          <p className="mt-1 text-xs text-slate-400">{ROLE_HELP[form.role]}</p>
        </div>
        <div>
          <label className="label" htmlFor="admin-password">
            Password
          </label>
          <input
            id="admin-password"
            className="input"
            type="password"
            value={form.password}
            autoComplete="new-password"
            onChange={(event) => setForm({ ...form, password: event.target.value })}
          />
          <p className="mt-1 text-xs text-slate-400">Minimum 12 characters.</p>
        </div>
        <div>
          <label className="label" htmlFor="admin-confirm">
            Confirm password
          </label>
          <input
            id="admin-confirm"
            className="input"
            type="password"
            value={form.confirm}
            autoComplete="new-password"
            onChange={(event) => setForm({ ...form, confirm: event.target.value })}
          />
        </div>
        {formError ? <p className="text-sm text-red-300">{formError}</p> : null}
        {error ? <ErrorBanner message={error} /> : null}
      </form>
    </Modal>
  )
}

function ResetPasswordDialog({
  target,
  pending,
  error,
  onCancel,
  onDone,
}: {
  target: AdministratorRecord
  pending: boolean
  error: string | null
  onCancel: () => void
  onDone: () => void
}) {
  const [password, setPassword] = useState('')
  const [confirm, setConfirm] = useState('')
  const [formError, setFormError] = useState<string | null>(null)
  const { run } = useAction()

  async function submit(event: FormEvent) {
    event.preventDefault()
    if (password.length < 12) {
      setFormError('Password must be at least 12 characters')
      return
    }
    if (password !== confirm) {
      setFormError('The two passwords do not match')
      return
    }
    setFormError(null)
    const outcome = await run(() => api.resetAdministratorPassword(target.username, password))
    if (outcome) onDone()
  }

  return (
    <Modal
      title={`Reset password for ${target.username}`}
      onClose={onCancel}
      footer={
        <>
          <button type="button" className="btn-ghost" onClick={onCancel} disabled={pending}>
            Cancel
          </button>
          <button type="submit" form="admin-reset" className="btn-primary" disabled={pending}>
            {pending ? 'Resetting…' : 'Reset password'}
          </button>
        </>
      }
    >
      <form id="admin-reset" className="space-y-4" onSubmit={submit}>
        <Notice kind="warn">
          Share this password over a secure channel. {target.username} will be signed out of every
          session, and {target.session_count} active session
          {target.session_count === 1 ? '' : 's'} will end.
        </Notice>
        <div>
          <label className="label" htmlFor="reset-password">
            New password
          </label>
          <input
            id="reset-password"
            className="input"
            type="password"
            value={password}
            autoComplete="new-password"
            onChange={(event) => setPassword(event.target.value)}
          />
        </div>
        <div>
          <label className="label" htmlFor="reset-confirm">
            Confirm password
          </label>
          <input
            id="reset-confirm"
            className="input"
            type="password"
            value={confirm}
            autoComplete="new-password"
            onChange={(event) => setConfirm(event.target.value)}
          />
        </div>
        {formError ? <p className="text-sm text-red-300">{formError}</p> : null}
        {error ? <ErrorBanner message={error} /> : null}
      </form>
    </Modal>
  )
}