import { useMemo, useState } from 'react'
import type { FormEvent } from 'react'

import { api } from '../api'
import { useCan } from '../auth/AuthContext'
import {
  ConfirmDialog,
  EmptyState,
  EnabledBadge,
  ErrorBanner,
  Modal,
  Notice,
  Spinner,
} from '../components/ui'
import { useAction, useAsync } from '../lib/hooks'
import type { Client, User } from '../types'

type Kind = 'users' | 'clients'

/**
 * Users and clients share one page: the interactions (enable, disable, delete,
 * backup-on-change) are identical and only the fields differ.
 */
export function AccountsPage({ kind }: { kind: Kind }) {
  const can = useCan()
  const isUsers = kind === 'users'
  const [notice, setNotice] = useState<{ kind: 'ok' | 'warn' | 'error'; text: string } | null>(null)

  const loader = useMemo<() => Promise<Array<User | Client>>>(
    () => (isUsers ? async () => (await api.users()) as Array<User | Client> : async () => (await api.clients()) as Array<User | Client>),
    [isUsers],
  )
  const { data, error, loading, reload } = useAsync(loader, [isUsers])
  const { run, pending, error: actionError } = useAction()

  const [createOpen, setCreateOpen] = useState(false)
  const [editing, setEditing] = useState<User | Client | null>(null)
  const [deleting, setDeleting] = useState<User | Client | null>(null)
  const [filter, setFilter] = useState('')

  const rows: Array<User | Client> = data ?? []
  const visible = useMemo(() => {
    const needle = filter.trim().toLowerCase()
    if (!needle) return rows
    return rows.filter((row) => {
      if (isUsers) {
        return (row as User).username.toLowerCase().includes(needle)
      }
      const client = row as Client
      return (
        client.name.toLowerCase().includes(needle) ||
        (client.address ?? '').toLowerCase().includes(needle)
      )
    })
  }, [rows, filter, isUsers])

  function announce(kindValue: 'ok' | 'warn' | 'error', text: string) {
    setNotice({ kind: kindValue, text })
  }

  async function toggle(row: User | Client) {
    const name = isUsers ? (row as User).username : (row as Client).name
    const enable = isUsers ? !(row as User).enabled : !(row as Client).enabled
    const result = await run<unknown>(() =>
      isUsers
        ? enable
          ? api.enableUser(name)
          : api.disableUser(name)
        : enable
          ? api.enableClient(name)
          : api.disableClient(name),
    )
    if (result) {
      announce('ok', `${enable ? 'Enabled' : 'Disabled'} ${name}. The previous content was backed up.`)
      await reload()
    }
  }

  async function confirmDelete() {
    if (!deleting) return
    const name = isUsers ? (deleting as User).username : (deleting as Client).name
    const result = await run(() =>
      isUsers ? api.deleteUser(name) : api.deleteClient(name),
    )
    setDeleting(null)
    if (result) {
      announce('ok', `Deleted ${name}. Restore it from Backups if that was a mistake.`)
      await reload()
    }
  }

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h1 className="text-xl font-semibold">{isUsers ? 'Users' : 'Clients'}</h1>
        <div className="flex items-center gap-2">
          <input
            className="input w-56"
            placeholder={isUsers ? 'Filter by username' : 'Filter by name or address'}
            value={filter}
            onChange={(event) => setFilter(event.target.value)}
            aria-label="Filter"
          />
          {can.canOperate ? (
            <button type="button" className="btn-primary" onClick={() => setCreateOpen(true)}>
              Add {isUsers ? 'user' : 'client'}
            </button>
          ) : null}
        </div>
      </div>

      {notice ? (
        <Notice kind={notice.kind} onDismiss={() => setNotice(null)}>
          {notice.text}
        </Notice>
      ) : null}
      {error ? <ErrorBanner message={error} onRetry={() => void reload()} /> : null}
      {actionError ? <ErrorBanner message={actionError} /> : null}

      {loading ? (
        <Spinner />
      ) : visible.length === 0 ? (
        <EmptyState>
          {rows.length === 0
            ? isUsers
              ? 'No users are configured.'
              : 'No clients are configured.'
            : 'Nothing matches that filter.'}
        </EmptyState>
      ) : (
        <div className="table-wrap">
          <table className="min-w-full divide-y divide-slate-700">
            <thead className="bg-slate-800/80">
              {isUsers ? <UserHeader /> : <ClientHeader />}
            </thead>
            <tbody className="divide-y divide-slate-800 bg-slate-900/40">
              {visible.map((row) =>
                isUsers ? (
                  <UserRow
                    key={(row as User).username}
                    user={row as User}
                    canOperate={can.canOperate}
                    pending={pending}
                    onToggle={() => void toggle(row)}
                    onEdit={() => setEditing(row)}
                    onDelete={() => setDeleting(row)}
                  />
                ) : (
                  <ClientRow
                    key={(row as Client).name}
                    client={row as Client}
                    canOperate={can.canOperate}
                    pending={pending}
                    onToggle={() => void toggle(row)}
                    onEdit={() => setEditing(row)}
                    onDelete={() => setDeleting(row)}
                    onDone={() => void reload()}
                  />
                ),
              )}
            </tbody>
          </table>
        </div>
      )}

      {createOpen ? (
        <AccountDialog
          kind={kind}
          onClose={() => setCreateOpen(false)}
          onSaved={(text) => {
            setCreateOpen(false)
            announce('ok', text)
            void reload()
          }}
        />
      ) : null}

      {editing ? (
        <AccountDialog
          kind={kind}
          existing={editing}
          onClose={() => setEditing(null)}
          onSaved={(text) => {
            setEditing(null)
            announce('ok', text)
            void reload()
          }}
        />
      ) : null}

      {deleting ? (
        <ConfirmDialog
          title={isUsers ? 'Delete user' : 'Delete client'}
          pending={pending}
          confirmLabel="Delete"
          message={
            <>
              <p>
                Delete{' '}
                <strong>
                  {isUsers ? (deleting as User).username : (deleting as Client).name}
                </strong>
                ?
              </p>
              <p className="mt-2 text-slate-400">
                The change is validated and backed up first, so it can be restored from the Backups
                page.
              </p>
            </>
          }
          onCancel={() => setDeleting(null)}
          onConfirm={() => void confirmDelete()}
        />
      ) : null}
    </div>
  )
}

function UserHeader() {
  return (
    <tr>
      <th className="th">Username</th>
      <th className="th">State</th>
      <th className="th">Auth method</th>
      <th className="th">Password</th>
      <th className="th">Privilege</th>
      <th className="th">Last auth</th>
      <th className="th text-right">Actions</th>
    </tr>
  )
}

function ClientHeader() {
  return (
    <tr>
      <th className="th">Name</th>
      <th className="th">State</th>
      <th className="th">Address</th>
      <th className="th">Secret</th>
      <th className="th">Message auth</th>
      <th className="th">Description</th>
      <th className="th text-right">Actions</th>
    </tr>
  )
}

function Actions({
  canOperate,
  enabled,
  pending,
  onToggle,
  onEdit,
  onDelete,
}: {
  canOperate: boolean
  enabled: boolean
  pending: boolean
  onToggle: () => void
  onEdit: () => void
  onDelete: () => void
}) {
  if (!canOperate) {
    return <span className="text-slate-500">read-only</span>
  }
  return (
    <div className="flex justify-end gap-2">
      <button type="button" className="btn-secondary" onClick={onToggle} disabled={pending}>
        {enabled ? 'Disable' : 'Enable'}
      </button>
      <button type="button" className="btn-secondary" onClick={onEdit} disabled={pending}>
        Edit
      </button>
      <button type="button" className="btn-danger" onClick={onDelete} disabled={pending}>
        Delete
      </button>
    </div>
  )
}

/** Wraps the shared action buttons in the table cell the caller renders. */
function ActionsCell(props: {
  canOperate: boolean
  enabled: boolean
  pending: boolean
  onToggle: () => void
  onEdit: () => void
  onDelete: () => void
}) {
  return (
    <td className="td text-right">
      <Actions {...props} />
    </td>
  )
}

function UserRow({
  user,
  canOperate,
  pending,
  onToggle,
  onEdit,
  onDelete,
}: {
  user: User
  canOperate: boolean
  pending: boolean
  onToggle: () => void
  onEdit: () => void
  onDelete: () => void
}) {
  return (
    <tr>
      <td className="td font-medium text-slate-100">
        {user.username}
        {user.duplicate_entries && user.duplicate_entries > 1 ? (
          <span className="ml-2 badge-warn" title="Appears more than once in the file">
            ×{user.duplicate_entries}
          </span>
        ) : null}
      </td>
      <td className="td">
        <EnabledBadge enabled={user.enabled} />
      </td>
      <td className="td">{user.auth_method}</td>
      <td className="td">{user.has_password ? 'set' : <span className="text-slate-500">none</span>}</td>
      <td className="td">{user.cisco_privilege ?? '—'}</td>
      <td className="td text-slate-400">{user.last_authentication ?? '—'}</td>
      <ActionsCell
        canOperate={canOperate}
        enabled={user.enabled}
        pending={pending}
        onToggle={onToggle}
        onEdit={onEdit}
        onDelete={onDelete}
      />
    </tr>
  )
}

function ClientRow({
  client,
  canOperate,
  pending,
  onToggle,
  onEdit,
  onDelete,
  onDone,
}: {
  client: Client
  canOperate: boolean
  pending: boolean
  onToggle: () => void
  onEdit: () => void
  onDelete: () => void
  onDone: () => void
}) {
  const { run, pending: secretPending, error } = useAction()
  const [revealed, setRevealed] = useState<string | null>(null)

  async function resetSecret() {
    const result = await run(() => api.resetSecret(client.name))
    if (result) {
      setRevealed(result.secret)
      onDone()
    }
  }

  return (
    <tr>
      <td className="td font-medium text-slate-100">{client.name}</td>
      <td className="td">
        <EnabledBadge enabled={client.enabled} />
      </td>
      <td className="td">
        {client.address ?? '—'}
        <span className="ml-2 badge-muted">{client.address_kind}</span>
      </td>
      <td className="td">
        {client.has_secret ? 'set' : <span className="text-slate-500">none</span>}
        {revealed ? (
          <code className="ml-2 rounded bg-slate-950 px-1 py-0.5 text-xs text-emerald-300">
            {revealed}
          </code>
        ) : null}
      </td>
      <td className="td">
        {client.require_message_authenticator ? (
          <span className="badge-ok">required</span>
        ) : (
          <span className="badge-warn">not required</span>
        )}
      </td>
      <td className="td max-w-xs truncate text-slate-400">{client.description || '—'}</td>
      <td className="td text-right">
        {error ? <span className="mr-2 text-xs text-red-300">{error}</span> : null}
        <div className="flex justify-end gap-2">
          {canOperate ? (
            <button
              type="button"
              className="btn-secondary"
              onClick={() => void resetSecret()}
              disabled={secretPending || pending}
              title="Generate a new shared secret for this client"
            >
              New secret
            </button>
          ) : null}
          <Actions
            canOperate={canOperate}
            enabled={client.enabled}
            pending={pending}
            onToggle={onToggle}
            onEdit={onEdit}
            onDelete={onDelete}
          />
        </div>
      </td>
    </tr>
  )
}

/** Create/edit form for a single user or client. */
function AccountDialog({
  kind,
  existing,
  onClose,
  onSaved,
}: {
  kind: Kind
  existing?: User | Client
  onClose: () => void
  onSaved: (message: string) => void
}) {
  const isUsers = kind === 'users'
  const editing = Boolean(existing)
  const { run, pending, error } = useAction()

  const user = existing as User | undefined
  const client = existing as Client | undefined

  const [username, setUsername] = useState(user?.username ?? '')
  const [password, setPassword] = useState('')
  const [privilege, setPrivilege] = useState(String(user?.cisco_privilege ?? 1))
  const [authMethod, setAuthMethod] = useState(user?.auth_method ?? 'pap')

  const [name, setName] = useState(client?.name ?? '')
  const [address, setAddress] = useState(client?.address ?? '')
  const [nasType, setNasType] = useState(client?.nas_type ?? 'other')
  const [description, setDescription] = useState(client?.description ?? '')
  const [messageAuth, setMessageAuth] = useState(client?.require_message_authenticator ?? false)

  async function onSubmit(event: FormEvent) {
    event.preventDefault()
    if (isUsers) {
      const result = editing
        ? await run(() =>
            api.updateUser(username, {
              cisco_privilege: Number(privilege) || 1,
              auth_method: authMethod,
            }),
          )
        : await run(() => api.createUser({ username, password }))
      if (result) onSaved(editing ? `Updated ${username}.` : `Created ${username}.`)
      return
    }

    const payload: Record<string, unknown> = {
      address,
      nas_type: nasType,
      description,
      require_message_authenticator: messageAuth,
    }
    const result = editing
      ? await run(() => api.updateClient(name, payload))
      : await run(() => api.createClient({ name, secret: password || undefined, ...payload }))
    if (result) onSaved(editing ? `Updated ${name}.` : `Created ${name}.`)
  }

  return (
    <Modal
      title={`${editing ? 'Edit' : 'Add'} ${isUsers ? 'user' : 'client'}`}
      onClose={onClose}
      footer={
        <>
          <button type="button" className="btn-secondary" onClick={onClose} disabled={pending}>
            Cancel
          </button>
          <button type="submit" form="account-form" className="btn-primary" disabled={pending}>
            {pending ? 'Saving…' : editing ? 'Save changes' : 'Create'}
          </button>
        </>
      }
    >
      <form id="account-form" className="space-y-4" onSubmit={onSubmit}>
        {error ? <ErrorBanner message={error} /> : null}

        {isUsers ? (
          <>
            <div>
              <label className="label" htmlFor="username">
                Username
              </label>
              <input
                id="username"
                className="input"
                value={username}
                onChange={(event) => setUsername(event.target.value)}
                // The API keys users by name; renaming is a delete plus a
                // create, so the field is locked while editing.
                disabled={editing}
                required
              />
            </div>
            {!editing ? (
              <div>
                <label className="label" htmlFor="password">
                  Password
                </label>
                <input
                  id="password"
                  className="input"
                  type="password"
                  autoComplete="new-password"
                  value={password}
                  onChange={(event) => setPassword(event.target.value)}
                  required
                  minLength={12}
                />
                <p className="mt-1 text-xs text-slate-500">
                  Stored as a FreeRADIUS hash; at least 12 characters.
                </p>
              </div>
            ) : (
              <div>
                <label className="label" htmlFor="new-password">
                  Set a new password (optional)
                </label>
                <input
                  id="new-password"
                  className="input"
                  type="password"
                  autoComplete="new-password"
                  value={password}
                  onChange={(event) => setPassword(event.target.value)}
                  minLength={12}
                />
              </div>
            )}
            <div className="grid gap-4 sm:grid-cols-2">
              <div>
                <label className="label" htmlFor="privilege">
                  Privilege (0–15)
                </label>
                <input
                  id="privilege"
                  className="input"
                  type="number"
                  min={0}
                  max={15}
                  value={privilege}
                  onChange={(event) => setPrivilege(event.target.value)}
                />
              </div>
              <div>
                <label className="label" htmlFor="auth-method">
                  Auth method
                </label>
                <select
                  id="auth-method"
                  className="input"
                  value={authMethod}
                  onChange={(event) => setAuthMethod(event.target.value)}
                >
                  {['pap', 'chap', 'mschap', 'eapol', 'ldap'].map((method) => (
                    <option key={method} value={method}>
                      {method}
                    </option>
                  ))}
                </select>
              </div>
            </div>
          </>
        ) : (
          <>
            <div>
              <label className="label" htmlFor="client-name">
                Client name
              </label>
              <input
                id="client-name"
                className="input"
                value={name}
                onChange={(event) => setName(event.target.value)}
                disabled={editing}
                required
              />
            </div>
            <div>
              <label className="label" htmlFor="address">
                Address (IP, CIDR or hostname)
              </label>
              <input
                id="address"
                className="input"
                value={address}
                onChange={(event) => setAddress(event.target.value)}
                required
              />
            </div>
            {!editing ? (
              <div>
                <label className="label" htmlFor="secret">
                  Shared secret
                </label>
                <input
                  id="secret"
                  className="input"
                  value={password}
                  onChange={(event) => setPassword(event.target.value)}
                  placeholder="Leave blank to generate a strong one"
                  autoComplete="off"
                />
              </div>
            ) : null}
            <div className="grid gap-4 sm:grid-cols-2">
              <div>
                <label className="label" htmlFor="nas-type">
                  NAS type
                </label>
                <select
                  id="nas-type"
                  className="input"
                  value={nasType}
                  onChange={(event) => setNasType(event.target.value)}
                >
                  {['other', 'cisco', 'computone', 'livingston', 'max40xx', 'multitech', 'pathras', 'patton', 'portslave', 'tc', 'usrhiper'].map(
                    (type) => (
                      <option key={type} value={type}>
                        {type}
                      </option>
                    ),
                  )}
                </select>
              </div>
              <div className="flex items-end">
                <label className="flex items-center gap-2 text-sm">
                  <input
                    type="checkbox"
                    checked={messageAuth}
                    onChange={(event) => setMessageAuth(event.target.checked)}
                  />
                  Require message authenticator
                </label>
              </div>
            </div>
            <div>
              <label className="label" htmlFor="description">
                Description
              </label>
              <input
                id="description"
                className="input"
                value={description}
                onChange={(event) => setDescription(event.target.value)}
              />
            </div>
          </>
        )}
      </form>
    </Modal>
  )
}