import { useMemo, useState } from 'react'
import type { FormEvent } from 'react'

import { api } from '../api'
import { useCan } from '../auth/AuthContext'
import { ConfirmDialog, EmptyState, ErrorBanner, Modal, Notice, Spinner } from '../components/ui'
import { useAction, useAsync } from '../lib/hooks'
import type { Group, GroupAttribute } from '../types'

/** Attributes an operator most often sets on a group. */
const COMMON_ATTRIBUTES = [
  'Reply-Message',
  'Session-Timeout',
  'Idle-Timeout',
  'Max-Monthly-Session',
  'Max-All-Session',
  'Tunnel-Type',
  'Tunnel-Medium-Type',
]

interface Draft {
  name: string
  attributes: GroupAttribute[]
}

function emptyDraft(): Draft {
  return { name: '', attributes: [] }
}

function draftFrom(group: Group): Draft {
  return {
    name: group.name,
    attributes: group.attributes.map((attribute) => ({ ...attribute })),
  }
}

export function GroupsPage() {
  const can = useCan()
  const [editing, setEditing] = useState<Draft | null>(null)
  const [notice, setNotice] = useState<{ kind: 'ok' | 'warn' | 'error'; text: string } | null>(null)
  const [pendingDelete, setPendingDelete] = useState<Group | null>(null)

  const status = useAsync(() => api.groups(), [])
  const { run, pending, error } = useAction()

  const groups = status.data?.groups ?? []
  const groupfileEnabled = status.data?.enabled ?? false

  // Group -> user membership, read on demand per group to avoid one request
  // per row on the list.
  const memberCounts = useMemo(() => {
    const counts: Record<string, number> = {}
    for (const group of groups) {
      counts[group.name] = group.members?.length ?? 0
    }
    return counts
  }, [groups])

  async function save(draft: Draft, original?: Group) {
    const body = {
      name: draft.name,
      attributes: draft.attributes.map(({ key, value, reply }) => ({ key, value, reply })),
    }
    const outcome = original
      ? await run(() => api.updateGroup(original.name, body))
      : await run(() => api.createGroup(body))
    if (outcome) {
      setEditing(null)
      setNotice({ kind: 'ok', text: `Group ${outcome.name} saved.` })
      await status.reload()
    }
  }

  async function remove(group: Group) {
    const outcome = await run(() => api.deleteGroup(group.name))
    if (outcome) {
      setPendingDelete(null)
      const orphaned = memberCounts[group.name]
      setNotice({
        kind: 'ok',
        text: orphaned
          ? `Group ${group.name} deleted. ${orphaned} user(s) still reference it and now have no group attributes.`
          : `Group ${group.name} deleted.`,
      })
      await status.reload()
    }
  }

  return (
    <div className="space-y-6">
      <header className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-lg font-semibold text-slate-100">Groups</h1>
          <p className="text-sm text-slate-400">
            Named bundles of attributes that users join with{' '}
            <code className="text-slate-300">Group = name</code> in their account.
          </p>
        </div>
        {can.canOperate ? (
          <button type="button" className="btn-primary" onClick={() => setEditing(emptyDraft())}>
            Add group
          </button>
        ) : null}
      </header>

      {!groupfileEnabled && status.data ? (
        <Notice kind="warn">
          <strong>FreeRADIUS is not reading this file.</strong>{' '}
          The <code>files</code> module at <code>{status.data.module_file}</code> has no active{' '}
          <code>groupfile</code> directive, so groups saved here have no effect on
          authentication. Re-run <code>backend/scripts/install.sh</code> to enable it.
        </Notice>
      ) : null}

      {notice ? (
        <Notice kind={notice.kind} onDismiss={() => setNotice(null)}>
          {notice.text}
        </Notice>
      ) : null}

      {status.loading ? <Spinner label="Loading groups" /> : null}

      {status.error ? <ErrorBanner message={status.error} onRetry={status.reload} /> : null}

      {groups.length === 0 && !status.loading && !status.error ? (
        <EmptyState>No groups defined yet.</EmptyState>
      ) : null}

      {groups.length > 0 ? (
        <div className="table-wrap">
          <table className="min-w-full">
            <thead className="bg-slate-800">
              <tr>
                <th className="px-4 py-2 text-left text-xs font-semibold uppercase text-slate-300">
                  Group
                </th>
                <th className="px-4 py-2 text-left text-xs font-semibold uppercase text-slate-300">
                  Attributes
                </th>
                <th className="px-4 py-2 text-left text-xs font-semibold uppercase text-slate-300">
                  Members
                </th>
                {can.canOperate ? (
                  <th className="px-4 py-2 text-right text-xs font-semibold uppercase text-slate-300">
                    Actions
                  </th>
                ) : null}
              </tr>
            </thead>
            <tbody>
              {groups.map((group) => (
                <tr key={group.name} className="border-t border-slate-700">
                  <td className="px-4 py-2 text-sm text-slate-100">
                    <span className="font-medium">{group.name}</span>
                    {group.is_default ? (
                      <span className="ml-2 text-xs text-slate-400">(catch-all)</span>
                    ) : null}
                  </td>
                  <td className="px-4 py-2 text-sm text-slate-300">
                    {group.attributes.length === 0 ? (
                      <span className="text-slate-500">none</span>
                    ) : (
                      <ul className="space-y-0.5">
                        {group.attributes.map((attribute) => (
                          <li key={`${attribute.key}-${attribute.value}`}>
                            <code>
                              {attribute.reply ? 'reply:' : ''}
                              {attribute.key} = {attribute.value}
                            </code>
                          </li>
                        ))}
                      </ul>
                    )}
                  </td>
                  <td className="px-4 py-2 text-sm text-slate-300">
                    {group.is_default ? (
                      <span className="text-slate-500">all</span>
                    ) : (
                      memberCounts[group.name] ?? 0
                    )}
                  </td>
                  {can.canOperate ? (
                    <td className="px-4 py-2 text-right">
                      <div className="flex justify-end gap-2">
                        <button
                          type="button"
                          className="btn-ghost"
                          disabled={group.is_default || pending}
                          title={
                            group.is_default
                              ? 'DEFAULT is managed implicitly'
                              : `Edit ${group.name}`
                          }
                          onClick={() => setEditing(draftFrom(group))}
                        >
                          Edit
                        </button>
                        <button
                          type="button"
                          className="btn-ghost"
                          disabled={group.is_default || pending}
                          onClick={() => setPendingDelete(group)}
                        >
                          Delete
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

      {editing ? (
        <GroupEditor
          draft={editing}
          // Editing an existing group keeps the name read-only; creating one
          // lets it be typed. An existing name resolves to the group it names.
          original={groups.find((group) => group.name === editing.name)}
          pending={pending}
          error={error}
          onChange={setEditing}
          onCancel={() => setEditing(null)}
          onSave={() => save(editing, groups.find((group) => group.name === editing.name))}
        />
      ) : null}

      {pendingDelete ? (
        <ConfirmDialog
          title={`Delete group ${pendingDelete.name}?`}
          confirmLabel="Delete"
          pending={pending}
          onCancel={() => setPendingDelete(null)}
          onConfirm={() => remove(pendingDelete)}
          message={
            <>
              <p>
                This removes the group definition. Users that reference it keep their{' '}
                <code>Group = {pendingDelete.name}</code> line but will receive none of its
                attributes, so their access may change.
              </p>
              {memberCounts[pendingDelete.name] ? (
                <p className="mt-2 text-amber-300">
                  {memberCounts[pendingDelete.name]} user(s) currently reference this group.
                </p>
              ) : null}
            </>
          }
        />
      ) : null}
    </div>
  )
}

function GroupEditor({
  draft,
  original,
  pending,
  error,
  onChange,
  onCancel,
  onSave,
}: {
  draft: Draft
  original: Group | undefined
  pending: boolean
  error: string | null
  onChange: (draft: Draft) => void
  onCancel: () => void
  onSave: () => void
}) {
  const [nameError, setNameError] = useState<string | null>(null)

  function submit(event: FormEvent) {
    event.preventDefault()
    const name = draft.name.trim()
    if (!name) {
      setNameError('Group name is required')
      return
    }
    if (name === 'DEFAULT') {
      setNameError('DEFAULT is managed implicitly and cannot be edited here')
      return
    }
    const blank = draft.attributes.findIndex((a) => !a.key.trim() || !a.value.trim())
    if (blank !== -1) {
      setNameError(`Attribute ${blank + 1} needs both a name and a value`)
      return
    }
    setNameError(null)
    onSave()
  }

  function update(index: number, patch: Partial<GroupAttribute>) {
    const next = draft.attributes.slice()
    next[index] = { ...next[index]!, ...patch }
    onChange({ ...draft, attributes: next })
  }

  return (
    <Modal
      title={original ? `Edit group ${original.name}` : 'Add group'}
      onClose={onCancel}
      footer={
        <>
          <button type="button" className="btn-ghost" onClick={onCancel} disabled={pending}>
            Cancel
          </button>
          <button type="submit" form="group-editor" className="btn-primary" disabled={pending}>
            {pending ? 'Saving…' : 'Save'}
          </button>
        </>
      }
    >
      <form id="group-editor" className="space-y-4" onSubmit={submit}>
        <div>
          <label className="label" htmlFor="group-name">
            Name
          </label>
          <input
            id="group-name"
            className="input"
            value={draft.name}
            readOnly={original !== undefined}
            onChange={(event) => onChange({ ...draft, name: event.target.value })}
            placeholder="staff"
          />
          {nameError ? <p className="mt-1 text-xs text-red-300">{nameError}</p> : null}
        </div>

        <div>
          <div className="flex items-center justify-between">
            <span className="label">Attributes</span>
            <button
              type="button"
              className="btn-ghost"
              onClick={() =>
                onChange({
                  ...draft,
                  attributes: [...draft.attributes, { key: '', value: '', reply: false }],
                })
              }
            >
              Add attribute
            </button>
          </div>

          {draft.attributes.length === 0 ? (
            <p className="mt-1 text-sm text-slate-500">
              A group with no attributes is valid but has no effect.
            </p>
          ) : null}

          <div className="mt-2 space-y-2">
            {draft.attributes.map((attribute, index) => (
              <div key={index} className="flex flex-wrap items-center gap-2">
                <input
                  className="input flex-1"
                  list="common-attributes"
                  aria-label={`Attribute ${index + 1} name`}
                  value={attribute.key}
                  onChange={(event) => update(index, { key: event.target.value })}
                  placeholder="Reply-Message"
                />
                <input
                  className="input flex-1"
                  aria-label={`Attribute ${index + 1} value`}
                  value={attribute.value}
                  onChange={(event) => update(index, { value: event.target.value })}
                  placeholder="welcome"
                />
                <label className="flex items-center gap-1 text-xs text-slate-400">
                  <input
                    type="checkbox"
                    checked={attribute.reply}
                    onChange={(event) => update(index, { reply: event.target.checked })}
                  />
                  reply
                </label>
                <button
                  type="button"
                  className="btn-ghost"
                  onClick={() =>
                    onChange({
                      ...draft,
                      attributes: draft.attributes.filter((_, i) => i !== index),
                    })
                  }
                >
                  Remove
                </button>
              </div>
            ))}
          </div>

          <datalist id="common-attributes">
            {COMMON_ATTRIBUTES.map((name) => (
              <option key={name} value={name} />
            ))}
          </datalist>
          <p className="mt-1 text-xs text-slate-500">
            Values cannot contain commas, quotes or backslashes: the file is one line per
            group. Attributes that change how authentication is processed (Auth-Type,
            Filename, passwords) are rejected by the server.
          </p>
        </div>

        {error ? <ErrorBanner message={error} /> : null}
      </form>
    </Modal>
  )
}