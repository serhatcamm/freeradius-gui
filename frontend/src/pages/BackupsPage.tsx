import { useState } from 'react'

import { api } from '../api'
import { useCan } from '../auth/AuthContext'
import {
  ConfirmDialog,
  EmptyState,
  ErrorBanner,
  Notice,
  Spinner,
  formatBytes,
  formatTimestamp,
} from '../components/ui'
import { useAction, useAsync } from '../lib/hooks'
import type { Backup } from '../types'

export function BackupsPage() {
  const can = useCan()
  const backups = useAsync(() => api.backups(), [])
  const { run, pending, error: actionError } = useAction()
  const [selected, setSelected] = useState<Backup | null>(null)
  const [notice, setNotice] = useState<string | null>(null)

  // The endpoint wraps the list in {backups, count}; calling .map() on the
  // envelope throws during render and blanks the page.
  const rows = backups.data?.backups ?? []

  async function confirmRollback() {
    if (!selected) return
    const id = selected.id
    const label = selected.label ?? id
    setSelected(null)
    const result = await run(() => api.rollback(id))
    if (result?.ok) {
      setNotice(`Restored ${label}. Validate the configuration before reloading FreeRADIUS.`)
      await backups.reload()
    }
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-semibold">Backups</h1>
        <button type="button" className="btn-secondary" onClick={() => void backups.reload()}>
          Refresh
        </button>
      </div>

      {notice ? <Notice onDismiss={() => setNotice(null)}>{notice}</Notice> : null}
      {actionError ? <ErrorBanner message={actionError} /> : null}
      {backups.error ? (
        <ErrorBanner message={backups.error} onRetry={() => void backups.reload()} />
      ) : null}

      {backups.loading ? (
        <Spinner label="Loading backups" />
      ) : rows.length === 0 ? (
        <EmptyState>
          No backups yet. One is created automatically before the panel changes any configuration
          file.
        </EmptyState>
      ) : (
        <div className="table-wrap">
          <table className="min-w-full divide-y divide-slate-700">
            <thead className="bg-slate-800/80">
              <tr>
                <th className="th">Label</th>
                <th className="th">Operation</th>
                <th className="th">Administrator</th>
                <th className="th">Created</th>
                <th className="th">Size</th>
                <th className="th">Integrity</th>
                <th className="th text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800 bg-slate-900/40">
              {rows.map((backup) => (
                <tr key={backup.id}>
                  <td className="td">
                    <code className="text-xs text-slate-200">{backup.id}</code>
                    {backup.notes ? (
                      <div className="mt-0.5 text-xs text-slate-400">{backup.notes}</div>
                    ) : null}
                  </td>
                  <td className="td">{backup.operation ?? '—'}</td>
                  <td className="td text-slate-400">{backup.administrator ?? '—'}</td>
                  <td className="td text-slate-400">{formatTimestamp(backup.created_at)}</td>
                  <td className="td tabular-nums text-slate-400">{formatBytes(backup.size_bytes)}</td>
                  <td className="td">
                    <span className="badge-muted" title={backup.sha256}>
                      sha256
                    </span>
                  </td>
                  <td className="td text-right">
                    {can.isAdmin ? (
                      <button
                        type="button"
                        className="btn-secondary"
                        onClick={() => setSelected(backup)}
                        disabled={pending}
                      >
                        Restore
                      </button>
                    ) : (
                      <span className="text-slate-500">admin only</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {selected ? (
        <ConfirmDialog
          title="Restore backup"
          pending={pending}
          confirmLabel="Restore"
          message={
            <>
              <p>
                The contents of <code>{selected.id}</code> will overwrite the current file. The
                current version is backed up first, so this can be undone.
              </p>
              <p className="mt-2 text-slate-400">
                FreeRADIUS is <strong>not</strong> restarted automatically. Validate the
                configuration, then reload from the Service page.
              </p>
            </>
          }
          onCancel={() => setSelected(null)}
          onConfirm={() => void confirmRollback()}
        />
      ) : null}
    </div>
  )
}