import { useState } from 'react'

import { api } from '../api'
import { useCan } from '../auth/AuthContext'
import {
  ConfirmDialog,
  EmptyState,
  ErrorBanner,
  Modal,
  Notice,
  Spinner,
  formatBytes,
  formatTimestamp,
} from '../components/ui'
import { useAction, useAsync } from '../lib/hooks'
import type { Backup, BackupDetail } from '../types'

export function BackupsPage() {
  const can = useCan()
  const backups = useAsync(() => api.backups(), [])
  const { run, pending, error: actionError } = useAction()
  const [selected, setSelected] = useState<Backup | null>(null)
  const [notice, setNotice] = useState<string | null>(null)

  // Diff is loaded on demand from GET /api/backups/{id}: the "before" bytes
  // live in the backup and the "after" side is the live file, which only the
  // service account can read, so it cannot be computed in the browser.
  const [diffId, setDiffId] = useState<string | null>(null)
  const detail = useAsync<BackupDetail | null>(
    () => (diffId ? api.backup(diffId) : Promise.resolve(null)),
    [diffId],
  )

  // The endpoint wraps the list in {backups, count}; calling .map() on the
  // envelope throws during render and blanks the page.
  const rows = backups.data?.backups ?? []

  function backupSize(backup: Backup): number {
    return Object.values(backup.files ?? {}).reduce((sum, f) => sum + (f.size ?? 0), 0)
  }

  async function confirmRollback() {
    if (!selected) return
    const id = selected.id
    const label = selected.notes ?? id
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
                  <td className="td tabular-nums text-slate-400">
                    {formatBytes(backupSize(backup))}
                  </td>
                  <td className="td">
                    {Object.values(backup.files ?? {}).every((f) => f.sha256) ? (
                      <span className="badge-muted" title="Content-addressed, immutable">
                        sha256
                      </span>
                    ) : (
                      <span className="badge-warn" title="No checksum recorded">
                        none
                      </span>
                    )}
                  </td>
                  <td className="td text-right">
                    <button
                      type="button"
                      className="btn-secondary"
                      onClick={() => setDiffId(backup.id)}
                      disabled={detail.loading}
                    >
                      Diff
                    </button>
                    {can.isAdmin ? (
                      <button
                        type="button"
                        className="btn-secondary ml-2"
                        onClick={() => setSelected(backup)}
                        disabled={pending}
                      >
                        Restore
                      </button>
                    ) : (
                      <span className="ml-2 text-slate-500">admin only</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {diffId ? (
        <Modal
          title={`Changes since ${diffId}`}
          onClose={() => setDiffId(null)}
          footer={
            <button type="button" className="btn-secondary" onClick={() => setDiffId(null)}>
              Close
            </button>
          }
        >
          {detail.loading ? <Spinner label="Computing diff" /> : null}
          {detail.error ? (
            <ErrorBanner message={detail.error} onRetry={() => void detail.reload()} />
          ) : null}
          {detail.data ? (
            detail.data.changed ? (
              <div className="space-y-4">
                <p className="text-sm text-slate-400">
                  What this backup captured, compared with the live file now. Restoring would put
                  the left-hand side back.
                </p>
                {detail.data.diff.map((entry) => (
                  <div key={entry.label}>
                    <h3 className="mb-1 text-xs font-semibold uppercase tracking-wide text-slate-400">
                      {entry.label}
                      <span className="ml-2 font-normal normal-case text-slate-500">
                        {entry.path}
                      </span>
                    </h3>
                    <DiffView text={entry.diff} />
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-sm text-slate-400">
                The live file is byte-identical to this backup, so restoring it would change
                nothing.
              </p>
            )
          ) : null}
        </Modal>
      ) : null}

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

/** Colour a unified diff line by its prefix. Monospace keeps columns aligned. */
function DiffView({ text }: { text: string }) {
  const lines = text.split('\n')
  return (
    <pre className="max-h-80 overflow-auto rounded border border-slate-800 bg-slate-950 p-2 text-xs leading-relaxed">
      {lines.map((line, index) => {
        const tone = line.startsWith('+')
          ? 'text-emerald-300'
          : line.startsWith('-')
            ? 'text-rose-300'
            : line.startsWith('@@')
              ? 'text-sky-300'
              : 'text-slate-400'
        return (
          <div key={index} className={tone}>
            {line || ' '}
          </div>
        )
      })}
    </pre>
  )
}