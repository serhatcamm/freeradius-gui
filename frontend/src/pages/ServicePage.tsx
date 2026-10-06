import { useState } from 'react'

import { api } from '../api'
import { useCan } from '../auth/AuthContext'
import {
  ConfirmDialog,
  ErrorBanner,
  Notice,
  Spinner,
  StatusBadge,
} from '../components/ui'
import { useAction, useAsync } from '../lib/hooks'
import type { ListeningSocket, ValidationResult } from '../types'

/**
 * Render the listening sockets. These arrive as objects
 * ({protocol, port, role}); calling .join() on them throws during render and
 * takes the whole page down to a blank screen.
 */
export function describePorts(ports: ListeningSocket[] | undefined): string {
  if (!Array.isArray(ports) || ports.length === 0) return 'no ports'
  return ports
    .map((p) => {
      const proto = p?.protocol ?? '?'
      const port = p?.port ?? '?'
      return p?.role ? `${proto}/${port} (${p.role})` : `${proto}/${port}`
    })
    .join(', ')
}

export function ServicePage() {
  const can = useCan()
  const response = useAsync(() => api.service(), [])
  const validation = useAsync(() => api.validate(), [])
  const journal = useAsync(() => api.serviceLog(200), [])
  const { run, pending, error: actionError } = useAction()

  // /api/service returns {service, server}; keep each half separate so a
  // missing field cannot blank the page.
  const service = response.data?.service ?? null
  const serverInfo = response.data?.server ?? null

  const [notice, setNotice] = useState<{ kind: 'ok' | 'warn' | 'error'; text: string } | null>(null)
  const [confirm, setConfirm] = useState<'restart' | 'reload' | null>(null)

  async function act(kind: 'restart' | 'reload') {
    setConfirm(null)
    const result = await run(() =>
      kind === 'restart' ? api.restartService() : api.reloadService(),
    )
    if (!result) return
    if (result.ok) {
      setNotice({ kind: 'ok', text: `FreeRADIUS ${kind} completed.` })
      await Promise.all([response.reload(), validation.reload(), journal.reload()])
    } else {
      setNotice({ kind: 'error', text: `FreeRADIUS ${kind} failed.` })
    }
  }

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h1 className="text-xl font-semibold">Service</h1>
        {can.isAdmin ? (
          <div className="flex gap-2">
            <button
              type="button"
              className="btn-secondary"
              onClick={() => setConfirm('reload')}
              disabled={pending}
            >
              Reload
            </button>
            <button
              type="button"
              className="btn-danger"
              onClick={() => setConfirm('restart')}
              disabled={pending}
            >
              Restart
            </button>
          </div>
        ) : (
          <span className="text-sm text-slate-500">Restart requires the admin role.</span>
        )}
      </div>

      {notice ? (
        <Notice kind={notice.kind} onDismiss={() => setNotice(null)}>
          {notice.text}
        </Notice>
      ) : null}
      {actionError ? <ErrorBanner message={actionError} /> : null}

      {response.error ? (
        <ErrorBanner message={response.error} onRetry={() => void response.reload()} />
      ) : null}

      {response.loading ? (
        <Spinner label="Reading service state" />
      ) : service ? (
        <section className="card p-5">
          <div className="flex flex-wrap items-center justify-between gap-4">
            <div>
              <h2 className="flex items-center gap-2 text-lg font-semibold">
                {service.unit ?? 'freeradius.service'}
                <StatusBadge active={service.systemd_state === 'active'} />
              </h2>
              <p className="mt-1 text-sm text-slate-400">
                {serverInfo?.hostname ?? ''}
                {serverInfo?.freeradius_version ? ` · FreeRADIUS ${serverInfo.freeradius_version}` : ''}
              </p>
            </div>
            <div className="text-right text-sm text-slate-400">
              <div>
                pid {service.pid ?? '—'}
                {service.active_since ? ` · up since ${service.active_since}` : ''}
              </div>
              <div className="mt-1 text-xs">
                listening on {describePorts(service.listening_ports)}
              </div>
            </div>
          </div>
          {service.error ? (
            <p className="mt-3 text-sm text-red-300">{service.error}</p>
          ) : null}
        </section>
      ) : null}

      <ValidationCard
        result={validation.data}
        loading={validation.loading}
        onRun={() => void validation.reload()}
      />

      <section className="card p-5">
        <div className="mb-3 flex items-center justify-between">
          <h2 className="text-sm font-semibold uppercase tracking-wide text-slate-400">
            Recent journal entries
          </h2>
          <button type="button" className="btn-secondary" onClick={() => void journal.reload()}>
            Refresh
          </button>
        </div>
        {journal.loading ? (
          <Spinner label="Reading journal" />
        ) : journal.error ? (
          <ErrorBanner message={journal.error} onRetry={() => void journal.reload()} />
        ) : (
          <pre className="max-h-96 overflow-auto rounded-md bg-slate-950 p-3 font-mono text-xs leading-relaxed text-slate-300">
            {(journal.data?.lines ?? []).join('\n') || 'No entries.'}
          </pre>
        )}
      </section>

      {confirm ? (
        <ConfirmDialog
          title={confirm === 'restart' ? 'Restart FreeRADIUS' : 'Reload FreeRADIUS'}
          pending={pending}
          confirmLabel={confirm === 'restart' ? 'Restart' : 'Reload'}
          message={
            <>
              <p>
                This runs{' '}
                <code>systemctl {confirm} freeradius</code> through the panel's narrow sudo rule.
              </p>
              <p className="mt-2 text-slate-400">
                {confirm === 'restart'
                  ? 'Active sessions are dropped. Prefer a reload after a configuration change.'
                  : 'The configuration is re-read without dropping active sessions.'}
              </p>
              <p className="mt-2 text-xs text-slate-500">
                Validate the configuration first if you have not already.
              </p>
            </>
          }
          onCancel={() => setConfirm(null)}
          onConfirm={() => void act(confirm)}
        />
      ) : null}
    </div>
  )
}

function ValidationCard({
  result,
  loading,
  onRun,
}: {
  result: ValidationResult | null
  loading: boolean
  onRun: () => void
}) {
  return (
    <section className="card p-5">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h2 className="text-sm font-semibold uppercase tracking-wide text-slate-400">
          Configuration validation
        </h2>
        <button type="button" className="btn-primary" onClick={onRun} disabled={loading}>
          {loading ? 'Running…' : 'Run freeradius -XC'}
        </button>
      </div>

      {result ? (
        <div className="mt-4 space-y-3">
          <div className="flex items-center gap-3">
            <span className={result.ok ? 'badge-ok' : 'badge-err'}>
              {result.ok ? 'valid' : 'invalid'}
            </span>
            <span className="text-sm text-slate-400">
              exit {result.returncode} · {result.summary}
            </span>
          </div>
          {result.issues.length > 0 ? (
            <div className="table-wrap max-h-72 overflow-y-auto">
              <table className="min-w-full">
                <thead className="bg-slate-800">
                  <tr>
                    <th className="th">File</th>
                    <th className="th">Line</th>
                    <th className="th">Severity</th>
                    <th className="th">Message</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800">
                  {result.issues.map((issue, index) => (
                    <tr key={index}>
                      <td className="td font-mono text-xs">{issue.file ?? '—'}</td>
                      <td className="td font-mono text-xs">{issue.line ?? '—'}</td>
                      <td className="td">
                        <span
                          className={
                            issue.severity === 'error'
                              ? 'badge-err'
                              : issue.severity === 'warning'
                                ? 'badge-warn'
                                : 'badge-muted'
                          }
                        >
                          {issue.severity ?? 'info'}
                        </span>
                      </td>
                      <td className="td">{issue.message ?? '—'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <p className="text-sm text-slate-400">No issues reported.</p>
          )}
        </div>
      ) : (
        <p className="mt-3 text-sm text-slate-400">
          Runs the real parser against the live configuration. Every write is validated the same way
          before it is applied.
        </p>
      )}
    </section>
  )
}