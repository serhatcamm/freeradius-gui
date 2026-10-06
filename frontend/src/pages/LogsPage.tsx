import { useMemo, useState } from 'react'
import type { FormEvent } from 'react'

import { api } from '../api'
import { useCan } from '../auth/AuthContext'
import { EmptyState, ErrorBanner, Notice, Spinner } from '../components/ui'
import { useAction, useAsync } from '../lib/hooks'
import type { LogEvent } from '../types'

export function LogsPage() {
  const can = useCan()
  const [notice, setNotice] = useState<{ kind: 'ok' | 'warn' | 'error'; text: string } | null>(null)
  const [username, setUsername] = useState('')
  const [result, setResult] = useState('')
  const [hours, setHours] = useState('24')
  const { run, pending, error: actionError } = useAction()

  const events = useAsync(() => api.logs({ hours: Number(hours) || 24 }), [hours])
  const capability = useAsync(() => api.logCapability(), [])

  const rows = events.data?.events ?? []
  const totals = useMemo(() => countResults(rows), [rows])

  async function toggleLogging() {
    const enabled = !capability.data?.available
    const result = enabled
      ? await run(() => api.enableRequestLogging())
      : await run(() => api.disableRequestLogging())
    if (!result) return
    if (result.ok) {
      setNotice({ kind: 'ok', text: result.message ?? `Request logging ${enabled ? 'enabled' : 'disabled'}.` })
    } else {
      setNotice({
        kind: 'error',
        text: result.error ?? 'The change could not be applied.',
      })
    }
    await Promise.all([capability.reload(), events.reload()])
  }

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h1 className="text-xl font-semibold">Logs</h1>
        <div className="flex items-center gap-2">
          <select
            className="input w-32"
            value={hours}
            onChange={(event) => setHours(event.target.value)}
            aria-label="Time window"
          >
            <option value="1">Last hour</option>
            <option value="6">Last 6 hours</option>
            <option value="24">Last 24 hours</option>
            <option value="168">Last 7 days</option>
          </select>
          <button type="button" className="btn-secondary" onClick={() => void events.reload()}>
            Refresh
          </button>
        </div>
      </div>

      {notice ? (
        <Notice kind={notice.kind} onDismiss={() => setNotice(null)}>
          {notice.text}
        </Notice>
      ) : null}
      {actionError ? <ErrorBanner message={actionError} /> : null}

      <RequestLoggingCard
        capability={capability.data}
        loading={capability.loading}
        canOperate={can.canOperate}
        pending={pending}
        onToggle={() => void toggleLogging()}
      />

      <div className="grid gap-3 sm:grid-cols-3">
        <ResultCount label="Access-Accept" value={totals.accept} tone="ok" />
        <ResultCount label="Access-Reject" value={totals.reject} tone="err" />
        <ResultCount label="No response" value={totals.other} tone="warn" />
      </div>

      <div className="grid gap-4 sm:grid-cols-2">
        <div>
          <label className="label" htmlFor="log-username">
            Filter by username
          </label>
          <input
            id="log-username"
            className="input"
            value={username}
            onChange={(event) => setUsername(event.target.value)}
            placeholder="substring match"
          />
        </div>
        <div>
          <label className="label" htmlFor="log-result">
            Filter by result
          </label>
          <select
            id="log-result"
            className="input"
            value={result}
            onChange={(event) => setResult(event.target.value)}
          >
            <option value="">All results</option>
            <option value="Access-Accept">Access-Accept</option>
            <option value="Access-Reject">Access-Reject</option>
          </select>
        </div>
      </div>

      {events.error ? <ErrorBanner message={events.error} onRetry={() => void events.reload()} /> : null}

      {events.loading ? (
        <Spinner label="Reading logs" />
      ) : (
        <LogTable
          events={rows}
          sources={events.data?.source_paths ?? []}
          totalLines={events.data?.total_lines ?? 0}
          usernameFilter={username}
          resultFilter={result}
        />
      )}

      <RadiusTestCard canOperate={can.canOperate} />
    </div>
  )
}

function RequestLoggingCard({
  capability,
  loading,
  canOperate,
  pending,
  onToggle,
}: {
  capability: Awaited<ReturnType<typeof api.logCapability>> | null
  loading: boolean
  canOperate: boolean
  pending: boolean
  onToggle: () => void
}) {
  if (loading) return null
  const available = Boolean(capability?.available)
  const logFile = capability?.log_file ?? '—'

  return (
    <section className="card p-5">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div className="min-w-0">
          <h2 className="flex items-center gap-2 text-sm font-semibold uppercase tracking-wide text-slate-400">
            Request logging
            <span className={available ? 'badge-ok' : 'badge-muted'}>
              {available ? 'active' : 'inactive'}
            </span>
          </h2>
          <p className="mt-1 text-sm text-slate-400">
            Enabling installs the linelog hooks and the SQL log module so every authentication
            attempt is recorded, then reloads FreeRADIUS.
          </p>
          <p className="mt-2 text-xs text-slate-500">
            Log file: <code>{logFile}</code>
            {capability?.writable === false ? ' (not writable by the panel user)' : ''}
          </p>
          {!available && capability?.reason ? (
            <p className="mt-2 text-xs text-amber-300">{capability.reason}</p>
          ) : null}
        </div>
        {canOperate ? (
          <button
            type="button"
            className={available ? 'btn-secondary' : 'btn-primary'}
            onClick={onToggle}
            disabled={pending}
          >
            {pending ? 'Working…' : available ? 'Disable request logging' : 'Enable request logging'}
          </button>
        ) : null}
      </div>
    </section>
  )
}

function ResultCount({
  label,
  value,
  tone,
}: {
  label: string
  value: number
  tone: 'ok' | 'err' | 'warn'
}) {
  const badge = tone === 'ok' ? 'badge-ok' : tone === 'err' ? 'badge-err' : 'badge-warn'
  return (
    <div className="card flex items-center justify-between px-4 py-3">
      <span className="text-sm text-slate-400">{label}</span>
      <span className={badge}>{value}</span>
    </div>
  )
}

function LogTable({
  events,
  sources,
  totalLines,
  usernameFilter,
  resultFilter,
}: {
  events: LogEvent[]
  sources: string[]
  totalLines: number
  usernameFilter: string
  resultFilter: string
}) {
  const filtered = useMemo(() => {
    const needle = usernameFilter.trim().toLowerCase()
    return events.filter((event) => {
      if (resultFilter && event.result !== resultFilter) return false
      if (needle && !(event.username ?? '').toLowerCase().includes(needle)) return false
      return true
    })
  }, [events, usernameFilter, resultFilter])

  if (filtered.length === 0) {
    return (
      <EmptyState>
        No matching log lines.
        {events.length > 0 ? ` ${events.length} other lines are hidden by the filters.` : ''}
      </EmptyState>
    )
  }

  return (
    <div className="space-y-2">
      <div className="text-xs text-slate-500">
        Showing {filtered.length} of {events.length} recent events ({totalLines} lines scanned).
        {sources.length > 0 ? ` Sources: ${sources.join(', ')}` : ''}
      </div>
      <div className="table-wrap max-h-[32rem] overflow-y-auto">
        <table className="min-w-full divide-y divide-slate-700">
          <thead className="sticky top-0 bg-slate-800">
            <tr>
              <th className="th">Time</th>
              <th className="th">Result</th>
              <th className="th">Username</th>
              <th className="th">NAS / client</th>
              <th className="th">Message</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800 bg-slate-900/40">
            {filtered.map((event, index) => (
              <tr key={`${event.timestamp ?? 'x'}-${index}`}>
                <td className="td font-mono text-xs text-slate-400">
                  {event.timestamp ? event.timestamp.replace('T', ' ').slice(0, 19) : '—'}
                </td>
                <td className="td">
                  <ResultBadge result={event.result} severity={event.severity} />
                </td>
                <td className="td font-medium text-slate-100">{event.username ?? '—'}</td>
                <td className="td text-slate-400">
                  {event.nas_ip ?? event.client ?? '—'}
                  {event.client && event.nas_ip ? (
                    <span className="ml-2 badge-muted">{event.client}</span>
                  ) : null}
                </td>
                <td className="td max-w-md truncate" title={event.message}>
                  {event.message}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}

function ResultBadge({ result, severity }: { result?: string | null; severity: string }) {
  if (result === 'Access-Accept') return <span className="badge-ok">accept</span>
  if (result === 'Access-Reject') return <span className="badge-err">reject</span>
  const tone = severity === 'error' ? 'badge-err' : severity === 'warn' ? 'badge-warn' : 'badge-muted'
  return <span className={tone}>{result ?? severity}</span>
}

function RadiusTestCard({ canOperate }: { canOperate: boolean }) {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const { run, pending, error } = useAction()
  const [result, setResult] = useState<Awaited<ReturnType<typeof api.radiusTest>> | null>(null)

  async function onSubmit(event: FormEvent) {
    event.preventDefault()
    const outcome = await run(() => api.radiusTest(username, password))
    if (outcome) {
      setResult(outcome)
      setPassword('')
    }
  }

  return (
    <section className="card p-5">
      <h2 className="text-sm font-semibold uppercase tracking-wide text-slate-400">
        Authenticate a user
      </h2>
      <p className="mt-1 text-sm text-slate-400">
        Sends a real RADIUS Access-Request to the local server and shows the reply. Useful for
        checking a credential after an edit.
      </p>

      {!canOperate ? (
        <p className="mt-3 text-sm text-slate-500">Requires the operator role.</p>
      ) : (
        <form className="mt-4 grid gap-4 sm:grid-cols-[1fr_1fr_auto]" onSubmit={onSubmit}>
          <div>
            <label className="label" htmlFor="test-username">
              Username
            </label>
            <input
              id="test-username"
              className="input"
              value={username}
              onChange={(event) => setUsername(event.target.value)}
              required
            />
          </div>
          <div>
            <label className="label" htmlFor="test-password">
              Password
            </label>
            <input
              id="test-password"
              className="input"
              type="password"
              autoComplete="off"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              required
            />
          </div>
          <div className="flex items-end">
            <button type="submit" className="btn-primary" disabled={pending}>
              {pending ? 'Testing…' : 'Test'}
            </button>
          </div>
        </form>
      )}

      {error ? (
        <div className="mt-3">
          <ErrorBanner message={error} />
        </div>
      ) : null}

      {result ? (
        <div className="mt-4 space-y-2 border-t border-slate-700 pt-4 text-sm">
          <div className="flex items-center gap-3">
            <span className={result.error ? 'badge-err' : 'badge-ok'}>{result.result}</span>
            <span className="text-slate-400">
              {result.response_time_ms.toFixed(2)} ms · {result.username} @ {result.server}:{result.port}
            </span>
          </div>
          {result.error ? <p className="text-red-300">{result.error}</p> : null}
          {result.returned_attributes.length > 0 ? (
            <div className="table-wrap">
              <table className="min-w-full">
                <thead className="bg-slate-800">
                  <tr>
                    <th className="th">Reply attribute</th>
                    <th className="th">Value</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800">
                  {result.returned_attributes.map((attribute, index) => (
                    <tr key={index}>
                      <td className="td font-mono text-xs">{attribute['Name'] ?? '—'}</td>
                      <td className="td font-mono text-xs">{attribute['Value'] ?? '—'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : null}
        </div>
      ) : null}
    </section>
  )
}

function countResults(events: LogEvent[]) {
  let accept = 0
  let reject = 0
  let other = 0
  for (const event of events) {
    if (event.result === 'Access-Accept') accept += 1
    else if (event.result === 'Access-Reject') reject += 1
    else other += 1
  }
  return { accept, reject, other }
}