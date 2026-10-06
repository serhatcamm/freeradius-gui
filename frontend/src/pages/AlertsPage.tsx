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
import type { Alert, AlertMetric, AlertRule } from '../types'

const METRICS: { value: AlertMetric; label: string }[] = [
  { value: 'failures', label: 'Failed authentications' },
  { value: 'successes', label: 'Successful authentications' },
  { value: 'challenges', label: 'Challenges issued' },
  { value: 'total', label: 'All attempts' },
]

/** Window choices that map onto seconds without the user doing arithmetic. */
const WINDOWS = [
  { seconds: 300, label: '5 minutes' },
  { seconds: 900, label: '15 minutes' },
  { seconds: 3600, label: '1 hour' },
  { seconds: 21600, label: '6 hours' },
  { seconds: 86400, label: '24 hours' },
  { seconds: 604800, label: '7 days' },
]

interface Draft {
  name: string
  metric: AlertMetric
  threshold: number
  windowLabel: string
  username: string
  client: string
}

function emptyDraft(): Draft {
  return {
    name: '',
    metric: 'failures',
    threshold: 5,
    windowLabel: '15 minutes',
    username: '',
    client: '',
  }
}

function draftFrom(rule: AlertRule): Draft {
  return {
    name: rule.name,
    metric: rule.metric,
    threshold: rule.threshold,
    windowLabel: (
      WINDOWS.find((w) => w.seconds === rule.window_seconds)?.label ?? '15 minutes'
    ),
    username: rule.username ?? '',
    client: rule.client ?? '',
  }
}

function windowSeconds(label: string): number {
  return WINDOWS.find((w) => w.label === label)?.seconds ?? 900
}

function describeWindow(seconds: number): string {
  return WINDOWS.find((w) => w.seconds === seconds)?.label ?? `${seconds}s`
}

export function AlertsPage() {
  const can = useCan()
  const rules = useAsync(() => api.alertRules(), [])
  const alerts = useAsync(() => api.alerts(), [])
  const { run, pending, error: actionError } = useAction()
  const [notice, setNotice] = useState<string | null>(null)
  const [editing, setEditing] = useState<Draft | null>(null)
  const [deleting, setDeleting] = useState<AlertRule | null>(null)
  const [ackAll, setAckAll] = useState<Alert | null>(null)

  const ruleRows = rules.data ?? []
  const alertRows = alerts.data?.alerts ?? []
  const unacknowledged = alertRows.filter((a) => !a.acknowledged_at)

  async function reload() {
    await Promise.all([rules.reload(), alerts.reload()])
  }

  async function save(draft: Draft, original?: AlertRule) {
    const body = {
      name: draft.name.trim(),
      metric: draft.metric,
      threshold: draft.threshold,
      window_seconds: windowSeconds(draft.windowLabel),
      username: draft.username.trim() || null,
      client: draft.client.trim() || null,
    }
    const outcome = original
      ? await run(() => api.updateAlertRule(original.id, body))
      : await run(() => api.createAlertRule(body))
    if (outcome) {
      setEditing(null)
      setNotice(`Alert rule ${outcome.name} saved.`)
      await reload()
    }
  }

  async function toggleEnabled(rule: AlertRule) {
    const outcome = await run(() => api.updateAlertRule(rule.id, { enabled: !rule.enabled }))
    if (outcome) {
      setNotice(`Alert rule ${outcome.name} ${outcome.enabled ? 'enabled' : 'disabled'}.`)
      await reload()
    }
  }

  async function confirmDelete() {
    if (!deleting) return
    const name = deleting.name
    setDeleting(null)
    const outcome = await run(() => api.deleteAlertRule(deleting.id))
    if (outcome) {
      setNotice(`Alert rule ${name} deleted along with its alerts.`)
      await reload()
    }
  }

  async function acknowledge(alert: Alert) {
    const outcome = await run(() => api.acknowledgeAlert(alert.id))
    if (outcome) {
      setAckAll(null)
      setNotice('Alert acknowledged.')
      await reload()
    }
  }

  return (
    <div className="space-y-6">
      <header className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-lg font-semibold text-slate-100">Alerts</h1>
          <p className="text-sm text-slate-400">
            Rules are evaluated from the authentication log whenever this page or the rule list
            is read, so an alert always reflects the log as it is now.
          </p>
        </div>
        {can.isAdmin ? (
          <button type="button" className="btn-primary" onClick={() => setEditing(emptyDraft())}>
            Add rule
          </button>
        ) : null}
      </header>

      {notice ? (
        <Notice onDismiss={() => setNotice(null)}>
          {notice}
        </Notice>
      ) : null}
      {actionError ? <ErrorBanner message={actionError} /> : null}

      {unacknowledged.length > 0 ? (
        <Notice kind="warn">
          <strong>
            {unacknowledged.length} unacknowledged alert
            {unacknowledged.length === 1 ? '' : 's'}.
          </strong>{' '}
          Rules only raise a new alert once their window has rolled over, so a condition that is
          still ongoing will not repeat here.
        </Notice>
      ) : null}

      {rules.error ? <ErrorBanner message={rules.error} onRetry={() => void reload()} /> : null}
      {alerts.error ? (
        <ErrorBanner message={alerts.error} onRetry={() => void reload()} />
      ) : null}

      <section className="space-y-3">
        <h2 className="text-sm font-semibold uppercase tracking-wide text-slate-400">Rules</h2>
        {rules.loading ? <Spinner label="Evaluating rules" /> : null}

        {!rules.loading && ruleRows.length === 0 ? (
          <EmptyState>
            No alert rules yet. A rule counts authentication events over a window and raises an
            alert when the count reaches a threshold.
          </EmptyState>
        ) : null}

        {ruleRows.length > 0 ? (
          <div className="table-wrap">
            <table className="min-w-full">
              <thead className="bg-slate-800">
                <tr>
                  <th className="px-4 py-2 text-left text-xs font-semibold uppercase text-slate-300">
                    Rule
                  </th>
                  <th className="px-4 py-2 text-left text-xs font-semibold uppercase text-slate-300">
                    Condition
                  </th>
                  <th className="px-4 py-2 text-left text-xs font-semibold uppercase text-slate-300">
                    Now
                  </th>
                  <th className="px-4 py-2 text-left text-xs font-semibold uppercase text-slate-300">
                    Last fired
                  </th>
                  {can.isAdmin ? (
                    <th className="px-4 py-2 text-right text-xs font-semibold uppercase text-slate-300">
                      Actions
                    </th>
                  ) : null}
                </tr>
              </thead>
              <tbody>
                {ruleRows.map((rule) => (
                  <tr key={rule.id} className="border-t border-slate-700">
                    <td className="px-4 py-2 text-sm text-slate-100">
                      <span className="font-medium">{rule.name}</span>
                      {!rule.enabled ? (
                        <span className="ml-2 text-xs text-slate-500">(disabled)</span>
                      ) : null}
                      {rule.username || rule.client ? (
                        <div className="text-xs text-slate-400">
                          {[
                            rule.username ? `user ${rule.username}` : null,
                            rule.client ? `client ${rule.client}` : null,
                          ]
                            .filter(Boolean)
                            .join(', ')}
                        </div>
                      ) : (
                        <div className="text-xs text-slate-500">any user or client</div>
                      )}
                    </td>
                    <td className="px-4 py-2 text-sm text-slate-300">
                      {rule.metric_label} ≥ {rule.threshold}
                      <div className="text-xs text-slate-500">
                        in {describeWindow(rule.window_seconds)}
                      </div>
                    </td>
                    <td className="px-4 py-2 text-sm">
                      <span className={rule.would_fire ? 'badge-warn' : 'badge-muted'}>
                        {rule.observed} / {rule.threshold}
                      </span>
                    </td>
                    <td className="px-4 py-2 text-sm text-slate-400">
                      {rule.last_fired_at ? formatTimestamp(rule.last_fired_at) : 'never'}
                    </td>
                    {can.isAdmin ? (
                      <td className="px-4 py-2 text-right">
                        <div className="flex justify-end gap-2">
                          <button
                            type="button"
                            className="btn-ghost"
                            disabled={pending}
                            onClick={() => void toggleEnabled(rule)}
                          >
                            {rule.enabled ? 'Disable' : 'Enable'}
                          </button>
                          <button
                            type="button"
                            className="btn-ghost"
                            disabled={pending}
                            onClick={() => setEditing(draftFrom(rule))}
                          >
                            Edit
                          </button>
                          <button
                            type="button"
                            className="btn-ghost"
                            disabled={pending}
                            onClick={() => setDeleting(rule)}
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
      </section>

      <section className="space-y-3">
        <h2 className="text-sm font-semibold uppercase tracking-wide text-slate-400">
          Raised alerts
        </h2>
        {alerts.loading ? <Spinner label="Loading alerts" /> : null}

        {!alerts.loading && alertRows.length === 0 ? (
          <EmptyState>Nothing has been raised.</EmptyState>
        ) : null}

        {alertRows.length > 0 ? (
          <div className="table-wrap">
            <table className="min-w-full">
              <thead className="bg-slate-800">
                <tr>
                  <th className="px-4 py-2 text-left text-xs font-semibold uppercase text-slate-300">
                    Raised
                  </th>
                  <th className="px-4 py-2 text-left text-xs font-semibold uppercase text-slate-300">
                    Rule
                  </th>
                  <th className="px-4 py-2 text-left text-xs font-semibold uppercase text-slate-300">
                    Observed
                  </th>
                  {can.canOperate ? (
                    <th className="px-4 py-2 text-right text-xs font-semibold uppercase text-slate-300">
                      Actions
                    </th>
                  ) : null}
                </tr>
              </thead>
              <tbody>
                {alertRows.map((alert) => (
                  <tr key={alert.id} className="border-t border-slate-700">
                    <td className="px-4 py-2 text-sm text-slate-400">
                      {formatTimestamp(alert.raised_at)}
                    </td>
                    <td className="px-4 py-2 text-sm text-slate-100">
                      {alert.rule_name}
                      <div className="text-xs text-slate-500">{alert.metric_label}</div>
                    </td>
                    <td className="px-4 py-2 text-sm text-slate-300">
                      {alert.observed} ≥ {alert.threshold}
                    </td>
                    {can.canOperate ? (
                      <td className="px-4 py-2 text-right">
                        {alert.acknowledged_at ? (
                          <span className="text-xs text-slate-500">
                            acknowledged by {alert.acknowledged_by}
                          </span>
                        ) : (
                          <button
                            type="button"
                            className="btn-ghost"
                            disabled={pending}
                            onClick={() => setAckAll(alert)}
                          >
                            Acknowledge
                          </button>
                        )}
                      </td>
                    ) : null}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : null}
      </section>

      {editing ? (
        <RuleEditor
          draft={editing}
          original={ruleRows.find((rule) => rule.name === editing.name)}
          pending={pending}
          error={actionError}
          onChange={setEditing}
          onCancel={() => setEditing(null)}
          onSave={() => save(editing, ruleRows.find((rule) => rule.name === editing.name))}
        />
      ) : null}

      {deleting ? (
        <ConfirmDialog
          title={`Delete rule ${deleting.name}?`}
          confirmLabel="Delete"
          pending={pending}
          onCancel={() => setDeleting(null)}
          onConfirm={() => void confirmDelete()}
          message={
            <p>
              The rule and every alert it has raised are removed. This cannot be undone.
            </p>
          }
        />
      ) : null}

      {ackAll ? (
        <ConfirmDialog
          title={`Acknowledge alert from ${ackAll.rule_name}?`}
          confirmLabel="Acknowledge"
          pending={pending}
          onCancel={() => setAckAll(null)}
          onConfirm={() => void acknowledge(ackAll)}
          message={
            <p>
              This records that you have seen the alert. It does not stop the rule from firing
              again after its window rolls over.
            </p>
          }
        />
      ) : null}
    </div>
  )
}

function RuleEditor({
  draft,
  original,
  pending,
  error,
  onChange,
  onCancel,
  onSave,
}: {
  draft: Draft
  original: AlertRule | undefined
  pending: boolean
  error: string | null
  onChange: (draft: Draft) => void
  onCancel: () => void
  onSave: () => void
}) {
  const [formError, setFormError] = useState<string | null>(null)
  const metric = METRICS.find((m) => m.value === draft.metric)

  function submit(event: FormEvent) {
    event.preventDefault()
    if (!draft.name.trim()) {
      setFormError('Name is required')
      return
    }
    if (!Number.isInteger(draft.threshold) || draft.threshold < 1) {
      setFormError('Threshold must be a whole number of at least 1')
      return
    }
    setFormError(null)
    onSave()
  }

  return (
    <Modal
      title={original ? `Edit rule ${original.name}` : 'Add alert rule'}
      onClose={onCancel}
      footer={
        <>
          <button type="button" className="btn-ghost" onClick={onCancel} disabled={pending}>
            Cancel
          </button>
          <button type="submit" form="alert-rule-editor" className="btn-primary" disabled={pending}>
            {pending ? 'Saving…' : 'Save'}
          </button>
        </>
      }
    >
      <form id="alert-rule-editor" className="space-y-4" onSubmit={submit}>
        <div>
          <label className="label" htmlFor="rule-name">
            Name
          </label>
          <input
            id="rule-name"
            className="input"
            value={draft.name}
            readOnly={original !== undefined}
            onChange={(event) => onChange({ ...draft, name: event.target.value })}
            placeholder="wifi brute force"
          />
        </div>

        <div>
          <label className="label" htmlFor="rule-metric">
            Count
          </label>
          <select
            id="rule-metric"
            className="input"
            value={draft.metric}
            onChange={(event) =>
              onChange({ ...draft, metric: event.target.value as AlertMetric })
            }
          >
            {METRICS.map((m) => (
              <option key={m.value} value={m.value}>
                {m.label}
              </option>
            ))}
          </select>
        </div>

        <div className="grid gap-4 sm:grid-cols-2">
          <div>
            <label className="label" htmlFor="rule-threshold">
              Raise when count reaches
            </label>
            <input
              id="rule-threshold"
              className="input"
              type="number"
              min={1}
              value={draft.threshold}
              onChange={(event) =>
                onChange({ ...draft, threshold: Number(event.target.value) })
              }
            />
          </div>
          <div>
            <label className="label" htmlFor="rule-window">
              Within
            </label>
            <select
              id="rule-window"
              className="input"
              value={draft.windowLabel}
              onChange={(event) => onChange({ ...draft, windowLabel: event.target.value })}
            >
              {WINDOWS.map((w) => (
                <option key={w.seconds} value={w.label}>
                  {w.label}
                </option>
              ))}
            </select>
          </div>
        </div>

        <div className="grid gap-4 sm:grid-cols-2">
          <div>
            <label className="label" htmlFor="rule-username">
              RADIUS user <span className="font-normal text-slate-500">(optional)</span>
            </label>
            <input
              id="rule-username"
              className="input"
              value={draft.username}
              autoComplete="off"
              onChange={(event) => onChange({ ...draft, username: event.target.value })}
              placeholder="any user"
            />
          </div>
          <div>
            <label className="label" htmlFor="rule-client">
              Client <span className="font-normal text-slate-500">(optional)</span>
            </label>
            <input
              id="rule-client"
              className="input"
              value={draft.client}
              autoComplete="off"
              onChange={(event) => onChange({ ...draft, client: event.target.value })}
              placeholder="any client"
            />
          </div>
        </div>

        <p className="text-xs text-slate-500">
          Leave both blank to watch every RADIUS user and client. The count comes from the
          authentication log, so a rule only sees events FreeRADIUS has written &mdash;{' '}
          {metric ? metric.label.toLowerCase() : 'the selected metric'} are counted, and lines
          without a timestamp are ignored because they cannot be placed in a window.
        </p>

        {formError ? <p className="text-sm text-red-300">{formError}</p> : null}
        {error ? <ErrorBanner message={error} /> : null}
      </form>
    </Modal>
  )
}