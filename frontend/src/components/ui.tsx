import { useEffect } from 'react'
import type { ReactNode } from 'react'

/** Small presentational primitives shared by every page. */

export function Spinner({ label = 'Loading' }: { label?: string }) {
  return (
    <div className="flex items-center gap-3 p-8 text-slate-400">
      <span
        className="h-5 w-5 animate-spin rounded-full border-2 border-slate-600 border-t-sky-400"
        aria-hidden="true"
      />
      <span>{label}…</span>
    </div>
  )
}

export function ErrorBanner({ message, onRetry }: { message: string; onRetry?: () => void }) {
  return (
    <div
      role="alert"
      className="mb-4 flex items-start justify-between gap-4 rounded-md border border-red-700 bg-red-950/40 px-4 py-3 text-sm text-red-200"
    >
      <span className="break-words">{message}</span>
      {onRetry ? (
        <button type="button" className="btn-secondary shrink-0" onClick={onRetry}>
          Retry
        </button>
      ) : null}
    </div>
  )
}

export function Notice({
  kind = 'ok',
  children,
  onDismiss,
}: {
  kind?: 'ok' | 'warn' | 'error'
  children: ReactNode
  onDismiss?: () => void
}) {
  const tone =
    kind === 'ok' ? 'border-emerald-700 bg-emerald-950/40 text-emerald-200'
      : kind === 'warn' ? 'border-amber-700 bg-amber-950/40 text-amber-200'
        : 'border-red-700 bg-red-950/40 text-red-200'
  return (
    <div
      role="status"
      className={`mb-4 flex items-start justify-between gap-4 rounded-md border px-4 py-3 text-sm ${tone}`}
    >
      <span className="break-words">{children}</span>
      {onDismiss ? (
        <button type="button" className="shrink-0 opacity-70 hover:opacity-100" onClick={onDismiss}>
          Dismiss
        </button>
      ) : null}
    </div>
  )
}

export function StatusBadge({ active }: { active: boolean }) {
  return (
    <span className={active ? 'badge-ok' : 'badge-err'}>
      {active ? 'active' : 'inactive'}
    </span>
  )
}

export function EnabledBadge({ enabled }: { enabled: boolean }) {
  return <span className={enabled ? 'badge-ok' : 'badge-muted'}>{enabled ? 'enabled' : 'disabled'}</span>
}

export function StatTile({
  label,
  value,
  hint,
}: {
  label: string
  value: ReactNode
  hint?: ReactNode
}) {
  return (
    <div className="card p-4">
      <div className="text-xs font-medium uppercase tracking-wide text-slate-400">{label}</div>
      <div className="mt-1 text-2xl font-semibold tabular-nums">{value}</div>
      {hint ? <div className="mt-1 text-xs text-slate-400">{hint}</div> : null}
    </div>
  )
}

export function Modal({
  title,
  children,
  onClose,
  footer,
}: {
  title: string
  children: ReactNode
  onClose: () => void
  footer?: ReactNode
}) {
  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if (event.key === 'Escape') onClose()
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [onClose])

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4"
      role="dialog"
      aria-modal="true"
      aria-label={title}
      onClick={(event) => {
        if (event.target === event.currentTarget) onClose()
      }}
    >
      <div className="card w-full max-w-lg p-5">
        <div className="mb-4 flex items-center justify-between">
          <h2 className="text-lg font-semibold">{title}</h2>
          <button type="button" className="btn-ghost" onClick={onClose} aria-label="Close">
            ✕
          </button>
        </div>
        <div className="space-y-4">{children}</div>
        {footer ? <div className="mt-5 flex justify-end gap-2">{footer}</div> : null}
      </div>
    </div>
  )
}

export function ConfirmDialog({
  title,
  message,
  confirmLabel = 'Confirm',
  pending,
  onConfirm,
  onCancel,
}: {
  title: string
  message: ReactNode
  confirmLabel?: string
  pending?: boolean
  onConfirm: () => void
  onCancel: () => void
}) {
  return (
    <Modal
      title={title}
      onClose={onCancel}
      footer={
        <>
          <button type="button" className="btn-secondary" onClick={onCancel} disabled={pending}>
            Cancel
          </button>
          <button type="button" className="btn-danger" onClick={onConfirm} disabled={pending}>
            {pending ? 'Working…' : confirmLabel}
          </button>
        </>
      }
    >
      <div className="text-sm text-slate-300">{message}</div>
    </Modal>
  )
}

export function EmptyState({ children }: { children: ReactNode }) {
  return (
    <div className="card p-10 text-center text-sm text-slate-400">{children}</div>
  )
}

export function formatBytes(bytes?: number): string {
  if (bytes === undefined) return '—'
  const units = ['B', 'KB', 'MB', 'GB']
  let value = bytes
  let unit = 0
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024
    unit += 1
  }
  return `${value.toFixed(unit === 0 ? 0 : 1)} ${units[unit]}`
}

export function formatDuration(seconds?: number): string {
  if (seconds === undefined || seconds < 0) return '—'
  const days = Math.floor(seconds / 86400)
  const hours = Math.floor((seconds % 86400) / 3600)
  const minutes = Math.floor((seconds % 3600) / 60)
  if (days > 0) return `${days}d ${hours}h`
  if (hours > 0) return `${hours}h ${minutes}m`
  if (minutes > 0) return `${minutes}m`
  return `${seconds}s`
}

export function formatTimestamp(value?: string | null): string {
  if (!value) return '—'
  const parsed = new Date(value)
  if (Number.isNaN(parsed.getTime())) return value
  return parsed.toLocaleString()
}