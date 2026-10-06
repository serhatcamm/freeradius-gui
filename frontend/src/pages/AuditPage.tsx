import { api } from '../api'
import { EmptyState, ErrorBanner, Spinner, formatTimestamp } from '../components/ui'
import { useAsync } from '../lib/hooks'

export function AuditPage() {
  const entries = useAsync(() => api.audit(), [])

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-semibold">Audit log</h1>
        <button type="button" className="btn-secondary" onClick={() => void entries.reload()}>
          Refresh
        </button>
      </div>

      {entries.error ? (
        <ErrorBanner message={entries.error} onRetry={() => void entries.reload()} />
      ) : null}

      {entries.loading ? (
        <Spinner label="Loading audit trail" />
      ) : (entries.data ?? []).length === 0 ? (
        <EmptyState>No recorded activity yet.</EmptyState>
      ) : (
        <div className="table-wrap">
          <table className="min-w-full divide-y divide-slate-700">
            <thead className="bg-slate-800/80">
              <tr>
                <th className="th">Time</th>
                <th className="th">Administrator</th>
                <th className="th">Action</th>
                <th className="th">Object</th>
                <th className="th">Source</th>
                <th className="th">Detail</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800 bg-slate-900/40">
              {(entries.data ?? []).map((entry) => (
                <tr key={entry.id}>
                  <td className="td text-slate-400">{formatTimestamp(entry.created_at)}</td>
                  <td className="td font-medium text-slate-100">{entry.username ?? 'system'}</td>
                  <td className="td">
                    <code className="text-xs">{entry.action}</code>
                  </td>
                  <td className="td text-slate-400">
                    {entry.object_type ? `${entry.object_type}:${entry.object_id ?? ''}` : '—'}
                  </td>
                  <td className="td text-slate-400">{entry.source_ip ?? '—'}</td>
                  <td className="td max-w-md truncate font-mono text-xs text-slate-400">
                    {entry.detail ? JSON.stringify(entry.detail) : '—'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}