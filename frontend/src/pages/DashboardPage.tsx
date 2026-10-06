import { api } from '../api'
import { ErrorBanner, Spinner, StatTile, StatusBadge, formatDuration } from '../components/ui'
import { useAsync } from '../lib/hooks'
import { describePorts } from './ServicePage'

export function DashboardPage() {
  const { data, error, loading, reload } = useAsync(() => api.dashboard(), [])

  if (loading) return <Spinner label="Loading dashboard" />
  if (error) return <ErrorBanner message={error} onRetry={() => void reload()} />
  if (!data) return null

  const counts = data.counts ?? {}
  const disabledUsers = Number(counts.users_disabled ?? counts.disabled_users ?? 0)
  const groups = data.groups

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-semibold">Dashboard</h1>
        <button type="button" className="btn-secondary" onClick={() => void reload()}>
          Refresh
        </button>
      </div>

      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <StatTile
          label="FreeRADIUS"
          value={<StatusBadge active={data.service?.systemd_state === 'active'} />}
          hint={data.service?.status ?? undefined}
        />
        <StatTile
          label="Users configured"
          value={data.radius?.users_configured ?? 0}
          hint={disabledUsers > 0 ? `${disabledUsers} disabled` : 'all enabled'}
        />
        <StatTile
          label="Clients"
          value={data.radius?.clients_configured ?? 0}
          hint={`auth ${data.radius?.auth_port ?? '—'} · acct ${data.radius?.accounting_port ?? '—'}`}
        />
        <StatTile
          label="Uptime"
          value={formatDuration(data.server?.uptime_seconds ?? undefined)}
          hint={data.server?.hostname}
        />
        <StatTile
          label="Groups"
          value={groups?.count ?? 0}
          hint={
            !groups?.available
              ? (groups?.reason ?? 'groupfile not read')
              : groups.enabled
                ? `${groups.members} member assignment${groups.members === 1 ? '' : 's'}`
                : 'groupfile not active'
          }
        />
      </div>

      <section className="card p-5">
        <h2 className="mb-3 text-sm font-semibold uppercase tracking-wide text-slate-400">Host</h2>
        <dl className="grid gap-x-6 gap-y-2 text-sm sm:grid-cols-2">
          <Row label="Hostname" value={data.server?.hostname} />
          <Row label="Operating system" value={data.server?.os} />
          <Row label="FreeRADIUS version" value={data.server?.freeradius_version} />
          <Row
            label="Listening ports"
            value={describePorts(data.radius?.listening_ports ?? data.service?.listening_ports)}
          />
        </dl>
      </section>
    </div>
  )
}

function Row({ label, value }: { label: string; value?: string | null }) {
  return (
    <div className="flex justify-between gap-4 border-b border-slate-800 py-1 last:border-0">
      <dt className="text-slate-400">{label}</dt>
      <dd className="truncate text-right text-slate-200">{value || '—'}</dd>
    </div>
  )
}