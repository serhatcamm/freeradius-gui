import { NavLink, Route, Routes } from 'react-router-dom'

import { useAuth, useCan } from './auth/AuthContext'
import { AccountsPage } from './pages/AccountsPage'
import { AuditPage } from './pages/AuditPage'
import { BackupsPage } from './pages/BackupsPage'
import { DashboardPage } from './pages/DashboardPage'
import { LogInPage } from './pages/LogInPage'
import { LogsPage } from './pages/LogsPage'
import { ServicePage } from './pages/ServicePage'
import { SettingsPage } from './pages/SettingsPage'
import { Spinner } from './components/ui'

const NAV = [
  { to: '/', label: 'Dashboard', end: true },
  { to: '/users', label: 'Users' },
  { to: '/clients', label: 'Clients' },
  { to: '/logs', label: 'Logs' },
  { to: '/service', label: 'Service' },
  { to: '/backups', label: 'Backups' },
  { to: '/audit', label: 'Audit' },
  { to: '/settings', label: 'Settings' },
]

export default function App() {
  const { admin, loading } = useAuth()

  if (loading) {
    return (
      <div className="flex min-h-screen items-center justify-center">
        <Spinner label="Restoring session" />
      </div>
    )
  }

  if (!admin) {
    return (
      <Routes>
        <Route path="*" element={<LogInPage />} />
      </Routes>
    )
  }

  return (
    <div className="min-h-screen">
      <Header />
      <div className="mx-auto flex max-w-7xl flex-col gap-6 px-4 py-6 lg:flex-row">
        <Nav />
        <main className="min-w-0 flex-1">
          <Routes>
            <Route path="/" element={<DashboardPage />} />
            <Route path="/users" element={<AccountsPage kind="users" />} />
            <Route path="/clients" element={<AccountsPage kind="clients" />} />
            <Route path="/logs" element={<LogsPage />} />
            <Route path="/service" element={<ServicePage />} />
            <Route path="/backups" element={<BackupsPage />} />
            <Route path="/audit" element={<AuditPage />} />
            <Route path="/settings" element={<SettingsPage />} />
            <Route path="*" element={<DashboardPage />} />
          </Routes>
        </main>
      </div>
    </div>
  )
}

function Header() {
  const { admin, logout } = useAuth()
  return (
    <header className="border-b border-slate-800 bg-slate-950/60">
      <div className="mx-auto flex max-w-7xl items-center justify-between px-4 py-3">
        <div className="flex items-center gap-2">
          <span className="text-lg font-semibold">FreeRADIUS</span>
          <span className="badge-muted">panel</span>
        </div>
        <div className="flex items-center gap-3 text-sm">
          <span className="text-slate-400">
            {admin?.username} · <RoleBadge role={admin?.role ?? ''} />
          </span>
          <button type="button" className="btn-secondary" onClick={() => void logout()}>
            Sign out
          </button>
        </div>
      </div>
    </header>
  )
}

function RoleBadge({ role }: { role: string }) {
  const tone = role === 'admin' ? 'badge-err' : role === 'operator' ? 'badge-warn' : 'badge-muted'
  return <span className={tone}>{role}</span>
}

function Nav() {
  const can = useCan()
  return (
    <nav aria-label="Sections" className="lg:w-52 lg:shrink-0">
      <ul className="flex gap-1 overflow-x-auto lg:flex-col lg:overflow-visible">
        {NAV.map((item) => (
          <li key={item.to}>
            <NavLink
              to={item.to}
              end={item.end}
              className={({ isActive }) =>
                `block whitespace-nowrap rounded-md px-3 py-2 text-sm transition-colors ${
                  isActive
                    ? 'bg-sky-600 text-white'
                    : 'text-slate-300 hover:bg-slate-800'
                }`
              }
            >
              {item.label}
            </NavLink>
          </li>
        ))}
      </ul>
      {!can.canOperate ? (
        <p className="mt-4 rounded-md border border-slate-700 bg-slate-800/60 px-3 py-2 text-xs text-slate-400">
          You have read-only access. Changes require the operator role.
        </p>
      ) : null}
    </nav>
  )
}