/**
 * Thin API client.
 *
 * Two things it must get right:
 *
 *  - the CSRF token lives in a readable cookie and must be echoed in a header
 *    on every unsafe request;
 *  - an expired session must not be reported as a server error, so 401 is
 *    surfaced distinctly for the auth layer to react to.
 */
import type {
  ActiveDirectorySettings,
  ActiveDirectorySettingsInput,
  Administrator,
  AdministratorCreate,
  AdministratorList,
  AdministratorRecord,
  AdministratorUpdate,
  AlertList,
  AlertRule,
  AlertRuleInput,
  AuditList,
  BackupDetail,
  BackupList,
  Client,
  Dashboard,
  Group,
  GroupsStatus,
  LogCapability,
  LogEvent,
  LoginResponse,
  RadiusTestResult,
  ServiceState,
  Settings,
  User,
  ValidationResult,
} from './types'

export class ApiError extends Error {
  readonly status: number
  readonly detail?: string

  constructor(status: number, message: string, detail?: string) {
    super(message)
    this.name = 'ApiError'
    this.status = status
    this.detail = detail
  }

  get isUnauthorized(): boolean {
    return this.status === 401
  }

  get isForbidden(): boolean {
    return this.status === 403
  }
}

function readCookie(name: string): string {
  const prefix = `${name}=`
  for (const part of document.cookie.split(';')) {
    const trimmed = part.trim()
    if (trimmed.startsWith(prefix)) {
      return decodeURIComponent(trimmed.slice(prefix.length))
    }
  }
  return ''
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const method = (init.method ?? 'GET').toUpperCase()
  const headers = new Headers(init.headers)

  if (init.body !== undefined && !headers.has('Content-Type')) {
    headers.set('Content-Type', 'application/json')
  }

  // Double-submit: the header must match the cookie exactly.
  if (!['GET', 'HEAD', 'OPTIONS'].includes(method)) {
    const token = readCookie('frw_csrf')
    if (token) headers.set('X-CSRF-Token', token)
  }

  const response = await fetch(path, {
    ...init,
    method,
    headers,
    // Session cookie must ride along; without this the SPA cannot authenticate.
    credentials: 'same-origin',
  })

  if (response.status === 204) return undefined as T

  const text = await response.text()
  let payload: unknown = undefined
  if (text) {
    try {
      payload = JSON.parse(text)
    } catch {
      payload = text
    }
  }

  if (!response.ok) {
    const obj = (payload ?? {}) as Record<string, unknown>
    const message =
      typeof obj.error === 'string'
        ? obj.error
        : typeof obj.detail === 'string'
          ? obj.detail
          : `Request failed (${response.status})`
    throw new ApiError(response.status, message, typeof obj.detail === 'string' ? obj.detail : undefined)
  }

  return payload as T
}

function query(params: Record<string, string | number | undefined | null>): string {
  const search = new URLSearchParams()
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== null && value !== '') {
      search.set(key, String(value))
    }
  }
  const encoded = search.toString()
  return encoded ? `?${encoded}` : ''
}

export const api = {
  // -- auth --------------------------------------------------------------
  async login(username: string, password: string) {
    return request<LoginResponse>('/api/auth/login', {
      method: 'POST',
      body: JSON.stringify({ username, password }),
    })
  },
  logout: () => request<{ ok: boolean }>('/api/auth/logout', { method: 'POST' }),
  me: () => request<Administrator>('/api/auth/me'),
  changePassword: (current: string, next: string) =>
    request<{ ok: boolean }>('/api/auth/change-password', {
      method: 'POST',
      body: JSON.stringify({ current_password: current, new_password: next }),
    }),

  // -- dashboard ---------------------------------------------------------
  dashboard: () => request<Dashboard>('/api/dashboard'),
  settings: () => request<Settings>('/api/settings'),

  // -- users -------------------------------------------------------------
  users: () => request<User[]>('/api/users'),
  createUser: (body: { username: string; password: string; group?: string }) =>
    request<User>('/api/users', { method: 'POST', body: JSON.stringify(body) }),
  updateUser: (username: string, body: Record<string, unknown>) =>
    request<User>(`/api/users/${encodeURIComponent(username)}`, {
      method: 'PATCH',
      body: JSON.stringify(body),
    }),
  setUserPassword: (username: string, password: string) =>
    request<User>(`/api/users/${encodeURIComponent(username)}/password`, {
      method: 'POST',
      body: JSON.stringify({ password }),
    }),
  enableUser: (username: string) =>
    request<User>(`/api/users/${encodeURIComponent(username)}/enable`, { method: 'POST' }),
  disableUser: (username: string) =>
    request<User>(`/api/users/${encodeURIComponent(username)}/disable`, { method: 'POST' }),
  deleteUser: (username: string) =>
    request<{ ok: boolean }>(`/api/users/${encodeURIComponent(username)}`, { method: 'DELETE' }),

  // -- clients -----------------------------------------------------------
  clients: () => request<Client[]>('/api/clients'),
  createClient: (body: Record<string, unknown>) =>
    request<Client>('/api/clients', { method: 'POST', body: JSON.stringify(body) }),
  updateClient: (name: string, body: Record<string, unknown>) =>
    request<Client>(`/api/clients/${encodeURIComponent(name)}`, {
      method: 'PATCH',
      body: JSON.stringify(body),
    }),
  resetSecret: (name: string) =>
    request<{ name: string; secret: string }>(
      `/api/clients/${encodeURIComponent(name)}/reset-secret`,
      { method: 'POST' },
    ),
  enableClient: (name: string) =>
    request<Client>(`/api/clients/${encodeURIComponent(name)}/enable`, { method: 'POST' }),
  disableClient: (name: string) =>
    request<Client>(`/api/clients/${encodeURIComponent(name)}/disable`, { method: 'POST' }),
  deleteClient: (name: string) =>
    request<{ ok: boolean }>(`/api/clients/${encodeURIComponent(name)}`, { method: 'DELETE' }),

  // -- groups -----------------------------------------------------------
  groups: () => request<GroupsStatus>('/api/groups/status'),
  createGroup: (body: Record<string, unknown>) =>
    request<Group>('/api/groups', { method: 'POST', body: JSON.stringify(body) }),
  updateGroup: (name: string, body: Record<string, unknown>) =>
    request<Group>(`/api/groups/${encodeURIComponent(name)}`, {
      method: 'PATCH',
      body: JSON.stringify(body),
    }),
  deleteGroup: (name: string) =>
    request<{ ok: boolean; name: string; entries_removed: number }>(
      `/api/groups/${encodeURIComponent(name)}`,
      { method: 'DELETE' },
    ),

  // -- logs --------------------------------------------------------------
  logs: (params: {
    limit?: number
    result?: string
    username?: string
    nas_ip?: string
    hours?: number
  }) =>
    request<{
      events: LogEvent[]
      total_lines: number
      request_event_count: number
      capability: LogCapability
      source_paths: string[]
    }>(`/api/logs${query(params)}`),
  logCapability: () => request<LogCapability>('/api/logs/capability'),
  enableRequestLogging: () =>
    request<{ ok: boolean; message?: string; error?: string }>(
      '/api/logs/enable-request-logging',
      { method: 'POST' },
    ),
  disableRequestLogging: () =>
    request<{ ok: boolean; message?: string; error?: string }>(
      '/api/logs/disable-request-logging',
      { method: 'POST' },
    ),

  // -- service -----------------------------------------------------------
  service: () => request<ServiceState>('/api/service'),
  validate: () => request<ValidationResult>('/api/service/validate'),
  restartService: () => request<{ ok: boolean }>('/api/service/restart', { method: 'POST' }),
  reloadService: () => request<{ ok: boolean }>('/api/service/reload', { method: 'POST' }),
  serviceLog: (lines = 100) => request<{ lines: string[] }>(`/api/service/log?lines=${lines}`),

  // -- radius test -------------------------------------------------------
  // The shared secret is resolved server-side from a configured client, so it
  // is never sent from or received by the browser.
  radiusTest: (username: string, password: string, client: string) =>
    request<RadiusTestResult>('/api/radius/test', {
      method: 'POST',
      body: JSON.stringify({ username, password, client }),
    }),

  // -- backups & audit ---------------------------------------------------
  // Both list endpoints wrap their payload in an object; treating the
  // response as a bare array makes .map() throw and blanks the page.
  backups: () => request<BackupList>('/api/backups'),
  // The diff is computed server-side: the backup holds the "before" bytes and
  // only the service account can read the live files.
  backup: (id: string) =>
    request<BackupDetail>(`/api/backups/${encodeURIComponent(id)}`),
  rollback: (id: string) =>
    request<{ ok: boolean; message?: string }>(`/api/backups/${encodeURIComponent(id)}/rollback`, {
      method: 'POST',
    }),
  audit: () => request<AuditList>('/api/audit'),

  // -- administrators ----------------------------------------------------
  // Every one of these is admin-only; the server enforces it regardless of
  // what the UI shows.
  administrators: () => request<AdministratorList>('/api/administrators'),
  createAdministrator: (body: AdministratorCreate) =>
    request<AdministratorRecord>('/api/administrators', {
      method: 'POST',
      body: JSON.stringify(body),
    }),
  updateAdministrator: (username: string, body: AdministratorUpdate) =>
    request<AdministratorRecord>(`/api/administrators/${encodeURIComponent(username)}`, {
      method: 'PATCH',
      body: JSON.stringify(body),
    }),
  resetAdministratorPassword: (username: string, newPassword: string) =>
    request<{ ok: boolean; message?: string }>(
      `/api/administrators/${encodeURIComponent(username)}/password`,
      { method: 'POST', body: JSON.stringify({ new_password: newPassword }) },
    ),
  unlockAdministrator: (username: string) =>
    request<{ ok: boolean; message?: string }>(
      `/api/administrators/${encodeURIComponent(username)}/unlock`,
      { method: 'POST' },
    ),
  deactivateAdministrator: (username: string) =>
    request<{ ok: boolean; message?: string }>(
      `/api/administrators/${encodeURIComponent(username)}`,
      { method: 'DELETE' },
    ),

  // -- alerts -----------------------------------------------------------
  // Reading the rules or the alert list evaluates them, so both responses
  // carry a current observed count.
  alertRules: () => request<AlertRule[]>('/api/alerts/rules'),
  createAlertRule: (body: AlertRuleInput) =>
    request<AlertRule>('/api/alerts/rules', { method: 'POST', body: JSON.stringify(body) }),
  updateAlertRule: (id: number, body: Partial<AlertRuleInput> & { enabled?: boolean }) =>
    request<AlertRule>(`/api/alerts/rules/${id}`, { method: 'PATCH', body: JSON.stringify(body) }),
  deleteAlertRule: (id: number) =>
    request<{ ok: boolean }>(`/api/alerts/rules/${id}`, { method: 'DELETE' }),
  alerts: (unacknowledgedOnly = false) =>
    request<AlertList>(`/api/alerts?unacknowledged_only=${unacknowledgedOnly}`),
  acknowledgeAlert: (id: number) =>
    request<{ ok: boolean }>(`/api/alerts/${id}/acknowledge`, { method: 'POST' }),

  // -- active directory ------------------------------------------------
  activeDirectory: () => request<ActiveDirectorySettings>('/api/active-directory'),
  saveActiveDirectory: (body: ActiveDirectorySettingsInput) =>
    request<ActiveDirectorySettings>('/api/active-directory', {
      method: 'PUT',
      body: JSON.stringify(body),
    }),
  disconnectActiveDirectory: () =>
    request<{ ok: boolean; message?: string }>('/api/active-directory/disconnect', {
      method: 'POST',
    }),
}

export type {
  Administrator,
  AdministratorCreate,
  AdministratorList,
  AdministratorRecord,
  AdministratorUpdate,
  ActiveDirectorySettings,
  ActiveDirectorySettingsInput,
  Alert,
  AlertList,
  AlertMetric,
  AlertRule,
  AlertRuleInput,
  AuditEntry,
  Backup,
  BackupDetail,
  Client,
  Dashboard,
  Group,
  GroupAttribute,
  GroupsStatus,
  LogCapability,
  LogEvent,
  LoginResponse,
  RadiusTestResult,
  ServiceState,
  Settings,
  User,
  ValidationResult,
} from './types'
