/** Response shapes mirrored from the FastAPI schemas. */

export type Role = 'viewer' | 'operator' | 'admin'

export interface Administrator {
  username: string
  full_name: string | null
  role: Role
  last_login_at: string | null
}

export interface LoginResponse {
  administrator: Administrator
  csrf_token: string
  session_expires_in: number
}

export interface User {
  username: string
  auth_method: string
  enabled: boolean
  status: string
  cisco_privilege: number | null
  cisco_avpairs: string[]
  /** The group this user references with ``Group = name``, or "" for none. */
  group: string
  /** The API never returns the password itself. */
  has_password: boolean
  rejects: boolean
  line_number: number
  last_authentication: string | null
  duplicate_entries: number | null
}

export interface GroupAttribute {
  key: string
  value: string
  /** Written with an explicit ``reply:`` prefix. */
  reply: boolean
}

export interface Group {
  name: string
  is_default: boolean
  line_number: number
  comment: string
  attributes: GroupAttribute[]
  /** Users whose authorize entry sets ``Group = <name>``. */
  members?: string[]
}

export interface GroupsStatus {
  /** False when the files module has no active groupfile directive. */
  enabled: boolean
  module_file: string
  groups_file: string
  groups_file_exists: boolean
  directive: string | null
  error?: string
  groups: Group[]
}

export interface Client {
  name: string
  address: string | null
  address_kind: string
  /** The API never returns an existing secret. */
  has_secret: boolean
  nas_type: string
  description: string
  enabled: boolean
  status: string
  require_message_authenticator: boolean
  line_number: number
  generated_secret: string | null
}

/** One listening socket as reported by /api/service. */
export interface ListeningSocket {
  protocol: string
  port: number
  role: string | null
}

export interface ServiceStatus {
  status: string
  systemd_state: string
  enabled: string
  pid: number | null
  restarts: number
  active_since: string | null
  memory_kb: number | null
  cpu_seconds_total: number | null
  /** Objects, not numbers. Rendering these as strings throws at runtime. */
  listening_ports: ListeningSocket[]
  unit: string
  error?: string | null
}

export interface ServerInfo {
  hostname: string
  freeradius_version: string | null
  debian_version: string | null
  kernel: string | null
  raddb_dir: string
  users_file: string
  clients_file: string
  auth_port: number
  accounting_port: number
  config_validated: boolean
}

/**
 * /api/dashboard returns server_info() plus two computed fields, so it is a
 * superset of the /api/service shape.
 */
export interface DashboardServer extends ServerInfo {
  uptime_seconds: number | null
  os: string
}

export interface DashboardCounts {
  users_total?: number
  users_active?: number
  users_disabled?: number
  clients_total?: number
  clients_active?: number
  clients_disabled?: number
  [key: string]: number | undefined
}

export interface Dashboard {
  service: ServiceStatus
  server: DashboardServer
  radius: {
    auth_port?: number
    accounting_port?: number
    users_configured?: number
    clients_configured?: number
    listening_ports?: ListeningSocket[]
  }
  counts?: DashboardCounts
  /** Group counts plus whether the files module will read the groupfile. */
  groups?: {
    available: boolean
    reason?: string
    enabled: boolean
    count: number
    members: number
  }
  validation?: ValidationResult
  validation_summary?: string
  generated_at?: string
  [key: string]: unknown
}

/** GET /api/service returns the systemd status and host info side by side. */
export interface ServiceState {
  service: ServiceStatus
  server: ServerInfo
}

export interface ValidationIssue {
  file?: string
  line?: number
  severity?: string
  message?: string
  [key: string]: unknown
}

export interface ValidationResult {
  ok: boolean
  returncode: number
  issues: ValidationIssue[]
  summary: string
}

export interface LogCapability {
  available: boolean
  reason?: string | null
  site_installed?: boolean
  detail_installed?: boolean
  log_file?: string | null
  writable?: boolean
  [key: string]: unknown
}

export interface LogEvent {
  timestamp: string | null
  severity: string
  message: string
  source: string
  result?: string | null
  username?: string | null
  nas_ip?: string | null
  client?: string | null
  calling_station?: string | null
  reply?: string | null
}

export interface LogResponse {
  events: LogEvent[]
  total_lines: number
  request_event_count: number
  capability: LogCapability
  source_paths: string[]
}

export interface RadiusTestResult {
  result: string
  response_time_ms: number
  username: string
  server: string
  port: number
  returned_attributes: Record<string, string>[]
  request_attributes: Record<string, string>[]
  message_authenticator: string | null
  error: string | null
}

/** One file inside a backup. Absent from the label when it did not exist. */
export interface BackupFile {
  path: string
  present: boolean
  stored_as?: string
  sha256?: string
  size?: number
  mode?: number
}

/** One file's unified diff between a backup and the live file. */
export interface BackupDiff {
  label: string
  path: string
  changed: boolean
  diff: string
}

export interface Backup {
  id: string
  operation: string
  administrator: string
  hostname?: string
  source_ip?: string | null
  created_at: string
  notes?: string | null
  files: Record<string, BackupFile>
  changed_files?: string[]
}

/** GET /api/backups/{id} response. */
export interface BackupDetail {
  backup: Backup
  diff: BackupDiff[]
  changed: boolean
}

export interface AuditEntry {
  id: number
  username?: string
  action: string
  object_type?: string | null
  object_id?: string | null
  source_ip?: string | null
  detail?: Record<string, unknown> | null
  created_at?: string
  [key: string]: unknown
}

/** GET /api/backups returns {backups, count}, not a bare array. */
export interface BackupList {
  backups: Backup[]
  count: number
}

/** One row of GET /api/administrators. */
export interface AdministratorRecord extends Administrator {
  is_active: boolean
  created_at: string | null
  last_login_ip: string | null
  failed_attempts: number
  locked_until: string | null
  session_count: number
  is_self: boolean
}

export interface AdministratorList {
  administrators: AdministratorRecord[]
  count: number
  active_admin_count: number
}

export interface AdministratorCreate {
  username: string
  password: string
  role: Role
  full_name?: string | null
}

export interface AdministratorUpdate {
  role?: Role
  full_name?: string | null
  is_active?: boolean
}

export type AlertMetric = 'failures' | 'successes' | 'challenges' | 'total'

export interface AlertRule {
  id: number
  name: string
  metric: AlertMetric
  metric_label: string
  username: string | null
  client: string | null
  threshold: number
  window_seconds: number
  enabled: boolean
  created_at: string | null
  created_by: string | null
  last_fired_at: string | null
  /** Events counted in the current window as of the last evaluation. */
  observed: number
  would_fire: boolean
}

export interface Alert {
  id: number
  raised_at: string | null
  observed: number
  threshold: number
  rule_name: string
  metric: AlertMetric
  metric_label: string
  username: string | null
  client: string | null
  acknowledged_at: string | null
  acknowledged_by: string | null
}

export interface AlertList {
  alerts: Alert[]
  count: number
}

/** POST/PATCH body for an alert rule. */
export interface AlertRuleInput {
  name: string
  metric: AlertMetric
  threshold: number
  window_seconds: number
  username?: string | null
  client?: string | null
}

export interface ActiveDirectorySettings {
  configured: boolean
  domain: string | null
  base_dn: string | null
  bind_dn: string | null
  servers: string[]
  port: number
  use_ldaps: boolean
  start_tls: boolean
  tls_ca: string | null
  membership_attribute: string
  membership_delimiter: string
  group_map: Record<string, string>
  bind_password_set: boolean
  enabled: boolean
  ldap_block_installed: boolean
  ldap_module_installed: boolean
  ntlm_auth_available: boolean
  winbind_installed: boolean
  winbind_joined: boolean
  ready: boolean
  prerequisites: Array<{ name: string; ok: boolean; detail: string }>
  blocked_by: string[]
}

export interface ActiveDirectorySettingsInput {
  domain: string
  base_dn: string
  bind_dn: string
  servers: string[]
  port: number
  use_ldaps: boolean
  start_tls: boolean
  tls_ca?: string | null
  membership_attribute: string
  membership_delimiter: string
  group_map: Record<string, string>
  bind_password?: string
  enable: boolean
}

/** GET /api/audit returns {entries, count}, not a bare array. */
export interface AuditList {
  entries: AuditEntry[]
  count: number
}

export interface Settings {
  environment?: string
  docs_enabled?: boolean
  session_timeout_seconds?: number
  idle_timeout_seconds?: number
  cookie_secure?: boolean
  database?: string
  raddb_dir?: string
  /** A mapping of logical name -> absolute path, not a list. */
  managed_files?: Record<string, string>
  backup_dir?: string
  log_dir?: string
  audit_logging?: boolean
  [key: string]: unknown
}
