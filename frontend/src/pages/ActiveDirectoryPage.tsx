import { useEffect, useState } from 'react'
import type { FormEvent } from 'react'

import { api } from '../api'
import { ErrorBanner, Notice, Spinner } from '../components/ui'
import { useAction, useAsync } from '../lib/hooks'
import type { ActiveDirectoryConnectionTest, ActiveDirectorySettingsInput } from '../types'

type GroupRow = { ad: string; radius: string }

const emptyForm: ActiveDirectorySettingsInput = {
  domain: '',
  base_dn: '',
  bind_dn: '',
  servers: [''],
  port: 389,
  use_ldaps: false,
  start_tls: true,
  tls_ca: '',
  membership_attribute: 'memberOf',
  membership_delimiter: ';',
  group_map: {},
  enable: false,
}

export function ActiveDirectoryPage() {
  const status = useAsync(() => api.activeDirectory(), [])
  const [form, setForm] = useState(emptyForm)
  const [groups, setGroups] = useState<GroupRow[]>([])
  const [notice, setNotice] = useState<string | null>(null)
  const [testResult, setTestResult] = useState<ActiveDirectoryConnectionTest | null>(null)
  const save = useAction()
  const disconnect = useAction()
  const connectionTest = useAction()

  useEffect(() => {
    const data = status.data
    if (!data) return
    setForm({
      domain: data.domain ?? '',
      base_dn: data.base_dn ?? '',
      bind_dn: data.bind_dn ?? '',
      servers: data.servers.length > 0 ? data.servers : [''],
      port: data.port,
      use_ldaps: data.use_ldaps,
      start_tls: data.start_tls,
      tls_ca: data.tls_ca ?? '',
      membership_attribute: data.membership_attribute,
      membership_delimiter: data.membership_delimiter,
      group_map: data.group_map,
      enable: data.enabled,
    })
    setGroups(Object.entries(data.group_map).map(([ad, radius]) => ({ ad, radius })))
  }, [status.data])

  function update<K extends keyof ActiveDirectorySettingsInput>(key: K, value: ActiveDirectorySettingsInput[K]) {
    setForm((current) => ({ ...current, [key]: value }))
  }

  async function submit(event: FormEvent) {
    event.preventDefault()
    setNotice(null)
    const groupMap = Object.fromEntries(
      groups
        .map((row) => [row.ad.trim(), row.radius.trim()] as const)
        .filter(([ad, radius]) => ad && radius),
    )
    const result = await save.run(() => api.saveActiveDirectory({
      ...form,
      servers: form.servers.map((server) => server.trim()).filter(Boolean),
      tls_ca: form.tls_ca || null,
      group_map: groupMap,
      bind_password: form.bind_password || undefined,
    }))
    if (result) {
      setNotice(form.enable ? 'Settings saved and AD authentication enabled.' : 'Settings saved. AD remains disconnected.')
      setForm((current) => ({ ...current, bind_password: undefined }))
      void status.reload()
    }
  }

  async function disconnectNow() {
    if (!window.confirm('Disconnect AD and restore local RADIUS authentication?')) return
    const result = await disconnect.run(() => api.disconnectActiveDirectory())
    if (result) {
      setNotice(result.message ?? 'Active Directory disconnected.')
      update('enable', false)
      void status.reload()
    }
  }

  async function testConnection() {
    setTestResult(null)
    const result = await connectionTest.run(() => api.testActiveDirectory())
    if (result) setTestResult(result)
  }

  if (status.loading && !status.data) return <Spinner label="Loading Active Directory settings" />
  if (status.error && !status.data) return <ErrorBanner message={status.error} onRetry={() => void status.reload()} />

  const data = status.data
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-semibold">Active Directory</h1>
        <p className="mt-1 max-w-3xl text-sm text-slate-400">
          RADIUS passwords are checked through Samba/winbind and directory attributes are read through LDAP.
          The panel never verifies user passwords with an LDAP bind.
        </p>
      </div>

      {save.error ? <ErrorBanner message={save.error} /> : null}
      {disconnect.error ? <ErrorBanner message={disconnect.error} /> : null}
      {connectionTest.error ? <ErrorBanner message={connectionTest.error} /> : null}
      {notice ? <Notice onDismiss={() => setNotice(null)}>{notice}</Notice> : null}

      {data ? (
        <section className="card p-5">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <h2 className="text-sm font-semibold uppercase tracking-wide text-slate-400">Prerequisites</h2>
            <span className={data.ready ? 'badge-ok' : 'badge-warn'}>
              {data.ready ? 'Ready' : data.configured ? 'Needs host setup' : 'Not configured'}
            </span>
          </div>
          <div className="mt-4 grid gap-2 sm:grid-cols-2">
            {data.prerequisites.map((item) => (
              <div key={item.name} className="rounded-md border border-slate-800 px-3 py-2 text-sm">
                <div className="flex justify-between gap-3">
                  <span>{item.name}</span>
                  <span className={item.ok ? 'text-emerald-300' : 'text-amber-300'}>{item.ok ? 'Ready' : 'Missing'}</span>
                </div>
                <p className="mt-1 text-xs text-slate-500">{item.detail}</p>
              </div>
            ))}
          </div>
        </section>
      ) : null}

      <form className="card space-y-5 p-5" onSubmit={submit}>
        <h2 className="text-sm font-semibold uppercase tracking-wide text-slate-400">Directory connection</h2>
        <div className="grid gap-4 md:grid-cols-2">
          <Field label="AD domain" value={form.domain} onChange={(value) => update('domain', value)} placeholder="corp.example.com" required />
          <Field label="Base DN" value={form.base_dn} onChange={(value) => update('base_dn', value)} placeholder="dc=corp,dc=example,dc=com" required />
          <Field label="Read-only bind DN" value={form.bind_dn} onChange={(value) => update('bind_dn', value)} placeholder="cn=svc-radius,ou=service accounts,..." required />
          <Field label="Bind password" type="password" value={form.bind_password ?? ''} onChange={(value) => update('bind_password', value)} placeholder={data?.bind_password_set ? 'Stored; leave blank to keep' : 'Required'} required={!data?.bind_password_set} />
          <Field label="Domain controllers" value={form.servers.join(', ')} onChange={(value) => update('servers', value.split(',').map((server) => server.trim()))} placeholder="dc1.corp.example.com, dc2.corp.example.com" required />
          <Field label="TLS CA path" value={form.tls_ca ?? ''} onChange={(value) => update('tls_ca', value)} placeholder="/etc/ssl/certs/ad-ca.pem" />
        </div>
        <div className="flex flex-wrap gap-5 text-sm">
          <label className="flex items-center gap-2"><input type="checkbox" checked={form.use_ldaps} onChange={(event) => update('use_ldaps', event.target.checked)} /> LDAPS</label>
          <label className="flex items-center gap-2"><input type="checkbox" checked={form.start_tls} onChange={(event) => update('start_tls', event.target.checked)} /> StartTLS</label>
          <label className="flex items-center gap-2 font-medium text-amber-200"><input type="checkbox" checked={form.enable} onChange={(event) => update('enable', event.target.checked)} /> Enable AD authentication</label>
        </div>

        <div>
          <div className="flex items-center justify-between gap-3">
            <h2 className="text-sm font-semibold uppercase tracking-wide text-slate-400">AD group to RADIUS group</h2>
            <button type="button" className="btn-secondary" onClick={() => setGroups((current) => [...current, { ad: '', radius: '' }])}>Add mapping</button>
          </div>
          <div className="mt-3 space-y-2">
            {groups.map((row, index) => (
              <div key={`${index}-${row.ad}`} className="flex flex-col gap-2 sm:flex-row">
                <input className="input flex-1" value={row.ad} placeholder="CN=RADIUS-STAFF,OU=Groups,..." onChange={(event) => setGroups((current) => current.map((item, i) => i === index ? { ...item, ad: event.target.value } : item))} />
                <input className="input w-full sm:w-48" value={row.radius} placeholder="staff" onChange={(event) => setGroups((current) => current.map((item, i) => i === index ? { ...item, radius: event.target.value } : item))} />
                <button type="button" className="btn-danger" onClick={() => setGroups((current) => current.filter((_, i) => i !== index))}>Remove</button>
              </div>
            ))}
          </div>
        </div>

        <div className="flex flex-wrap gap-3">
          <button type="submit" className="btn-primary" disabled={save.pending}>{save.pending ? 'Saving...' : 'Save settings'}</button>
          <button type="button" className="btn-secondary" disabled={connectionTest.pending || !data?.configured} onClick={() => void testConnection()}>{connectionTest.pending ? 'Testing...' : 'Test connection'}</button>
          {data?.enabled ? <button type="button" className="btn-danger" disabled={disconnect.pending} onClick={() => void disconnectNow()}>{disconnect.pending ? 'Disconnecting...' : 'Disconnect AD'}</button> : null}
        </div>
        {testResult ? (
          <div className="rounded-md border border-slate-800 p-3 text-sm">
            <div className={testResult.ok ? 'text-emerald-300' : 'text-amber-300'}>{testResult.ok ? 'Connection succeeded.' : 'Connection checks did not pass.'}</div>
            <ul className="mt-2 space-y-1 text-xs text-slate-400">
              {testResult.checks.map((check) => <li key={check.name}><span className={check.status === 'pass' ? 'text-emerald-300' : check.status === 'fail' ? 'text-red-300' : 'text-slate-500'}>{check.status}</span> {check.name}: {check.detail}</li>)}
            </ul>
          </div>
        ) : null}
      </form>
    </div>
  )
}

function Field({ label, value, onChange, placeholder, type = 'text', required = false }: { label: string; value: string; onChange: (value: string) => void; placeholder?: string; type?: string; required?: boolean }) {
  return (
    <label>
      <span className="label">{label}</span>
      <input className="input" type={type} value={value} placeholder={placeholder} required={required} onChange={(event) => onChange(event.target.value)} />
    </label>
  )
}
