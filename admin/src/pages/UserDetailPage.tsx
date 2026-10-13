import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useEffect, useState } from 'react'
import { Link, useParams } from 'react-router-dom'

import { useAuth } from '../auth/AuthProvider'
import { RolePicker } from '../components/RolePicker'
import { Badge, Button, Card, ConfirmDialog, ErrorBox, Loading, Modal, Notice, PageHeader, SelectInput,
  TextInput } from '../components/ui'
import { api } from '../lib/api'
import { keys, useRoles, useServiceDetails, useServices } from '../lib/queries'
import { deskWarning } from '../lib/roles'
import type { AdminUser, Role, ServiceDetail } from '../lib/types'

export function UserDetailPage() {
  const { id = '' } = useParams()
  const user = useQuery({ queryKey: keys.user(id), queryFn: () => api.get<AdminUser>(`/admin/users/${id}`) })
  const roles = useRoles()
  const services = useServices()
  const details = useServiceDetails(services.data)
  const catalogues = details.map((d) => d.data).filter((d): d is ServiceDetail => Boolean(d))

  if (user.isLoading) return <Loading what="Loading user" />
  if (user.error || !user.data) return <ErrorBox error={user.error ?? 'User not found'} />
  const u = user.data

  return (
    <>
      <p className="mb-2 text-sm"><Link to="/users" className="text-brand-700 hover:underline">← Users</Link></p>
      <PageHeader title={u.full_name || u.email} description={u.email}
        actions={u.is_active ? <Badge variant="green">Active</Badge> : <Badge variant="red">Inactive</Badge>} />
      <div className="grid grid-cols-1 gap-6 xl:grid-cols-2">
        <div className="space-y-6">
          <ProfileCard user={u} />
          <RolesCard user={u} roles={roles.data?.roles ?? []} />
          <AttributesCard user={u} catalogues={catalogues} roleLabels={Object.fromEntries(
            (roles.data?.roles ?? []).map((r) => [r.key, r.label]))} />
        </div>
        <div className="space-y-6">
          <AccountCard user={u} />
          <AccessCard user={u} catalogues={catalogues} />
        </div>
      </div>
    </>
  )
}

function useUserMutation<T>(id: string, fn: (body: T) => Promise<unknown>) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: fn,
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: keys.user(id) })
      void queryClient.invalidateQueries({ queryKey: ['users'] })
    },
  })
}

function ProfileCard({ user }: { user: AdminUser }) {
  const [fullName, setFullName] = useState(user.full_name)
  const [phone, setPhone] = useState(user.phone)
  useEffect(() => { setFullName(user.full_name); setPhone(user.phone) }, [user.full_name, user.phone])
  const save = useUserMutation(user.user_id, (body: { full_name: string; phone: string }) =>
    api.patch(`/admin/users/${user.user_id}`, body))
  const dirty = fullName !== user.full_name || phone !== user.phone

  return (
    <Card title="Profile" actions={
      <Button disabled={!dirty} loading={save.isPending} onClick={() => save.mutate({ full_name: fullName, phone })}>
        Save
      </Button>}>
      <div className="space-y-4">
        <TextInput label="Full name" value={fullName} onChange={(e) => setFullName(e.target.value)} />
        <TextInput label="Phone" value={phone} onChange={(e) => setPhone(e.target.value)}
          help="Consultation Agent finds this person's broker profile by the last 10 digits." />
        <ErrorBox error={save.error} />
      </div>
    </Card>
  )
}

function RolesCard({ user, roles }: { user: AdminUser; roles: Role[] }) {
  const { user: me } = useAuth()
  const [selected, setSelected] = useState(user.roles)
  const [confirming, setConfirming] = useState(false)
  useEffect(() => setSelected(user.roles), [user.roles])
  const save = useUserMutation(user.user_id, (body: { roles: string[] }) =>
    api.patch(`/admin/users/${user.user_id}/roles`, body))
  const dirty = [...selected].sort().join() !== [...user.roles].sort().join()

  return (
    <Card title="Roles" actions={
      <Button disabled={!dirty} onClick={() => setConfirming(true)}>Save roles</Button>}>
      <div className="space-y-3">
        <RolePicker roles={roles} selected={selected} onChange={setSelected} />
        {me?.user_id === user.user_id && (
          <Notice>These are your own roles. You cannot remove your own console access.</Notice>
        )}
      </div>
      <ConfirmDialog open={confirming} title="Change roles?" confirmLabel="Change roles" busy={save.isPending}
        error={save.error}
        message={<>
          <p>{user.email} will be signed out of every app and must sign in again.</p>
          <p className="mt-2">Their new access reaches every service within about a minute.</p>
        </>}
        onClose={() => { setConfirming(false); save.reset() }}
        onConfirm={() => save.mutate({ roles: selected }, { onSuccess: () => setConfirming(false) })} />
    </Card>
  )
}

function AttributesCard({ user, catalogues, roleLabels }:
  { user: AdminUser; catalogues: ServiceDetail[]; roleLabels: Record<string, string> }) {
  const withAttributes = catalogues.filter((c) => c.attributes.some((a) => !a.retired))
  if (!withAttributes.length) return null
  return (
    <Card title="Service attributes">
      <div className="space-y-5">
        {withAttributes.map((service) => (
          <ServiceAttributes key={service.key} user={user} service={service} roleLabels={roleLabels} />
        ))}
      </div>
    </Card>
  )
}

function ServiceAttributes({ user, service, roleLabels }:
  { user: AdminUser; service: ServiceDetail; roleLabels: Record<string, string> }) {
  const current = user.attributes[service.key] ?? {}
  const [values, setValues] = useState<Record<string, string>>(current)
  useEffect(() => setValues(user.attributes[service.key] ?? {}), [user.attributes, service.key])
  const save = useUserMutation(user.user_id, (attributes: Record<string, string>) =>
    api.put(`/admin/users/${user.user_id}/attributes/${service.key}`, { attributes }))
  const live = service.attributes.filter((a) => !a.retired)
  const dirty = live.some((a) => (values[a.key] ?? '') !== (current[a.key] ?? ''))

  const desk = live.find((a) => a.key === 'desk')
  const warning = service.key === 'broker_tools' && desk
    ? deskWarning(user.roles, values.desk || undefined, desk.options, roleLabels)
    : null

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <h3 className="text-sm font-medium text-gray-900">{service.name}</h3>
        <Button variant="secondary" disabled={!dirty} loading={save.isPending}
          onClick={() => save.mutate(Object.fromEntries(live.map((a) => [a.key, values[a.key] ?? ''])))}>
          Save
        </Button>
      </div>
      {live.map((attribute) => (
        <SelectInput key={attribute.key} label={attribute.label} placeholder="None" value={values[attribute.key] ?? ''}
          onChange={(e) => setValues({ ...values, [attribute.key]: e.target.value })}
          options={attribute.options.map((o) => ({ value: o, label: roleLabels[o] ?? o }))}
          help={attribute.key === 'desk' && service.key === 'broker_tools'
            ? 'Broker Tools assigns leads, builds the distribution pool and groups team reports by desk.' : undefined} />
      ))}
      {warning && <Notice>{warning}</Notice>}
      <ErrorBox error={save.error} />
    </div>
  )
}

function AccountCard({ user }: { user: AdminUser }) {
  const { user: me } = useAuth()
  const [confirmStatus, setConfirmStatus] = useState(false)
  const [settingPassword, setSettingPassword] = useState(false)
  const [password, setPassword] = useState('')
  const [repeat, setRepeat] = useState('')
  const [resetSent, setResetSent] = useState(false)

  const status = useUserMutation(user.user_id, (body: { is_active: boolean }) =>
    api.patch(`/admin/users/${user.user_id}/status`, body))
  const setPasswordMutation = useMutation({
    mutationFn: () => api.post(`/admin/users/${user.user_id}/set-password`, { new_password: password }),
    onSuccess: () => { setSettingPassword(false); setPassword(''); setRepeat('') },
  })
  const reset = useMutation({
    mutationFn: () => api.post(`/admin/users/${user.user_id}/reset-password`),
    onSuccess: () => setResetSent(true),
  })
  const mismatch = repeat.length > 0 && password !== repeat

  return (
    <Card title="Account">
      <div className="flex flex-wrap gap-2">
        <Button variant={user.is_active ? 'danger' : 'primary'} disabled={me?.user_id === user.user_id}
          onClick={() => setConfirmStatus(true)}>
          {user.is_active ? 'Deactivate' : 'Activate'}
        </Button>
        <Button variant="secondary" onClick={() => setSettingPassword(true)}>Set password</Button>
        <Button variant="secondary" loading={reset.isPending} onClick={() => reset.mutate()}>Email a reset link</Button>
      </div>
      <div className="mt-3 space-y-2">
        {resetSent && <Notice tone="blue">Reset email requested. Delivery is not guaranteed; set a password if it doesn&apos;t arrive.</Notice>}
        {setPasswordMutation.isSuccess && <Notice tone="blue">Password set. They were signed out everywhere; hand it over privately.</Notice>}
        <ErrorBox error={reset.error} />
      </div>

      <ConfirmDialog open={confirmStatus} danger={user.is_active} busy={status.isPending} error={status.error}
        title={user.is_active ? 'Deactivate this account?' : 'Activate this account?'}
        confirmLabel={user.is_active ? 'Deactivate' : 'Activate'}
        message={user.is_active
          ? `${user.email} will be signed out and refused by every service within about a minute. Their roles are kept.`
          : `${user.email} will be able to sign in again with their current roles.`}
        onClose={() => { setConfirmStatus(false); status.reset() }}
        onConfirm={() => status.mutate({ is_active: !user.is_active }, { onSuccess: () => setConfirmStatus(false) })} />

      <Modal open={settingPassword} title="Set password" onClose={() => setSettingPassword(false)} footer={<>
        <Button variant="secondary" onClick={() => setSettingPassword(false)}>Cancel</Button>
        <Button disabled={password.length < 10 || password !== repeat} loading={setPasswordMutation.isPending}
          onClick={() => setPasswordMutation.mutate()}>Set password</Button>
      </>}>
        <div className="space-y-4">
          <p className="text-sm text-gray-600">
            For someone locked out. They are signed out everywhere and should change it themselves afterwards.
          </p>
          <TextInput label="New password" type="password" autoComplete="new-password" value={password}
            onChange={(e) => setPassword(e.target.value)} help="At least 10 characters." />
          <TextInput label="Repeat" type="password" autoComplete="new-password" value={repeat}
            onChange={(e) => setRepeat(e.target.value)} error={mismatch ? 'The two passwords differ.' : null} />
          <ErrorBox error={setPasswordMutation.error} />
        </div>
      </Modal>
    </Card>
  )
}

function AccessCard({ user, catalogues }: { user: AdminUser; catalogues: ServiceDetail[] }) {
  const label = (service: string, resource: string, action?: string, scope?: string) => {
    const res = catalogues.find((c) => c.key === service)?.resources.find((r) => r.key === resource)
    if (scope) return res?.scopes.find((s) => s.key === scope)?.label ?? scope
    if (action) return res?.actions.find((a) => a.key === action)?.label ?? action
    return res?.label ?? resource
  }
  const name = (service: string) => catalogues.find((c) => c.key === service)?.name ?? service

  return (
    <Card title="Effective access">
      <p className="mb-4 text-xs text-gray-500">
        What this person can do in each service right now, from all their roles combined.
      </p>
      <div className="space-y-4">
        {Object.entries(user.apps).map(([service, app]) => (
          <details key={service} className="rounded-lg border border-gray-200" open={app.access && service !== 'identity'}>
            <summary className="flex cursor-pointer items-center justify-between px-3 py-2 text-sm">
              <span className="font-medium text-gray-900">{name(service)}</span>
              <span className="flex items-center gap-2">
                {app.primary_role && <span className="text-xs text-gray-500">as {app.primary_role}</span>}
                {app.access ? <Badge variant="green">Access</Badge> : <Badge>No access</Badge>}
              </span>
            </summary>
            {Object.keys(app.permissions).length > 0 && (
              <ul className="space-y-1 border-t border-gray-100 px-3 py-2 text-xs text-gray-700">
                {Object.entries(app.permissions).map(([resource, actions]) => (
                  <li key={resource}>
                    <span className="font-medium">{label(service, resource)}</span>:{' '}
                    {Object.entries(actions).map(([action, scopes]) =>
                      `${label(service, resource, action)} (${scopes.map((s) => label(service, resource, undefined, s)).join(', ')})`,
                    ).join(' · ')}
                  </li>
                ))}
              </ul>
            )}
          </details>
        ))}
      </div>
    </Card>
  )
}
