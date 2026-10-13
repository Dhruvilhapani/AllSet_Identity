import { useMutation, useQueryClient } from '@tanstack/react-query'
import { format } from 'date-fns'
import { useState, type FormEvent } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'

import { Badge, Button, Card, ConfirmDialog, ErrorBox, Loading, Modal, Notice, PageHeader, Table,
  TextInput } from '../components/ui'
import { api } from '../lib/api'
import { keys, useService, useServices } from '../lib/queries'
import type { CreatedKey, ServiceDetail, ServiceKey } from '../lib/types'

const KEY_PATTERN = /^[a-z][a-z0-9_]{1,39}$/

export function when(value: string | null | undefined): string {
  return value ? format(new Date(value), 'd MMM yyyy, HH:mm') : '—'
}

export function ServicesPage() {
  const services = useServices()
  const [registering, setRegistering] = useState(false)

  return (
    <>
      <PageHeader title="Services"
        description="Every app that relies on AllSet Identity. Each one declares what can be controlled in a manifest it pushes on deploy; who gets what is set on the Permissions page."
        actions={<Button onClick={() => setRegistering(true)}>Register service</Button>} />
      <ErrorBox error={services.error} />
      {services.isLoading ? <Loading what="Loading services" /> : (
        <Table head={['Service', 'Key', 'Resources', 'Manifest pushed', 'Status']}>
          {(services.data ?? []).map((s) => (
            <tr key={s.key}>
              <td className="px-4 py-2.5">
                <Link to={`/services/${s.key}`} className="font-medium text-brand-700 hover:underline">{s.name}</Link>
                <p className="text-xs text-gray-500">{s.description}</p>
              </td>
              <td className="px-4 py-2.5 font-mono text-xs">{s.key}</td>
              <td className="px-4 py-2.5 text-gray-700">
                {s.resources}{s.retired_resources > 0 && <span className="text-xs text-gray-400"> (+{s.retired_resources} retired)</span>}
              </td>
              <td className="px-4 py-2.5 text-gray-600">{when(s.manifest_pushed_at)}</td>
              <td className="px-4 py-2.5">
                <div className="flex gap-1">
                  {s.is_active ? <Badge variant="green">Active</Badge> : <Badge variant="red">Inactive</Badge>}
                  {s.is_system && <Badge variant="purple">System</Badge>}
                </div>
              </td>
            </tr>
          ))}
        </Table>
      )}
      {registering && <RegisterDialog onClose={() => setRegistering(false)} />}
    </>
  )
}

function RegisterDialog({ onClose }: { onClose: () => void }) {
  const queryClient = useQueryClient()
  const navigate = useNavigate()
  const [key, setKey] = useState('')
  const [name, setName] = useState('')
  const [description, setDescription] = useState('')
  const register = useMutation({
    mutationFn: () => api.post<ServiceDetail>('/admin/services', { key, name: name.trim(), description: description.trim() }),
    onSuccess: (service) => {
      void queryClient.invalidateQueries({ queryKey: keys.services })
      onClose()
      navigate(`/services/${service.key}`)
    },
  })
  const keyError = key && !KEY_PATTERN.test(key) ? 'Lowercase letters, digits and _, starting with a letter.' : null

  function submit(e: FormEvent) {
    e.preventDefault()
    register.mutate()
  }

  return (
    <Modal open title="Register service" onClose={onClose} footer={<>
      <Button variant="secondary" onClick={onClose}>Cancel</Button>
      <Button type="submit" form="service-form" loading={register.isPending}
        disabled={!key || Boolean(keyError) || !name.trim()}>Register</Button>
    </>}>
      <form id="service-form" onSubmit={submit} className="space-y-4">
        <TextInput label="Key" value={key} onChange={(e) => setKey(e.target.value)} error={keyError}
          help={<>Becomes <code>apps.{key || 'key'}</code> in the introspect response. Cannot be changed.</>} />
        <TextInput label="Name" required value={name} onChange={(e) => setName(e.target.value)} />
        <TextInput label="Description" value={description} onChange={(e) => setDescription(e.target.value)} />
        <ErrorBox error={register.error} />
      </form>
    </Modal>
  )
}

export function ServiceDetailPage() {
  const { key = '' } = useParams()
  const service = useService(key)
  const queryClient = useQueryClient()
  const refresh = () => {
    void queryClient.invalidateQueries({ queryKey: keys.service(key) })
    void queryClient.invalidateQueries({ queryKey: keys.services })
  }

  if (service.isLoading) return <Loading what="Loading service" />
  if (service.error || !service.data) return <ErrorBox error={service.error ?? 'Service not found'} />
  const s = service.data

  return (
    <>
      <p className="mb-2 text-sm"><Link to="/services" className="text-brand-700 hover:underline">← Services</Link></p>
      <PageHeader title={s.name} description={<>{s.description} <code className="text-xs">({s.key})</code></>}
        actions={<Link to={`/permissions/${s.key}`}><Button variant="secondary">Edit permissions</Button></Link>} />
      <div className="grid grid-cols-1 gap-6 xl:grid-cols-2">
        <div className="space-y-6">
          <SettingsCard service={s} onChange={refresh} />
          <KeysCard service={s} onChange={refresh} />
        </div>
        <CatalogueCard service={s} onChange={refresh} />
      </div>
    </>
  )
}

function SettingsCard({ service, onChange }: { service: ServiceDetail; onChange: () => void }) {
  const [name, setName] = useState(service.name)
  const [description, setDescription] = useState(service.description)
  const update = useMutation({
    mutationFn: (body: Record<string, unknown>) => api.patch(`/admin/services/${service.key}`, body),
    onSuccess: onChange,
  })
  const dirty = name !== service.name || description !== service.description

  return (
    <Card title="Settings">
      <div className="space-y-4">
        <TextInput label="Name" value={name} onChange={(e) => setName(e.target.value)} />
        <TextInput label="Description" value={description} onChange={(e) => setDescription(e.target.value)} />
        <div className="flex flex-wrap gap-2">
          <Button disabled={!dirty} loading={update.isPending} onClick={() => update.mutate({ name, description })}>Save</Button>
          {!service.is_system && (
            <Button variant={service.is_active ? 'danger' : 'secondary'} loading={update.isPending}
              onClick={() => update.mutate({ is_active: !service.is_active })}>
              {service.is_active ? 'Deactivate service' : 'Activate service'}
            </Button>
          )}
        </div>
        {!service.is_active && <Notice>Inactive: nobody has access to this service, and its keys are not accepted.</Notice>}
        <p className="text-xs text-gray-500">Manifest last pushed: {when(service.manifest_pushed_at)}</p>
        <ErrorBox error={update.error} />
      </div>
    </Card>
  )
}

function KeysCard({ service, onChange }: { service: ServiceDetail; onChange: () => void }) {
  const [label, setLabel] = useState('')
  const [created, setCreated] = useState<CreatedKey | null>(null)
  const [copied, setCopied] = useState(false)
  const [revoking, setRevoking] = useState<ServiceKey | null>(null)

  const create = useMutation({
    mutationFn: () => api.post<CreatedKey>(`/admin/services/${service.key}/keys`, { label: label.trim() }),
    onSuccess: (key) => { setCreated(key); setLabel(''); onChange() },
  })
  const revoke = useMutation({
    mutationFn: (id: string) => api.del(`/admin/services/${service.key}/keys/${id}`),
    onSuccess: () => { setRevoking(null); onChange() },
  })

  async function copy() {
    if (!created) return
    try {
      await navigator.clipboard.writeText(created.key)
      setCopied(true)
    } catch {
      setCopied(false)
    }
  }

  return (
    <Card title="Service keys">
      <div className="space-y-4">
        <p className="text-sm text-gray-600">
          A key lets the service call introspect and push its manifest
          (<code className="text-xs">PUT /v1/services/manifest</code>). Store it in the service&apos;s Secret Manager;
          generate one per environment.
        </p>
        <div className="flex items-end gap-2">
          <div className="flex-1">
            <TextInput label="Label" placeholder="e.g. prod" value={label} onChange={(e) => setLabel(e.target.value)} />
          </div>
          <Button loading={create.isPending} onClick={() => create.mutate()}>Generate key</Button>
        </div>
        <ErrorBox error={create.error} />
        <ul className="divide-y divide-gray-100 text-sm">
          {(service.keys ?? []).map((k) => (
            <li key={k.id} className="flex items-center justify-between py-2">
              <span>
                <code className="text-xs">{k.key_prefix}…</code> <span className="text-gray-700">{k.label}</span>
                <span className="block text-xs text-gray-500">Created {when(k.created_at)}
                  {k.revoked_at && <> · revoked {when(k.revoked_at)}</>}</span>
              </span>
              {k.revoked_at ? <Badge variant="red">Revoked</Badge>
                : <Button variant="ghost" className="text-red-600" onClick={() => setRevoking(k)}>Revoke</Button>}
            </li>
          ))}
          {!service.keys?.length && <li className="py-2 text-gray-500">No keys generated here yet.</li>}
        </ul>
      </div>

      <Modal open={created !== null} title="Copy the new key now" onClose={() => { setCreated(null); setCopied(false) }}
        footer={<Button onClick={() => { setCreated(null); setCopied(false) }}>Done</Button>}>
        <div className="space-y-3 text-sm">
          <Notice>This is the only time the key is shown. Only its hash is stored.</Notice>
          <code className="block break-all rounded-lg bg-gray-100 p-3 text-xs">{created?.key}</code>
          <Button variant="secondary" onClick={() => void copy()}>{copied ? 'Copied' : 'Copy to clipboard'}</Button>
        </div>
      </Modal>
      <ConfirmDialog open={revoking !== null} danger title="Revoke this key?" confirmLabel="Revoke"
        busy={revoke.isPending} error={revoke.error}
        message={`Requests using ${revoking?.key_prefix}… are refused within about 30 seconds.`}
        onClose={() => { setRevoking(null); revoke.reset() }}
        onConfirm={() => revoking && revoke.mutate(revoking.id)} />
    </Card>
  )
}

function CatalogueCard({ service, onChange }: { service: ServiceDetail; onChange: () => void }) {
  const [deleting, setDeleting] = useState<string | null>(null)
  const remove = useMutation({
    mutationFn: (resource: string) => api.del(`/admin/services/${service.key}/resources/${resource}`),
    onSuccess: () => { setDeleting(null); onChange() },
  })
  const resources = service.resources.filter((r) => r.key !== 'app')

  return (
    <Card title="Catalogue">
      <p className="mb-4 text-xs text-gray-500">
        From the service&apos;s manifest. Items the latest push no longer lists are retired: their grants are kept but
        give nothing. A retired resource can be deleted here.
      </p>
      {!resources.length && <p className="text-sm text-gray-500">No resources yet. The service has not pushed a manifest.</p>}
      <ul className="space-y-3">
        {resources.map((r) => (
          <li key={r.key} className={r.retired ? 'opacity-60' : ''}>
            <div className="flex items-center justify-between">
              <p className="text-sm font-medium text-gray-900">
                {r.label} <code className="text-xs font-normal text-gray-500">{r.key}</code>
                {r.retired && <span className="ml-2"><Badge>Retired</Badge></span>}
              </p>
              {r.retired && <Button variant="ghost" className="text-red-600" onClick={() => setDeleting(r.key)}>Delete</Button>}
            </div>
            <p className="text-xs text-gray-600">
              Actions: {r.actions.map((a) => (a.retired ? `${a.label} (retired)` : a.label)).join(', ')}
            </p>
            <p className="text-xs text-gray-600">
              Scopes: {r.scopes.map((s) => (s.retired ? `${s.label} (retired)` : s.label)).join(', ')}
            </p>
          </li>
        ))}
      </ul>
      {service.attributes.length > 0 && (
        <div className="mt-5 border-t border-gray-100 pt-4">
          <p className="mb-2 text-sm font-medium text-gray-900">User attributes</p>
          {service.attributes.map((a) => (
            <p key={a.key} className="text-xs text-gray-600">
              {a.label} <code>{a.key}</code>: {a.options.join(', ')}{a.retired && ' (retired)'}
            </p>
          ))}
        </div>
      )}
      <ConfirmDialog open={deleting !== null} danger title={`Delete ${deleting}?`} confirmLabel="Delete"
        busy={remove.isPending} error={remove.error}
        message="The retired resource and every grant on it are removed for good."
        onClose={() => { setDeleting(null); remove.reset() }}
        onConfirm={() => deleting && remove.mutate(deleting)} />
    </Card>
  )
}
