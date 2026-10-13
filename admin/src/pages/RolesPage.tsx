import { useMutation, useQueryClient } from '@tanstack/react-query'
import { useState, type FormEvent } from 'react'

import { Badge, Button, ConfirmDialog, ErrorBox, Loading, Modal, PageHeader, Table, TextInput } from '../components/ui'
import { api } from '../lib/api'
import { keys, useRoles, useServices } from '../lib/queries'
import type { Role } from '../lib/types'

const KEY_PATTERN = /^[a-z][a-z0-9_]{1,39}$/

export function RolesPage() {
  const roles = useRoles()
  const services = useServices()
  const [editing, setEditing] = useState<Role | 'new' | null>(null)
  const [deleting, setDeleting] = useState<Role | null>(null)
  const queryClient = useQueryClient()

  const remove = useMutation({
    mutationFn: (key: string) => api.del(`/admin/roles/${key}`),
    onSuccess: () => {
      setDeleting(null)
      void queryClient.invalidateQueries({ queryKey: keys.roles })
    },
  })
  const serviceName = (key: string) => services.data?.find((s) => s.key === key)?.name ?? key

  return (
    <>
      <PageHeader title="Roles"
        description="A role is a bundle of permissions across services. What each role may do is set on the Permissions page; who holds it, on each user's page."
        actions={<Button onClick={() => setEditing('new')}>New role</Button>} />
      <ErrorBox error={roles.error} />
      {roles.isLoading ? <Loading what="Loading roles" /> : (
        <Table head={['Role', 'Key', 'Priority', 'Group', 'Members', 'Uses', '']}>
          {(roles.data?.roles ?? []).map((role) => (
            <tr key={role.key} className="align-top">
              <td className="px-4 py-2.5">
                <p className="font-medium text-gray-900">{role.label}</p>
                <p className="text-xs text-gray-500">{role.description}</p>
                {role.is_superuser && <Badge variant="purple" title="Every action in every service">Superuser</Badge>}
              </td>
              <td className="px-4 py-2.5 font-mono text-xs text-gray-700">{role.key}</td>
              <td className="px-4 py-2.5 text-gray-700">{role.priority}</td>
              <td className="px-4 py-2.5 text-gray-700">{role.exclusive_group ?? '—'}</td>
              <td className="px-4 py-2.5 text-gray-700">{role.members}</td>
              <td className="px-4 py-2.5 text-xs text-gray-600">
                {role.apps.filter((a) => a !== 'identity').map(serviceName).join(', ') || '—'}
              </td>
              <td className="px-4 py-2.5 text-right">
                {!role.is_superuser && (
                  <div className="flex justify-end gap-1">
                    <Button variant="ghost" onClick={() => setEditing(role)}>Edit</Button>
                    <Button variant="ghost" className="text-red-600" onClick={() => setDeleting(role)}>Delete</Button>
                  </div>
                )}
              </td>
            </tr>
          ))}
        </Table>
      )}
      <p className="mt-3 text-xs text-gray-500">
        Priority decides which role names a person in a service when they hold several (lowest wins); it is used for
        display and audit columns only. Roles in the same group are mutually exclusive.
      </p>

      {editing && <RoleDialog role={editing === 'new' ? null : editing} onClose={() => setEditing(null)} />}
      <ConfirmDialog open={deleting !== null} danger title={`Delete ${deleting?.label}?`} confirmLabel="Delete"
        busy={remove.isPending} error={remove.error}
        message="The role and all its grants are removed. This is refused while anyone holds it."
        onClose={() => { setDeleting(null); remove.reset() }}
        onConfirm={() => deleting && remove.mutate(deleting.key)} />
    </>
  )
}

function RoleDialog({ role, onClose }: { role: Role | null; onClose: () => void }) {
  const queryClient = useQueryClient()
  const [key, setKey] = useState(role?.key ?? '')
  const [label, setLabel] = useState(role?.label ?? '')
  const [description, setDescription] = useState(role?.description ?? '')
  const [priority, setPriority] = useState(String(role?.priority ?? 100))
  const [group, setGroup] = useState(role?.exclusive_group ?? '')

  const save = useMutation({
    mutationFn: () => {
      const body = { label: label.trim(), description: description.trim(), priority: Number(priority),
        exclusive_group: group.trim() }
      return role
        ? api.patch(`/admin/roles/${role.key}`, body)
        : api.post('/admin/roles', { ...body, key, exclusive_group: body.exclusive_group || null })
    },
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: keys.roles })
      onClose()
    },
  })

  const keyError = !role && key && !KEY_PATTERN.test(key)
    ? 'Lowercase letters, digits and _, starting with a letter (2-40 characters).' : null

  function submit(e: FormEvent) {
    e.preventDefault()
    save.mutate()
  }

  return (
    <Modal open title={role ? `Edit ${role.label}` : 'New role'} onClose={onClose} footer={<>
      <Button variant="secondary" onClick={onClose}>Cancel</Button>
      <Button type="submit" form="role-form" loading={save.isPending}
        disabled={!label.trim() || (!role && (!key || Boolean(keyError)))}>Save</Button>
    </>}>
      <form id="role-form" onSubmit={submit} className="space-y-4">
        <TextInput label="Key" value={key} disabled={Boolean(role)} onChange={(e) => setKey(e.target.value)}
          error={keyError} help="Fixed once created: it appears in tokens and in services' audit columns." />
        <TextInput label="Label" required value={label} onChange={(e) => setLabel(e.target.value)} />
        <TextInput label="Description" value={description} onChange={(e) => setDescription(e.target.value)} />
        <TextInput label="Priority" type="number" min={0} max={10000} value={priority}
          onChange={(e) => setPriority(e.target.value)} help="Lowest wins when a person holds several roles." />
        <TextInput label="Exclusive group" value={group} onChange={(e) => setGroup(e.target.value)}
          help="Optional. A person can hold only one role per group (pre-sales and sales share 'desk')." />
        {!role && <p className="text-xs text-gray-500">A new role grants nothing until you tick it on the Permissions page.</p>}
        <ErrorBox error={save.error} />
      </form>
    </Modal>
  )
}
