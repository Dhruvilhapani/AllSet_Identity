import { useMutation, useQueryClient } from '@tanstack/react-query'
import { useMemo, useState, type FormEvent } from 'react'
import { Link, useNavigate } from 'react-router-dom'

import { RolePicker } from '../components/RolePicker'
import { Badge, Button, ErrorBox, Loading, Modal, PageHeader, SelectInput, Table, TextInput } from '../components/ui'
import { api } from '../lib/api'
import { useRoles, useServices, useUsers } from '../lib/queries'
import type { AdminUser } from '../lib/types'

export function UsersPage() {
  const [search, setSearch] = useState('')
  const [role, setRole] = useState('')
  const [service, setService] = useState('')
  const [active, setActive] = useState('')
  const [adding, setAdding] = useState(false)

  const users = useUsers({ role, service, active })
  const roles = useRoles()
  const services = useServices()

  const shown = useMemo(() => {
    const needle = search.trim().toLowerCase()
    return (users.data ?? []).filter((u) =>
      !needle || u.email.toLowerCase().includes(needle) || u.full_name.toLowerCase().includes(needle))
  }, [users.data, search])

  const serviceName = (key: string) => services.data?.find((s) => s.key === key)?.name ?? key

  return (
    <>
      <PageHeader title="Users" description="Everyone with an AllSet account, their roles, and which services they can use."
        actions={<Button onClick={() => setAdding(true)}>Add user</Button>} />

      <div className="mb-4 grid grid-cols-1 gap-3 md:grid-cols-4">
        <TextInput label="Search" placeholder="Name or email" value={search} onChange={(e) => setSearch(e.target.value)} />
        <SelectInput label="Role" placeholder="Any role" value={role} onChange={(e) => setRole(e.target.value)}
          options={(roles.data?.roles ?? []).map((r) => ({ value: r.key, label: r.label }))} />
        <SelectInput label="Service access" placeholder="Any service" value={service}
          onChange={(e) => setService(e.target.value)}
          options={(services.data ?? []).filter((s) => !s.is_system).map((s) => ({ value: s.key, label: s.name }))} />
        <SelectInput label="Status" placeholder="Active and inactive" value={active} onChange={(e) => setActive(e.target.value)}
          options={[{ value: 'true', label: 'Active' }, { value: 'false', label: 'Inactive' }]} />
      </div>

      <ErrorBox error={users.error} />
      {users.isLoading ? <Loading what="Loading users" /> : (
        <Table head={['Name', 'Email', 'Roles', 'Services', 'Status']}>
          {shown.map((u) => (
            <tr key={u.user_id} className="hover:bg-gray-50">
              <td className="px-4 py-2.5">
                <Link to={`/users/${u.user_id}`} className="font-medium text-brand-700 hover:underline">
                  {u.full_name || '(no name)'}
                </Link>
                {u.phone && <p className="text-xs text-gray-500">{u.phone}</p>}
              </td>
              <td className="px-4 py-2.5 text-gray-700">{u.email}</td>
              <td className="px-4 py-2.5">
                <div className="flex flex-wrap gap-1">
                  {u.roles.length ? u.roles.map((r, i) => <Badge key={r} variant="blue">{u.role_labels[i] ?? r}</Badge>)
                    : <Badge>No roles</Badge>}
                </div>
              </td>
              <td className="px-4 py-2.5 text-gray-600">
                {Object.entries(u.apps).filter(([key, app]) => app.access && key !== 'identity')
                  .map(([key]) => serviceName(key)).join(', ') || '—'}
              </td>
              <td className="px-4 py-2.5">
                {u.is_active ? <Badge variant="green">Active</Badge> : <Badge variant="red">Inactive</Badge>}
              </td>
            </tr>
          ))}
          {!shown.length && (
            <tr><td colSpan={5} className="px-4 py-8 text-center text-gray-500">No users match.</td></tr>
          )}
        </Table>
      )}

      <AddUserDialog open={adding} onClose={() => setAdding(false)} />
    </>
  )
}

function AddUserDialog({ open, onClose }: { open: boolean; onClose: () => void }) {
  const roles = useRoles()
  const queryClient = useQueryClient()
  const navigate = useNavigate()
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [repeat, setRepeat] = useState('')
  const [fullName, setFullName] = useState('')
  const [phone, setPhone] = useState('')
  const [selected, setSelected] = useState<string[]>([])
  const mismatch = repeat.length > 0 && password !== repeat

  const create = useMutation({
    mutationFn: () => api.post<AdminUser>('/admin/users', {
      email: email.trim(), password, full_name: fullName.trim(), phone: phone.trim(), roles: selected,
    }),
    onSuccess: (user) => {
      void queryClient.invalidateQueries({ queryKey: ['users'] })
      close()
      navigate(`/users/${user.user_id}`)
    },
  })

  function close() {
    setEmail(''); setPassword(''); setRepeat(''); setFullName(''); setPhone(''); setSelected([]); create.reset()
    onClose()
  }

  function submit(e: FormEvent) {
    e.preventDefault()
    create.mutate()
  }

  return (
    <Modal open={open} title="Add user" onClose={close} footer={<>
      <Button variant="secondary" onClick={close}>Cancel</Button>
      <Button type="submit" form="add-user-form" disabled={password.length < 10 || password !== repeat}
        loading={create.isPending}>Add user</Button>
    </>}>
      <form id="add-user-form" onSubmit={submit} className="space-y-4">
        <p className="text-sm text-gray-600">
          No email is sent. Hand the password over privately; they can change it after signing in.
        </p>
        <TextInput label="Email" type="email" required value={email} onChange={(e) => setEmail(e.target.value)} />
        <TextInput label="Password" type="password" autoComplete="new-password" required value={password}
          onChange={(e) => setPassword(e.target.value)} help="At least 10 characters." />
        <TextInput label="Repeat password" type="password" autoComplete="new-password" required value={repeat}
          onChange={(e) => setRepeat(e.target.value)} error={mismatch ? 'The two passwords differ.' : null} />
        <TextInput label="Full name" value={fullName} onChange={(e) => setFullName(e.target.value)} />
        <TextInput label="Phone" value={phone} onChange={(e) => setPhone(e.target.value)}
          help="Consultation Agent finds the person's broker profile by this number." />
        <RolePicker roles={roles.data?.roles ?? []} selected={selected} onChange={setSelected} />
        <ErrorBox error={create.error} />
      </form>
    </Modal>
  )
}
