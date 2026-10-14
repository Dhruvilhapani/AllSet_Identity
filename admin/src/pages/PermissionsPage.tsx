import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import clsx from 'clsx'
import { useEffect, useMemo, useRef, useState } from 'react'
import { Navigate, useNavigate, useParams } from 'react-router-dom'

import { Button, ErrorBox, Loading, Modal, Notice, PageHeader, SelectInput } from '../components/ui'
import { api, ApiError } from '../lib/api'
import { ALL, cellKey, describe, diff, rolesInUse, serialise, toCells, toggleScope, type Cells } from '../lib/matrix'
import { keys, useService, useServices } from '../lib/queries'
import type { CatalogueResource, GrantsResponse } from '../lib/types'

export function PermissionsPage() {
  const { service } = useParams()
  const services = useServices()
  const navigate = useNavigate()

  if (!service) {
    const first = services.data?.find((s) => !s.is_system) ?? services.data?.[0]
    if (first) return <Navigate to={`/permissions/${first.key}`} replace />
    return services.isLoading ? <Loading what="Loading services" /> : <ErrorBox error={services.error} />
  }

  return (
    <>
      <PageHeader title="Permissions"
        description="What each role may do in a service. A person's access is the union of their roles. Scopes limit which rows an action covers."
        actions={
          <div className="w-64">
            <SelectInput label="Service" value={service} onChange={(e) => navigate(`/permissions/${e.target.value}`)}
              options={(services.data ?? []).map((s) => ({ value: s.key, label: s.name }))} />
          </div>} />
      <Matrix key={service} service={service} />
    </>
  )
}

function Matrix({ service }: { service: string }) {
  const queryClient = useQueryClient()
  const catalogue = useService(service)
  const grants = useQuery({
    queryKey: keys.grants(service),
    queryFn: () => api.get<GrantsResponse>(`/admin/services/${service}/grants`),
    // Refetch only when asked: a background refetch must never replace a matrix
    // an admin is part-way through editing.
    refetchOnWindowFocus: false,
    staleTime: Infinity,
  })

  // The matrix as loaded, and the version it was loaded at. Edits are compared
  // with it, and saved with If-Match on its version, so a change someone else
  // saved in the meantime is a 409 rather than silently overwritten.
  const [base, setBase] = useState<{ version: number; cells: Cells } | null>(null)
  const [cells, setCells] = useState<Cells>(new Map())
  const [reviewing, setReviewing] = useState(false)
  const [allRoles, setAllRoles] = useState(false)
  const editing = useRef({ base, cells })
  editing.current = { base, cells }

  useEffect(() => {
    if (!grants.data) return
    const { base: current, cells: edited } = editing.current
    if (current && diff(current.cells, edited).length) return   // keep unsaved edits
    const loaded = { version: grants.data.version, cells: toCells(grants.data.grants) }
    setBase(loaded)
    setCells(loaded.cells)
  }, [grants.data])

  const initial = useMemo(() => base?.cells ?? new Map<string, string[]>(), [base])

  // Throw away local edits and adopt what the server has now.
  async function reload() {
    const { data } = await grants.refetch()
    if (!data) return
    const loaded = { version: data.version, cells: toCells(data.grants) }
    setBase(loaded)
    setCells(loaded.cells)
  }

  const save = useMutation({
    mutationFn: () => api.put<{ version: number }>(`/admin/services/${service}/grants`,
      { grants: serialise(cells, superusers) }, { 'If-Match': `"${base?.version}"` }),
    onSuccess: ({ version }) => {
      setBase({ version, cells })
      setReviewing(false)
      void queryClient.invalidateQueries({ queryKey: keys.grants(service) })
      void queryClient.invalidateQueries({ queryKey: keys.roles })
      void queryClient.invalidateQueries({ queryKey: ['users'] })
    },
  })

  const roles = grants.data?.roles ?? []
  const superusers = new Set(roles.filter((r) => r.is_superuser).map((r) => r.key))
  // Roles are shared by every service, but most hold nothing in a given one.
  const inUse = rolesInUse(roles, initial, cells)
  const shown = allRoles ? roles : roles.filter((r) => inUse.has(r.key))
  const hidden = roles.length - inUse.size
  const resources = useMemo(() => {
    const live = (catalogue.data?.resources ?? []).filter((r) => !r.retired)
    return [...live.filter((r) => r.key === 'app'), ...live.filter((r) => r.key !== 'app')]
  }, [catalogue.data])
  const changes = diff(initial, cells)
  const editable = Boolean(grants.data?.editable)
  const stale = save.error instanceof ApiError && save.error.status === 409

  if (catalogue.isLoading || grants.isLoading) return <Loading what="Loading permissions" />
  if (catalogue.error || grants.error) return <ErrorBox error={catalogue.error ?? grants.error} />

  const labels = { roles: Object.fromEntries(roles.map((r) => [r.key, r.label])), resources }

  return (
    <div className="space-y-4">
      {!editable && (
        <Notice tone="blue">
          {catalogue.data?.name} is a system service: its permissions decide who can use this console, so they are
          set by migration and cannot be edited here.
        </Notice>
      )}
      {editable && (
        <div className="flex items-center justify-between rounded-xl border border-gray-200 bg-white px-4 py-3">
          <p className="text-sm text-gray-600">
            {changes.length ? `${changes.length} unsaved change${changes.length === 1 ? '' : 's'}.` : 'No unsaved changes.'}
          </p>
          <div className="flex gap-2">
            <Button variant="secondary" disabled={!changes.length} onClick={() => setCells(initial)}>Discard</Button>
            <Button disabled={!changes.length} onClick={() => setReviewing(true)}>Review changes</Button>
          </div>
        </div>
      )}

      {(hidden > 0 || allRoles) && (
        <label className="flex items-center gap-2 text-sm text-gray-600">
          <input type="checkbox" className="h-4 w-4 rounded border-gray-300" checked={allRoles}
            onChange={(e) => setAllRoles(e.target.checked)} />
          Show all roles
          {hidden > 0 && (
            <span className="text-gray-400">
              ({hidden} with no permissions in {catalogue.data?.name} {allRoles ? 'shown' : 'hidden'})
            </span>
          )}
        </label>
      )}

      <div className="overflow-x-auto rounded-xl border border-gray-200 bg-white">
        <table className="min-w-full text-sm">
          <thead className="bg-gray-50">
            <tr>
              <th scope="col" className="sticky left-0 z-10 bg-gray-50 px-4 py-2.5 text-left text-xs font-semibold uppercase tracking-wide text-gray-500">
                Resource › action
              </th>
              {shown.map((role) => (
                <th key={role.key} scope="col" className="px-3 py-2.5 text-left text-xs font-semibold text-gray-600">
                  {role.label}
                  {role.is_superuser && <span className="block font-normal text-gray-400">superuser</span>}
                </th>
              ))}
            </tr>
          </thead>
          {resources.map((resource) => (
            <ResourceRows key={resource.key} resource={resource} roles={shown} cells={cells} initial={initial}
              superusers={superusers} editable={editable}
              onToggle={(role, action, scope) => setCells((c) => toggleScope(c, role, resource.key, action, scope))} />
          ))}
        </table>
      </div>

      <Modal open={reviewing} size="lg" title="Review changes" onClose={() => { setReviewing(false); save.reset() }}
        footer={<>
          <Button variant="secondary" onClick={() => setReviewing(false)}>Keep editing</Button>
          {stale
            ? <Button onClick={() => { save.reset(); setReviewing(false); void reload() }}>Discard mine and reload</Button>
            : <Button loading={save.isPending} onClick={() => save.mutate()}>Save {changes.length} change{changes.length === 1 ? '' : 's'}</Button>}
        </>}>
        <div className="space-y-3">
          <ul className="list-disc space-y-1 pl-5 text-sm text-gray-700">
            {changes.map((change) => (
              <li key={cellKey(change.role, change.resource, change.action)}>{describe(change, labels)}</li>
            ))}
          </ul>
          <p className="text-xs text-gray-500">Saved changes reach every service within about a minute.</p>
          {stale
            ? <ErrorBox error="Someone else changed these permissions since you loaded them. Reload to see their changes; yours will be discarded." />
            : <ErrorBox error={save.error} />}
        </div>
      </Modal>
    </div>
  )
}

function ResourceRows({ resource, roles, cells, initial, superusers, editable, onToggle }: {
  resource: CatalogueResource
  roles: GrantsResponse['roles']
  cells: Cells
  initial: Cells
  superusers: Set<string>
  editable: boolean
  onToggle: (role: string, action: string, scope: string) => void
}) {
  const actions = resource.actions.filter((a) => !a.retired)
  const scopes = resource.scopes.filter((s) => !s.retired)
  const isApp = resource.key === 'app'

  return (
    <tbody className="divide-y divide-gray-100 border-t border-gray-200">
      <tr className="bg-gray-50/60">
        <th colSpan={roles.length + 1} scope="rowgroup"
          className="sticky left-0 px-4 py-2 text-left text-xs font-semibold uppercase tracking-wide text-gray-700">
          {isApp ? 'Access to the service' : resource.label}
          {resource.description && <span className="ml-2 font-normal normal-case text-gray-400">{resource.description}</span>}
        </th>
      </tr>
      {actions.map((action) => (
        <tr key={action.key}>
          <th scope="row" className="sticky left-0 bg-white px-4 py-2 text-left font-normal text-gray-700">
            {isApp ? 'Can use the service' : action.label}
          </th>
          {roles.map((role) => {
            const key = cellKey(role.key, resource.key, action.key)
            const granted = cells.get(key) ?? []
            const changed = (initial.get(key) ?? []).join() !== granted.join()
            if (superusers.has(role.key)) {
              return <td key={role.key} className="px-3 py-2 text-xs text-gray-400">All</td>
            }
            return (
              <td key={role.key} className={clsx('px-3 py-2', changed && 'bg-amber-50')}>
                <div className="flex flex-wrap gap-1">
                  {scopes.map((scope) => {
                    const on = granted.includes(scope.key)
                    const onlyAll = scopes.length === 1
                    return (
                      <button key={scope.key} type="button" disabled={!editable}
                        aria-pressed={on}
                        aria-label={`${role.label}: ${resource.label} ${action.label} — ${scope.label}`}
                        title={scope.label}
                        onClick={() => onToggle(role.key, action.key, scope.key)}
                        className={clsx('rounded-md border px-2 py-0.5 text-xs',
                          on ? 'border-brand-600 bg-brand-600 text-white' : 'border-gray-300 bg-white text-gray-600 hover:bg-gray-100',
                          !editable && 'cursor-not-allowed opacity-70')}>
                        {onlyAll ? (on ? 'Yes' : 'No') : scope.key === ALL ? 'All' : scope.label}
                      </button>
                    )
                  })}
                </div>
              </td>
            )
          })}
        </tr>
      ))}
    </tbody>
  )
}
