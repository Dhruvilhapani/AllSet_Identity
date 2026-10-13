import { toggleRole } from '../lib/roles'
import type { Role } from '../lib/types'

/** Checkboxes, except that roles sharing an exclusive group act as a radio group. */
export function RolePicker({ roles, selected, onChange }:
  { roles: Role[]; selected: string[]; onChange: (roles: string[]) => void }) {
  return (
    <fieldset>
      <legend className="mb-2 text-xs font-semibold uppercase tracking-wide text-gray-600">Roles</legend>
      <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
        {roles.map((role) => (
          <label key={role.key} className="flex cursor-pointer items-start gap-2 rounded-lg border border-gray-200 p-2.5 text-sm hover:bg-gray-50">
            <input type="checkbox" className="mt-0.5" checked={selected.includes(role.key)}
              onChange={() => onChange(toggleRole(selected, role.key, roles))} />
            <span>
              <span className="font-medium text-gray-900">{role.label}</span>
              {role.exclusive_group && <span className="ml-1 text-xs text-gray-500">(one {role.exclusive_group} role)</span>}
              {role.description && <span className="block text-xs text-gray-500">{role.description}</span>}
            </span>
          </label>
        ))}
      </div>
    </fieldset>
  )
}
