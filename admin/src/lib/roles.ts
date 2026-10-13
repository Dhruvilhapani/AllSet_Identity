// Role-picking rules shared by the invite dialog and the user page.

import type { Role } from './types'

/**
 * Add or remove a role. Roles in the same exclusive group (presales and sales
 * share 'desk') behave like a radio group: picking one drops the others, as
 * the database would refuse both.
 */
export function toggleRole(selected: string[], key: string, roles: Role[]): string[] {
  if (selected.includes(key)) return selected.filter((r) => r !== key)
  const group = roles.find((r) => r.key === key)?.exclusive_group
  const kept = group
    ? selected.filter((r) => roles.find((role) => role.key === r)?.exclusive_group !== group)
    : selected
  return [...kept, key].sort()
}

/**
 * Broker Tools' desk is set separately from the presales/sales role, so the
 * two can disagree. Returns a warning to show, or null when they agree.
 * A desk option and the role it corresponds to share a key.
 */
export function deskWarning(roles: string[], desk: string | undefined, deskOptions: string[],
                            labels: Record<string, string>): string | null {
  const label = (key: string) => labels[key] ?? key
  const deskRoles = roles.filter((r) => deskOptions.includes(r))
  if (desk && !deskRoles.includes(desk)) {
    return deskRoles.length
      ? `Desk is ${label(desk)} but the user has the ${label(deskRoles[0])} role.`
      : `Desk is ${label(desk)} but the user has no ${label(desk)} role.`
  }
  if (!desk && deskRoles.length) {
    return `The user has the ${label(deskRoles[0])} role but no desk, so Broker Tools will not assign them leads.`
  }
  return null
}
