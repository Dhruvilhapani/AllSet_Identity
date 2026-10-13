// The permission matrix as the console edits it: one cell per (role, resource,
// action), holding the scopes granted. Pure functions, so the logic that decides
// what gets saved is unit-tested (matrix.test.ts).

import type { CatalogueResource, Grants } from './types'

export const ALL = 'all'

export type Cells = Map<string, string[]>

export function cellKey(role: string, resource: string, action: string): string {
  return `${role}\u0000${resource}\u0000${action}`
}

function splitKey(key: string): [string, string, string] {
  const [role, resource, action] = key.split('\u0000')
  return [role, resource, action]
}

export function toCells(grants: Grants): Cells {
  const cells: Cells = new Map()
  for (const [role, resources] of Object.entries(grants)) {
    for (const [resource, actions] of Object.entries(resources)) {
      for (const [action, scopes] of Object.entries(actions)) {
        if (scopes.length) cells.set(cellKey(role, resource, action), [...scopes].sort())
      }
    }
  }
  return cells
}

/**
 * Toggle one scope in one cell. 'all' covers every row, so choosing it clears
 * the named scopes, and choosing a named scope clears 'all'.
 */
export function toggleScope(cells: Cells, role: string, resource: string, action: string, scope: string): Cells {
  const key = cellKey(role, resource, action)
  const current = cells.get(key) ?? []
  let next: string[]
  if (current.includes(scope)) next = current.filter((s) => s !== scope)
  else if (scope === ALL) next = [ALL]
  else next = [...current.filter((s) => s !== ALL), scope]

  const updated = new Map(cells)
  if (next.length) updated.set(key, next.sort())
  else updated.delete(key)
  return updated
}

/** The PUT body: the whole matrix for one service, superusers excluded. */
export function serialise(cells: Cells, superusers: Set<string>): Grants {
  const grants: Grants = {}
  for (const [key, scopes] of cells) {
    const [role, resource, action] = splitKey(key)
    if (superusers.has(role) || !scopes.length) continue
    grants[role] ??= {}
    grants[role][resource] ??= {}
    grants[role][resource][action] = [...scopes].sort()
  }
  return grants
}

export interface Change {
  role: string
  resource: string
  action: string
  added: string[]
  removed: string[]
}

export function diff(before: Cells, after: Cells): Change[] {
  const keys = new Set([...before.keys(), ...after.keys()])
  const changes: Change[] = []
  for (const key of [...keys].sort()) {
    const was = before.get(key) ?? []
    const now = after.get(key) ?? []
    const added = now.filter((s) => !was.includes(s))
    const removed = was.filter((s) => !now.includes(s))
    if (added.length || removed.length) {
      const [role, resource, action] = splitKey(key)
      changes.push({ role, resource, action, added, removed })
    }
  }
  return changes
}

export interface Labels {
  roles: Record<string, string>
  resources: CatalogueResource[]
}

/** "Sales · Leads › Read: added Own leads (sales owner); removed All" */
export function describe(change: Change, labels: Labels): string {
  const resource = labels.resources.find((r) => r.key === change.resource)
  const action = resource?.actions.find((a) => a.key === change.action)
  const scopeLabel = (key: string) => resource?.scopes.find((s) => s.key === key)?.label ?? key
  const parts: string[] = []
  if (change.added.length) parts.push(`added ${change.added.map(scopeLabel).join(', ')}`)
  if (change.removed.length) parts.push(`removed ${change.removed.map(scopeLabel).join(', ')}`)
  const role = labels.roles[change.role] ?? change.role
  return `${role} · ${resource?.label ?? change.resource} › ${action?.label ?? change.action}: ${parts.join('; ')}`
}
