import { describe as group, expect, it } from 'vitest'

import { ALL, cellKey, describe, diff, serialise, toCells, toggleScope } from './matrix'
import type { CatalogueResource, Grants } from './types'

const grants: Grants = {
  presales: { lead: { read: ['own_presales'], create: ['all'] } },
  tech: { lead: { read: ['all'] } },
}

const lead: CatalogueResource = {
  key: 'lead', label: 'Leads', description: '', retired: false,
  actions: [{ key: 'read', label: 'Read', retired: false }, { key: 'create', label: 'Create', retired: false }],
  scopes: [
    { key: 'all', label: 'All', is_all: true, retired: false },
    { key: 'own_presales', label: 'Own leads (pre-sales owner)', is_all: false, retired: false },
    { key: 'own_sales', label: 'Own leads (sales owner)', is_all: false, retired: false },
  ],
}

group('toggleScope', () => {
  it('adds and removes a named scope', () => {
    let cells = toCells(grants)
    cells = toggleScope(cells, 'presales', 'lead', 'read', 'own_sales')
    expect(cells.get(cellKey('presales', 'lead', 'read'))).toEqual(['own_presales', 'own_sales'])
    cells = toggleScope(cells, 'presales', 'lead', 'read', 'own_presales')
    cells = toggleScope(cells, 'presales', 'lead', 'read', 'own_sales')
    expect(cells.has(cellKey('presales', 'lead', 'read'))).toBe(false)
  })

  it('treats all as covering the named scopes', () => {
    let cells = toCells(grants)
    cells = toggleScope(cells, 'presales', 'lead', 'read', ALL)
    expect(cells.get(cellKey('presales', 'lead', 'read'))).toEqual(['all'])
    cells = toggleScope(cells, 'presales', 'lead', 'read', 'own_sales')
    expect(cells.get(cellKey('presales', 'lead', 'read'))).toEqual(['own_sales'])
  })

  it('never mutates the cells it was given', () => {
    const before = toCells(grants)
    toggleScope(before, 'sales', 'lead', 'read', 'own_sales')
    expect(before.has(cellKey('sales', 'lead', 'read'))).toBe(false)
  })
})

group('serialise', () => {
  it('round-trips the grants and leaves superusers out', () => {
    const cells = toggleScope(toCells(grants), 'admin', 'lead', 'read', ALL)
    expect(serialise(cells, new Set(['admin']))).toEqual(grants)
  })
})

group('diff and describe', () => {
  it('lists each changed cell in words', () => {
    const before = toCells(grants)
    let after = toggleScope(before, 'presales', 'lead', 'read', ALL)
    after = toggleScope(after, 'tech', 'lead', 'create', ALL)
    const changes = diff(before, after)
    const labels = { roles: { presales: 'Pre-sales', tech: 'Tech' }, resources: [lead] }
    expect(changes.map((c) => describe(c, labels))).toEqual([
      'Pre-sales · Leads › Read: added All; removed Own leads (pre-sales owner)',
      'Tech · Leads › Create: added All',
    ])
  })

  it('reports nothing when the edits cancel out', () => {
    const before = toCells(grants)
    const after = toggleScope(toggleScope(before, 'tech', 'lead', 'create', ALL), 'tech', 'lead', 'create', ALL)
    expect(diff(before, after)).toEqual([])
  })
})
