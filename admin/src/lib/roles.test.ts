import { describe, expect, it } from 'vitest'

import { deskWarning, toggleRole } from './roles'
import type { Role } from './types'

const role = (key: string, exclusive_group: string | null = null): Role => ({
  key, label: key, description: '', priority: 100, is_superuser: false, exclusive_group, members: 0, apps: [],
})
const roles = [role('presales', 'desk'), role('sales', 'desk'), role('viewer')]
const labels = { presales: 'Pre-sales', sales: 'Sales' }

describe('toggleRole', () => {
  it('treats an exclusive group like a radio group', () => {
    expect(toggleRole(['presales', 'viewer'], 'sales', roles)).toEqual(['sales', 'viewer'])
  })

  it('adds and removes ordinary roles', () => {
    expect(toggleRole(['sales'], 'viewer', roles)).toEqual(['sales', 'viewer'])
    expect(toggleRole(['sales', 'viewer'], 'viewer', roles)).toEqual(['sales'])
  })
})

describe('deskWarning', () => {
  const options = ['presales', 'sales']

  it('is silent when desk and role agree, or neither is set', () => {
    expect(deskWarning(['presales', 'viewer'], 'presales', options, labels)).toBeNull()
    expect(deskWarning(['viewer'], undefined, options, labels)).toBeNull()
  })

  it('warns when they disagree', () => {
    expect(deskWarning(['sales'], 'presales', options, labels)).toBe(
      'Desk is Pre-sales but the user has the Sales role.')
    expect(deskWarning(['viewer'], 'sales', options, labels)).toBe('Desk is Sales but the user has no Sales role.')
    expect(deskWarning(['sales'], undefined, options, labels)).toContain('has the Sales role but no desk')
  })
})
