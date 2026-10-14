import { describe, expect, it } from 'vitest'

import { apiBase, errorMessage } from './api'

describe('apiBase', () => {
  it('follows the path the console was served from', () => {
    expect(apiBase('/admin/')).toBe('/v1')
    expect(apiBase('/identity/admin/')).toBe('/identity/v1')
  })
})

describe('errorMessage', () => {
  it('shows the API detail', () => {
    expect(errorMessage(400, { detail: 'unknown role: nope' })).toBe('unknown role: nope')
  })

  it('flattens validation errors', () => {
    const body = { detail: [{ loc: ['body', 'key'], msg: 'String should match pattern' }] }
    expect(errorMessage(422, body)).toBe('key: String should match pattern')
  })

  it('explains an outage', () => {
    expect(errorMessage(503, null)).toContain('unavailable')
  })
})
