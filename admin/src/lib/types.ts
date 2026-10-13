// Shapes returned by AllSet Identity (app/api/v1/admin.py, app/permissions/payload.py).

/** resource -> action -> granted scopes. An absent action is denied. */
export type Permissions = Record<string, Record<string, string[]>>

export interface AppBlock {
  access: boolean
  primary_role: string | null
  permissions: Permissions
  attributes: Record<string, string>
}

export interface IdentityUser {
  active: boolean
  user_id: string
  email: string
  full_name: string
  phone: string
  roles: string[]
  role_labels: string[]
  is_active: boolean
  apps: Record<string, AppBlock>
}

export interface Session {
  access_token: string
  refresh_token: string | null
  expires_in: number
  user: IdentityUser
}

export interface AdminUser {
  user_id: string
  email: string
  full_name: string
  phone: string
  roles: string[]
  role_labels: string[]
  /** service -> attribute -> value */
  attributes: Record<string, Record<string, string>>
  is_active: boolean
  legacy_migrated_at: string | null
  created_at: string | null
  apps: Record<string, AppBlock>
}

export interface Role {
  key: string
  label: string
  description: string
  priority: number
  is_superuser: boolean
  exclusive_group: string | null
  members: number
  apps: string[]
}

export interface RolesResponse {
  roles: Role[]
  exclusive_groups: string[][]
}

export interface ServiceSummary {
  key: string
  name: string
  description: string
  is_system: boolean
  is_active: boolean
  grants_version: number
  manifest_pushed_at: string | null
  resources: number
  retired_resources: number
}

export interface CatalogueAction {
  key: string
  label: string
  retired: boolean
}

export interface CatalogueScope {
  key: string
  label: string
  is_all: boolean
  retired: boolean
}

export interface CatalogueResource {
  key: string
  label: string
  description: string
  retired: boolean
  actions: CatalogueAction[]
  scopes: CatalogueScope[]
}

export interface CatalogueAttribute {
  key: string
  label: string
  kind: string
  options: string[]
  retired: boolean
}

export interface ServiceKey {
  id: string
  key_prefix: string
  label: string
  created_at: string
  created_by: string | null
  revoked_at: string | null
}

export interface ServiceDetail {
  key: string
  name: string
  description: string
  is_system: boolean
  is_active: boolean
  grants_version: number
  manifest_pushed_at: string | null
  resources: CatalogueResource[]
  attributes: CatalogueAttribute[]
  keys?: ServiceKey[]
}

/** role -> resource -> action -> scopes */
export type Grants = Record<string, Record<string, Record<string, string[]>>>

export interface GrantsResponse {
  service: string
  version: number
  editable: boolean
  grants: Grants
  roles: { key: string; label: string; is_superuser: boolean }[]
}

export interface AuditEntry {
  id: number
  at: string
  actor_user_id: string | null
  actor_email: string
  action: string
  target_type: string
  target_key: string
  before: unknown
  after: unknown
}

export interface CreatedKey {
  id: string
  service: string
  key: string
  prefix: string
  label: string
}
