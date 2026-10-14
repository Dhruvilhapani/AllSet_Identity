import { useQueries, useQuery } from '@tanstack/react-query'

import { api } from './api'
import type { AdminUser, RolesResponse, ServiceDetail, ServiceSummary } from './types'

export const keys = {
  users: (filters: Record<string, string>) => ['users', filters] as const,
  user: (id: string) => ['user', id] as const,
  roles: ['roles'] as const,
  services: ['services'] as const,
  service: (key: string) => ['service', key] as const,
  grants: (key: string) => ['grants', key] as const,
}

export function useRoles() {
  return useQuery({ queryKey: keys.roles, queryFn: () => api.get<RolesResponse>('/admin/roles') })
}

export function useServices() {
  return useQuery({
    queryKey: keys.services,
    queryFn: () => api.get<{ services: ServiceSummary[] }>('/admin/services').then((r) => r.services),
  })
}

export function useService(key: string | undefined) {
  return useQuery({
    queryKey: keys.service(key ?? ''),
    queryFn: () => api.get<ServiceDetail>(`/admin/services/${encodeURIComponent(key ?? '')}`),
    enabled: Boolean(key),
  })
}

/** Every service's catalogue: labels for permissions, and which attributes exist. */
export function useServiceDetails(services: ServiceSummary[] | undefined) {
  return useQueries({
    queries: (services ?? []).map((s) => ({
      queryKey: keys.service(s.key),
      queryFn: () => api.get<ServiceDetail>(`/admin/services/${encodeURIComponent(s.key)}`),
    })),
  })
}

export function useUsers(filters: Record<string, string>) {
  const query = new URLSearchParams(Object.entries(filters).filter(([, v]) => v)).toString()
  return useQuery({
    queryKey: keys.users(filters),
    queryFn: () => api.get<{ users: AdminUser[] }>(`/admin/users${query ? `?${query}` : ''}`).then((r) => r.users),
  })
}
