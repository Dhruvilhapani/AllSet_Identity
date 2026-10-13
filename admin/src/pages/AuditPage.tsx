import { useInfiniteQuery } from '@tanstack/react-query'
import { useState } from 'react'

import { Button, ErrorBox, Loading, PageHeader, SelectInput, Table, TextInput } from '../components/ui'
import { api } from '../lib/api'
import type { AuditEntry } from '../lib/types'
import { when } from './ServicesPage'

const PAGE = 50

export function AuditPage() {
  const [targetType, setTargetType] = useState('')
  const [targetKey, setTargetKey] = useState('')
  const [actor, setActor] = useState('')

  const filters = { target_type: targetType, target_key: targetKey.trim(), actor_email: actor.trim() }
  const entries = useInfiniteQuery({
    queryKey: ['audit', filters],
    initialPageParam: 0,
    queryFn: ({ pageParam }) => {
      const params = new URLSearchParams(Object.entries(filters).filter(([, v]) => v))
      params.set('limit', String(PAGE))
      if (pageParam) params.set('before_id', String(pageParam))
      return api.get<{ entries: AuditEntry[] }>(`/admin/audit?${params}`).then((r) => r.entries)
    },
    getNextPageParam: (last) => (last.length === PAGE ? last[last.length - 1].id : undefined),
  })
  const rows = entries.data?.pages.flat() ?? []

  return (
    <>
      <PageHeader title="Audit log" description="Every change to users' roles and attributes, roles, permissions, services and keys, newest first." />
      <div className="mb-4 grid grid-cols-1 gap-3 md:grid-cols-3">
        <SelectInput label="Changed" placeholder="Anything" value={targetType} onChange={(e) => setTargetType(e.target.value)}
          options={[{ value: 'user', label: 'Users' }, { value: 'role', label: 'Roles' }, { value: 'service', label: 'Services' }]} />
        <TextInput label="Target" placeholder="User id, role or service key" value={targetKey}
          onChange={(e) => setTargetKey(e.target.value)} />
        <TextInput label="By" placeholder="Admin email" value={actor} onChange={(e) => setActor(e.target.value)} />
      </div>
      <ErrorBox error={entries.error} />
      {entries.isLoading ? <Loading what="Loading audit log" /> : (
        <Table head={['When', 'By', 'What', 'Target', 'Change']}>
          {rows.map((entry) => (
            <tr key={entry.id} className="align-top">
              <td className="whitespace-nowrap px-4 py-2.5 text-gray-600">{when(entry.at)}</td>
              <td className="px-4 py-2.5 text-gray-700">{entry.actor_email || 'a deploy or migration'}</td>
              <td className="px-4 py-2.5 font-mono text-xs">{entry.action}</td>
              <td className="px-4 py-2.5 text-xs text-gray-700">{entry.target_type} <code>{entry.target_key}</code></td>
              <td className="px-4 py-2.5">
                <details>
                  <summary className="cursor-pointer text-xs text-brand-700">Before / after</summary>
                  <div className="mt-2 grid grid-cols-1 gap-2 lg:grid-cols-2">
                    <pre className="max-h-64 overflow-auto rounded bg-gray-50 p-2 text-xs">{JSON.stringify(entry.before, null, 2)}</pre>
                    <pre className="max-h-64 overflow-auto rounded bg-gray-50 p-2 text-xs">{JSON.stringify(entry.after, null, 2)}</pre>
                  </div>
                </details>
              </td>
            </tr>
          ))}
          {!rows.length && <tr><td colSpan={5} className="px-4 py-8 text-center text-gray-500">Nothing recorded yet.</td></tr>}
        </Table>
      )}
      {entries.hasNextPage && (
        <div className="mt-4 flex justify-center">
          <Button variant="secondary" loading={entries.isFetchingNextPage} onClick={() => void entries.fetchNextPage()}>
            Load older entries
          </Button>
        </div>
      )}
    </>
  )
}
