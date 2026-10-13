import clsx from 'clsx'
import { NavLink, Outlet } from 'react-router-dom'

import { useAuth } from '../auth/AuthProvider'
import { Button } from './ui'

const NAV = [
  { to: '/users', label: 'Users' },
  { to: '/roles', label: 'Roles' },
  { to: '/permissions', label: 'Permissions' },
  { to: '/services', label: 'Services' },
  { to: '/audit', label: 'Audit log' },
]

export function Layout() {
  const { user, signOut } = useAuth()
  return (
    <div className="flex min-h-screen">
      <aside className="flex w-56 shrink-0 flex-col border-r border-gray-200 bg-white">
        <div className="border-b border-gray-200 px-5 py-4">
          <p className="text-sm font-semibold text-gray-900">AllSet Identity</p>
          <p className="text-xs text-gray-500">Admin console</p>
        </div>
        <nav className="flex flex-1 flex-col gap-1 p-3" aria-label="Main">
          {NAV.map((item) => (
            <NavLink key={item.to} to={item.to}
              className={({ isActive }) => clsx('rounded-lg px-3 py-2 text-sm font-medium',
                isActive ? 'bg-brand-50 text-brand-700' : 'text-gray-600 hover:bg-gray-100')}>
              {item.label}
            </NavLink>
          ))}
        </nav>
        <div className="border-t border-gray-200 p-3">
          <p className="truncate px-2 text-xs text-gray-500" title={user?.email}>{user?.email}</p>
          <Button variant="ghost" className="mt-1 w-full justify-start" onClick={() => void signOut()}>Sign out</Button>
        </div>
      </aside>
      <main className="min-w-0 flex-1 px-8 py-6">
        <Outlet />
      </main>
    </div>
  )
}
