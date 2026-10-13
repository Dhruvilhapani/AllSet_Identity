import { Navigate, Route, Routes } from 'react-router-dom'

import { canUseConsole, useAuth } from './auth/AuthProvider'
import { Layout } from './components/Layout'
import { Loading } from './components/ui'
import { AuditPage } from './pages/AuditPage'
import { PermissionsPage } from './pages/PermissionsPage'
import { RolesPage } from './pages/RolesPage'
import { ServiceDetailPage, ServicesPage } from './pages/ServicesPage'
import { NoAccessPage, SignInPage } from './pages/SignInPage'
import { UserDetailPage } from './pages/UserDetailPage'
import { UsersPage } from './pages/UsersPage'

export default function App() {
  const { user, checking } = useAuth()

  if (checking) return <div className="px-8"><Loading what="Checking your session" /></div>
  if (!user) return <SignInPage />
  if (!canUseConsole(user)) return <NoAccessPage />

  return (
    <Routes>
      <Route element={<Layout />}>
        <Route path="/users" element={<UsersPage />} />
        <Route path="/users/:id" element={<UserDetailPage />} />
        <Route path="/roles" element={<RolesPage />} />
        <Route path="/permissions" element={<PermissionsPage />} />
        <Route path="/permissions/:service" element={<PermissionsPage />} />
        <Route path="/services" element={<ServicesPage />} />
        <Route path="/services/:key" element={<ServiceDetailPage />} />
        <Route path="/audit" element={<AuditPage />} />
        <Route path="*" element={<Navigate to="/users" replace />} />
      </Route>
    </Routes>
  )
}
