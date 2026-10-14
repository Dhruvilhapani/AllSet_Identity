import { useState, type FormEvent } from 'react'

import { useAuth } from '../auth/AuthProvider'
import { Button, ErrorBox, TextInput } from '../components/ui'

export function SignInPage() {
  const { signIn } = useAuth()
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<unknown>(null)

  async function submit(e: FormEvent) {
    e.preventDefault()
    setBusy(true)
    setError(null)
    try {
      await signIn(email.trim(), password)
    } catch (err) {
      setError(err)
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center px-4">
      <form onSubmit={submit} className="w-full max-w-sm space-y-4 rounded-xl border border-gray-200 bg-white p-6 shadow-sm">
        <div>
          <h1 className="text-lg font-semibold text-gray-900">AllSet Identity</h1>
          <p className="text-sm text-gray-500">Sign in to the admin console with your AllSet account.</p>
        </div>
        <TextInput label="Email" type="email" autoComplete="username" required value={email}
          onChange={(e) => setEmail(e.target.value)} />
        <TextInput label="Password" type="password" autoComplete="current-password" required value={password}
          onChange={(e) => setPassword(e.target.value)} />
        <ErrorBox error={error} />
        <Button type="submit" className="w-full" loading={busy}>Sign in</Button>
      </form>
    </div>
  )
}

export function NoAccessPage() {
  const { user, signOut } = useAuth()
  return (
    <div className="flex min-h-screen items-center justify-center px-4">
      <div className="w-full max-w-md space-y-4 rounded-xl border border-gray-200 bg-white p-6 text-sm">
        <h1 className="text-lg font-semibold text-gray-900">No access to the admin console</h1>
        <p className="text-gray-600">
          You are signed in as <strong>{user?.email}</strong>, but your roles do not include the admin console.
          Ask an admin if you need it.
        </p>
        <Button variant="secondary" onClick={() => void signOut()}>Sign out</Button>
      </div>
    </div>
  )
}

