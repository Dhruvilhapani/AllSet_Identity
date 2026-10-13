// Building blocks, styled like AllSet_CMS admin_ui so the two feel like one product.

import clsx from 'clsx'
import { useEffect, useId, type ButtonHTMLAttributes, type InputHTMLAttributes, type ReactNode,
  type SelectHTMLAttributes } from 'react'

type ButtonVariant = 'primary' | 'secondary' | 'danger' | 'ghost'

export function Button({ variant = 'primary', loading = false, className, children, disabled, ...props }:
  ButtonHTMLAttributes<HTMLButtonElement> & { variant?: ButtonVariant; loading?: boolean }) {
  const variants: Record<ButtonVariant, string> = {
    primary: 'bg-brand-600 text-white hover:bg-brand-700 disabled:bg-brand-500/60',
    secondary: 'bg-white text-gray-700 border border-gray-300 hover:bg-gray-50 disabled:text-gray-400',
    danger: 'bg-red-600 text-white hover:bg-red-700 disabled:bg-red-400',
    ghost: 'text-gray-600 hover:bg-gray-100 disabled:text-gray-300',
  }
  return (
    <button
      type="button"
      className={clsx('inline-flex items-center justify-center gap-2 rounded-lg px-3.5 py-2 text-sm font-medium',
        'focus:outline-none focus-visible:ring-2 focus-visible:ring-brand-500 focus-visible:ring-offset-1',
        'disabled:cursor-not-allowed', variants[variant], className)}
      disabled={disabled || loading}
      {...props}
    >
      {loading && <Spinner size="sm" />}
      {children}
    </button>
  )
}

export function Field({ label, help, error, children, htmlFor }:
  { label: string; help?: ReactNode; error?: string | null; children: ReactNode; htmlFor?: string }) {
  return (
    <div className="flex flex-col gap-1">
      <label htmlFor={htmlFor} className="text-xs font-semibold uppercase tracking-wide text-gray-600">{label}</label>
      {children}
      {error ? <p className="text-xs text-red-600">{error}</p> : help && <p className="text-xs text-gray-500">{help}</p>}
    </div>
  )
}

const control = 'w-full rounded-lg border border-gray-300 bg-white px-3 py-2 text-sm text-gray-900 ' +
  'focus:border-brand-500 focus:outline-none focus:ring-2 focus:ring-brand-500/20 disabled:bg-gray-50 disabled:text-gray-500'

export function TextInput({ label, help, error, className, ...props }:
  InputHTMLAttributes<HTMLInputElement> & { label: string; help?: ReactNode; error?: string | null }) {
  const id = useId()
  return (
    <Field label={label} help={help} error={error} htmlFor={id}>
      <input id={id} className={clsx(control, className)} {...props} />
    </Field>
  )
}

export function SelectInput({ label, help, options, placeholder, className, ...props }:
  SelectHTMLAttributes<HTMLSelectElement> & {
    label: string; help?: ReactNode; options: { value: string; label: string }[]; placeholder?: string
  }) {
  const id = useId()
  return (
    <Field label={label} help={help} htmlFor={id}>
      <select id={id} className={clsx(control, className)} {...props}>
        {placeholder !== undefined && <option value="">{placeholder}</option>}
        {options.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
      </select>
    </Field>
  )
}

type BadgeVariant = 'gray' | 'blue' | 'green' | 'red' | 'amber' | 'purple'

export function Badge({ children, variant = 'gray', title }: { children: ReactNode; variant?: BadgeVariant; title?: string }) {
  const variants: Record<BadgeVariant, string> = {
    gray: 'bg-gray-100 text-gray-700',
    blue: 'bg-blue-100 text-blue-800',
    green: 'bg-green-100 text-green-800',
    red: 'bg-red-100 text-red-800',
    amber: 'bg-amber-100 text-amber-800',
    purple: 'bg-purple-100 text-purple-800',
  }
  return (
    <span title={title} className={clsx('inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium',
      variants[variant])}>
      {children}
    </span>
  )
}

export function Spinner({ size = 'md' }: { size?: 'sm' | 'md' }) {
  return (
    <svg className={clsx('animate-spin', size === 'sm' ? 'h-4 w-4' : 'h-6 w-6 text-brand-600')}
      fill="none" viewBox="0 0 24 24" aria-hidden="true">
      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
    </svg>
  )
}

export function Loading({ what = 'Loading' }: { what?: string }) {
  return (
    <div className="flex items-center gap-3 py-10 text-sm text-gray-500" role="status">
      <Spinner /> {what}…
    </div>
  )
}

export function ErrorBox({ error }: { error: unknown }) {
  if (!error) return null
  const message = error instanceof Error ? error.message : String(error)
  return (
    <div role="alert" className="rounded-lg border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-800">
      {message}
    </div>
  )
}

export function Notice({ children, tone = 'amber' }: { children: ReactNode; tone?: 'amber' | 'blue' }) {
  return (
    <div className={clsx('rounded-lg border px-4 py-3 text-sm', tone === 'amber'
      ? 'border-amber-200 bg-amber-50 text-amber-900' : 'border-blue-200 bg-blue-50 text-blue-900')}>
      {children}
    </div>
  )
}

export function Card({ title, actions, children }: { title?: ReactNode; actions?: ReactNode; children: ReactNode }) {
  return (
    <section className="rounded-xl border border-gray-200 bg-white">
      {(title || actions) && (
        <header className="flex items-center justify-between gap-3 border-b border-gray-200 px-5 py-3">
          <h2 className="text-sm font-semibold text-gray-900">{title}</h2>
          <div className="flex items-center gap-2">{actions}</div>
        </header>
      )}
      <div className="px-5 py-4">{children}</div>
    </section>
  )
}

export function PageHeader({ title, description, actions }: { title: string; description?: ReactNode; actions?: ReactNode }) {
  return (
    <div className="mb-6 flex flex-wrap items-start justify-between gap-4">
      <div>
        <h1 className="text-xl font-semibold text-gray-900">{title}</h1>
        {description && <p className="mt-1 max-w-3xl text-sm text-gray-500">{description}</p>}
      </div>
      <div className="flex items-center gap-2">{actions}</div>
    </div>
  )
}

export function Modal({ open, title, onClose, children, footer, size = 'md' }: {
  open: boolean; title: string; onClose: () => void; children: ReactNode; footer?: ReactNode; size?: 'md' | 'lg'
}) {
  useEffect(() => {
    if (!open) return
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose() }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [open, onClose])

  if (!open) return null
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4" role="dialog" aria-modal="true" aria-label={title}>
      <div className="absolute inset-0 bg-black/40" onClick={onClose} />
      <div className={clsx('relative flex max-h-[calc(100vh-2rem)] w-full flex-col rounded-xl bg-white shadow-xl',
        size === 'lg' ? 'max-w-3xl' : 'max-w-lg')}>
        <div className="flex items-center justify-between border-b border-gray-200 px-5 py-4">
          <h2 className="text-base font-semibold text-gray-900">{title}</h2>
          <button type="button" onClick={onClose} aria-label="Close"
            className="rounded p-1 text-gray-500 hover:bg-gray-100">✕</button>
        </div>
        <div className="overflow-y-auto px-5 py-4">{children}</div>
        {footer && <div className="flex justify-end gap-2 border-t border-gray-200 px-5 py-3">{footer}</div>}
      </div>
    </div>
  )
}

export function ConfirmDialog({ open, title, message, confirmLabel, danger, busy, error, onConfirm, onClose }: {
  open: boolean; title: string; message: ReactNode; confirmLabel: string; danger?: boolean; busy?: boolean
  error?: unknown; onConfirm: () => void; onClose: () => void
}) {
  return (
    <Modal open={open} title={title} onClose={onClose} footer={<>
      <Button variant="secondary" onClick={onClose}>Cancel</Button>
      <Button variant={danger ? 'danger' : 'primary'} loading={busy} onClick={onConfirm}>{confirmLabel}</Button>
    </>}>
      <div className="space-y-3 text-sm text-gray-600">
        <div>{message}</div>
        <ErrorBox error={error} />
      </div>
    </Modal>
  )
}

export function Table({ head, children }: { head: string[]; children: ReactNode }) {
  return (
    <div className="overflow-x-auto rounded-xl border border-gray-200 bg-white">
      <table className="min-w-full divide-y divide-gray-200 text-sm">
        <thead className="bg-gray-50">
          <tr>
            {head.map((h) => (
              <th key={h} scope="col" className="px-4 py-2.5 text-left text-xs font-semibold uppercase tracking-wide text-gray-500">{h}</th>
            ))}
          </tr>
        </thead>
        <tbody className="divide-y divide-gray-100">{children}</tbody>
      </table>
    </div>
  )
}
