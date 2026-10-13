# AllSet Identity admin console

The single-page app admins use to manage users, roles, permissions, services
and service keys for every AllSet service. Identity serves the built bundle at
`/admin/`, and at `/identity/admin/` on the shared Firebase site. The design
behind it is in [`../docs/ARCHITECTURE_ADMIN.md`](../docs/ARCHITECTURE_ADMIN.md).

Only people whose roles grant `identity.console.use` (admin and tech in the
seed) get past the sign-in screen; the API enforces the same rule on every call.

## Stack

React 18, TypeScript, Vite, Tailwind, TanStack Query, react-router (hash
routes), the same stack as the CMS admin panel. No external fonts, scripts or
images: Identity serves the console with a Content-Security-Policy that allows
only its own origin.

Tokens live under the same `localStorage` keys as the CMS admin panel and Broker
Tools (`allset_access_token`, `allset_refresh_token`), so on the shared Firebase
site signing in to one signs you in to the others.

## Develop

```bash
npm ci
npm run dev        # http://localhost:5174, proxies /v1 to Identity on :8100
npm test           # unit tests for the matrix, role rules and API helpers
npm run build      # type-check and build into dist/, which Identity serves
```

Identity itself must be running on port 8100 (`uvicorn app.main:app --port 8100`
from the repo root). Without Supabase credentials, use the local stack in
[`../scripts/local_stack/`](../scripts/local_stack/README.md): Postgres with the
real migrations behind PostgREST, and a stubbed sign-in.

Set `IDENTITY_URL` to point the dev proxy elsewhere.

## Layout

| Path | What |
| --- | --- |
| `src/lib/api.ts` | The only code that calls Identity: base path, refresh on 401, error text |
| `src/lib/matrix.ts` | Permission-matrix editing: toggling scopes, which roles to show, the PUT body, the change list |
| `src/lib/roles.ts` | Exclusive-group role picking, and the desk/role mismatch warning |
| `src/pages/` | Users, user detail, roles, permissions, services, audit |
| `src/components/ui.tsx` | Buttons, fields, dialogs, tables, styled like the CMS admin panel |

## Behaviour worth knowing

- **The matrix is saved whole**, per service, with `If-Match` set to the
  version it was loaded at. If someone else saved first, the save is refused
  (409) and the admin can reload; nothing is silently overwritten. A background
  refetch never replaces a matrix that has unsaved edits.
- **The matrix shows only the roles in use** in that service: superusers and
  roles granted something there. Roles are shared by every service, so the
  rest (Editor and Viewer in Broker Tools, say) would be empty columns. Tick
  **Show all roles** to grant one of them something.
- **New users get the password you type.** Nothing is emailed; hand it over
  privately. **Change password** on a user's page sets a new one without the
  old one.
- **Role changes sign the person out everywhere.** The new access reaches every
  service within about a minute.
- **A new service key is shown once.** Only its SHA-256 hash is stored.
