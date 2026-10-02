# DLP Guardian dashboard

The dashboard is a TanStack Start application. Lovable can remain connected to
this repository as an optional code editor, but the deployed app builds and
runs from the repository without Lovable services.

## Local development

```sh
bun install
bun run dev
```

Set `VITE_SUPABASE_URL` and `VITE_SUPABASE_PUBLISHABLE_KEY` for the browser
client. `SUPABASE_URL` and `SUPABASE_PUBLISHABLE_KEY` are also needed by the
server-side auth middleware. See the repository root README for Docker setup.

## Stack

- TanStack Start
- TypeScript
- React
- Tailwind CSS
- Supabase Auth and Data API
