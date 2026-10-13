# pgsesame for a Supabase app

A blog's permissions as one reviewable file: who can read, write and edit what,
through Supabase's Data API and outside it. [`schema.sql`](schema.sql) has the
tables; [`permissions.yaml`](permissions.yaml) has everything else.

| Who | Connects as | Can |
|---|---|---|
| A visitor | `anon` | read profiles and published posts |
| A signed-in user | `authenticated` | also read their own drafts; create their profile and posts; edit and delete only their own, and never change a post's author |
| The server | `service_role` | everything, past row-level security |
| A dashboard | `metabase` (in `reporting`) | read everything, over its own login |

## Why it's written this way

- **Its own schema, `app`.** Supabase grants `anon` and `authenticated` a lot in
  `public`. pgsesame manages a built-in role (`type: builtin`) only in the schemas
  the spec names for it, so Supabase's grants in `public` are left alone, and in
  `app` nothing is granted that the spec doesn't say.
- **Grants and policies together.** Row-level security decides which rows; a
  grant decides whether the table is reachable at all. `authenticated` gets
  `UPDATE` only on the columns a user may edit, so `author`, `id` and
  `created_at` can't change, whatever the policies say.
- **`(select auth.uid())`**, not `auth.uid()`: PostgreSQL evaluates it once per
  query instead of once per row, as Supabase recommends.
- **`service_role` still needs grants.** It bypasses row-level security, not
  privileges.
- **Default privileges** give `service_role` and `reporting` the tables created
  later in `app` (from the SQL editor or a migration, as `postgres`). The app's
  users get no default: a new table is unreachable until the spec grants it and
  gives it policies.
- **The dashboard's password** comes from `METABASE_PASSWORD` when pgsesame
  creates the user, never from the file.

## Run it

1. Create the tables: paste `schema.sql` into the SQL editor, or add it to your
   migrations.
2. Expose the `app` schema to the Data API in the project's API settings
   (Exposed schemas), so `supabase.from('posts')` with `db: { schema: 'app' }`
   reaches it.
3. Connect as `postgres`, over the direct connection (`db.<project>.supabase.co`,
   port 5432) or the session pooler, and plan:

   ```bash
   sesame login supabase --host db.<project>.supabase.co --user postgres --database postgres
   export METABASE_PASSWORD=...
   sesame plan permissions.yaml -t supabase
   sesame apply permissions.yaml -t supabase
   sesame plan permissions.yaml -t supabase  # nothing to do
   ```

From then on a change to who can do what is a change to `permissions.yaml`,
reviewed in a pull request, and a policy someone edits in the dashboard shows up
as drift in the next plan.
