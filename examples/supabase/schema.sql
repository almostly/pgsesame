-- The app's tables, in their own schema: Supabase grants anon and authenticated
-- a lot in public, and pgsesame manages a built-in role only in the schemas the
-- spec names for it.
CREATE SCHEMA IF NOT EXISTS app;

CREATE TABLE IF NOT EXISTS app.profiles (
    id uuid PRIMARY KEY REFERENCES auth.users ON DELETE CASCADE,
    username text UNIQUE NOT NULL,
    bio text
);

CREATE TABLE IF NOT EXISTS app.posts (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    author uuid NOT NULL DEFAULT auth.uid() REFERENCES app.profiles,
    title text NOT NULL,
    body text,
    published boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT now()
);
