-- ═══════════════════════════════════════════════════════════════════
-- uni-co — Supabase Schema
-- Run this entire file in Supabase → SQL Editor → New Query
-- ═══════════════════════════════════════════════════════════════════

-- Enable UUID extension (usually already enabled on Supabase)
create extension if not exists "uuid-ossp";


-- ── Departments ───────────────────────────────────────────────────────
create table if not exists departments (
  id          text primary key,
  name        text not null,
  code        text not null unique,
  color_hex   text,
  feature_key text,
  custom      boolean default false,
  created_at  timestamptz default now()
);

-- ── Users ─────────────────────────────────────────────────────────────
-- Note: passwords are stored as PBKDF2 hashes (client-side hashed).
-- This is NOT Supabase Auth — it is the app's own auth system.
create table if not exists users (
  id            text primary key,
  full_name     text not null,
  email         text unique,
  phone         text unique,
  pw            text,                  -- PBKDF2 hash (never plaintext)
  department_id text references departments(id),
  role          text default 'STUDENT',
  bio           text default '',
  gh            text default '',
  li            text default '',
  is_ghost      boolean default false,
  created_at    timestamptz default now()
);

-- ── Projects ──────────────────────────────────────────────────────────
create table if not exists projects (
  id              text primary key,
  title           text not null,
  description     text default '',
  department_id   text references departments(id),
  is_open_collab  boolean default false,
  due_date        timestamptz,
  status          text default 'ACTIVE',  -- ACTIVE | ARCHIVED
  creator_id      text references users(id),
  created_at      timestamptz default now()
);

-- ── Members ───────────────────────────────────────────────────────────
create table if not exists members (
  id          text primary key,
  project_id  text references projects(id) on delete cascade,
  user_id     text references users(id) on delete cascade,
  role        text default 'CONTRIBUTOR',  -- LEAD | CONTRIBUTOR
  joined_at   timestamptz default now(),
  unique(project_id, user_id)
);

-- ── Tasks ─────────────────────────────────────────────────────────────
create table if not exists tasks (
  id          text primary key,
  project_id  text references projects(id) on delete cascade,
  title       text not null,
  description text default '',
  status      text default 'TODO',     -- TODO | IN_PROGRESS | DONE
  priority    text default 'MEDIUM',   -- LOW | MEDIUM | HIGH
  due_date    timestamptz,
  created_at  timestamptz default now()
);

-- ── Files ─────────────────────────────────────────────────────────────
-- Files stored as base64 data URLs in the DB.
-- For large-scale use, replace data_url with a Supabase Storage path.
create table if not exists files (
  id              text primary key,
  project_id      text references projects(id) on delete cascade,
  uploaded_by_id  text references users(id),
  filename        text not null,
  file_type       text,
  size_bytes      bigint,
  data_url        text,           -- base64 data URL
  version         integer default 1,
  tags            text[] default '{}',
  created_at      timestamptz default now()
);

-- ── Messages ──────────────────────────────────────────────────────────
create table if not exists messages (
  id          text primary key,
  project_id  text references projects(id) on delete cascade,
  sender_id   text references users(id),
  content     text not null,
  sent_at     timestamptz default now()
);

-- ── Invite Keys ───────────────────────────────────────────────────────
create table if not exists invite_keys (
  id          text primary key,
  project_id  text references projects(id) on delete cascade,
  key_code    text not null unique,
  key_type    text default 'MULTI_USE',  -- MULTI_USE | SINGLE_USE
  is_active   boolean default true,
  used_count  integer default 0,
  expires_at  timestamptz,
  created_at  timestamptz default now()
);

-- ── Notifications ─────────────────────────────────────────────────────
create table if not exists notifications (
  id          text primary key,
  user_id     text references users(id) on delete cascade,
  text        text not null,
  type        text default 'system',
  read        boolean default false,
  created_at  timestamptz default now()
);

-- ── Quizzes ───────────────────────────────────────────────────────────
create table if not exists quizzes (
  id          text primary key,
  project_id  text references projects(id) on delete cascade,
  title       text not null,
  description text default '',
  questions   jsonb default '[]',
  created_by  text references users(id),
  created_at  timestamptz default now()
);

-- ── Quiz Attempts ─────────────────────────────────────────────────────
create table if not exists quiz_attempts (
  id           text primary key,
  quiz_id      text references quizzes(id) on delete cascade,
  user_id      text references users(id) on delete cascade,
  answers      jsonb default '[]',
  score        integer default 0,
  total        integer default 0,
  attempted_at timestamptz default now()
);

-- ── Permissions ───────────────────────────────────────────────────────
create table if not exists permissions (
  id          text primary key,
  project_id  text references projects(id) on delete cascade,
  user_id     text references users(id) on delete cascade,
  can_invite  boolean default false,
  can_edit    boolean default true,
  can_delete  boolean default false,
  unique(project_id, user_id)
);

-- ── Vault Versions ────────────────────────────────────────────────────
create table if not exists vault_versions (
  id         text primary key,
  file_id    text references files(id) on delete cascade,
  version    integer not null,
  data_url   text,
  created_at timestamptz default now()
);


-- ═══════════════════════════════════════════════════════════════════
-- Row Level Security (RLS)
-- ─────────────────────────────────────────────────────────────────
-- uni-co uses its own app-level auth (PBKDF2 password hashing).
-- Because the anon key is used for all requests from the browser,
-- we set RLS to allow all operations via the anon role.
--
-- ⚠ IMPORTANT FOR PRODUCTION:
-- Before launch, replace these open policies with proper RLS rules
-- using Supabase's server-side auth (supabase.auth) or JWTs.
-- The simple policies below are intentional for the migration step.
-- ═══════════════════════════════════════════════════════════════════

do $$
declare
  t text;
  tables text[] := array[
    'departments','users','projects','members','tasks','files',
    'messages','invite_keys','notifications','quizzes',
    'quiz_attempts','permissions','vault_versions'
  ];
begin
  foreach t in array tables loop
    execute format('alter table %I enable row level security', t);
    -- Drop existing open policy if it exists, then recreate
    execute format('drop policy if exists "anon_all" on %I', t);
    execute format(
      'create policy "anon_all" on %I for all to anon using (true) with check (true)',
      t
    );
  end loop;
end $$;


-- ═══════════════════════════════════════════════════════════════════
-- Indexes for common query patterns
-- ═══════════════════════════════════════════════════════════════════
create index if not exists idx_members_user_id    on members(user_id);
create index if not exists idx_members_project_id on members(project_id);
create index if not exists idx_tasks_project_id   on tasks(project_id);
create index if not exists idx_messages_project_id on messages(project_id);
create index if not exists idx_notifs_user_id     on notifications(user_id);
create index if not exists idx_perms_project_id   on permissions(project_id);
create index if not exists idx_files_project_id   on files(project_id);
create index if not exists idx_invite_keys_code   on invite_keys(key_code);
