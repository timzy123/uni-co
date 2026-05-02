-# uni-co — Deployment Guide
## From static prototype → live, shared, cloud-backed app

This guide takes you from zero to a publicly accessible uni-co instance
where every user on every device sees the same live data.

---

## What changed from the original

| Old (IndexedDB)                          | New (Supabase)                              |
|------------------------------------------|---------------------------------------------|
| Data lives only in your browser          | Data lives in a shared Postgres database    |
| Two devices = two separate apps          | Any device sees the same projects & teams   |
| Works offline only                       | Works anywhere with a network connection    |
| No real backend                          | Supabase handles storage, RLS, and hosting  |
| Opened as a local HTML file              | Deployed on Vercel with a real URL          |

Everything else — the UI, security layer, password hashing, themes,
quizzes, dependency graph, workstations — is unchanged.

---

## Part 1 — Create your Supabase database

### Step 1 · Sign up for Supabase

1. Go to **https://supabase.com** and click **Start your project** (free).
2. Sign in with GitHub (recommended) or email.
3. Click **New project**.
4. Fill in:
   - **Project name** — e.g. `uni-co`
   - **Database password** — generate a strong one, save it somewhere safe
   - **Region** — pick the one closest to your users
5. Click **Create new project** and wait ~1 minute for it to provision.

### Step 2 · Run the schema SQL

1. In your new Supabase project, click **SQL Editor** in the left sidebar.
2. Click **New query**.
3. Open the file `schema.sql` from this folder, copy its entire contents,
   and paste it into the SQL editor.
4. Click **Run** (or press `Cmd/Ctrl + Enter`).
5. You should see: `Success. No rows returned.`

This creates all 14 tables, enables Row Level Security with open anon
policies, and sets up indexes.

### Step 3 · Get your API credentials

1. In Supabase, go to **Settings → API** (left sidebar, bottom section).
2. Copy two values:
   - **Project URL** — looks like `https://abcdefgh.supabase.co`
   - **anon / public** key — a long JWT string starting with `eyJ`

Keep the **service_role** key secret — you will not need it here.

---

## Part 2 — Configure the app

### Step 4 · Set your credentials

Open **`config.js`** in the project folder and replace the placeholders:

```js
window.SUPABASE_URL      = 'https://YOUR_PROJECT.supabase.co';   // ← paste here
window.SUPABASE_ANON_KEY = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...'; // ← paste here
```

> **config.js is in .gitignore** so it won't be committed to Git.
> For Vercel deployment, you'll inject these as Environment Variables instead (see Part 3).

### Step 5 · Test locally

Open `index.html` in Chrome or Firefox.

- You should see the uni-co boot screen briefly, then the login page.
- Create an account — the data goes to Supabase.
- Open a second browser / incognito window, create another account,
  and join one of the demo projects.
- **Both windows now see the same data.** Cross-device sharing works.

---

## Part 3 — Deploy to Vercel (public URL)

### Step 6 · Install the Vercel CLI

```bash
npm install -g vercel
```

Or use the Vercel dashboard without the CLI (Step 8 alternative).

### Step 7 · Push your code to GitHub

```bash
# In the uni-co-supabase folder:
git init
git add .
git commit -m "Initial commit"
# Create a repo on GitHub, then:
git remote add origin https://github.com/YOUR_USERNAME/uni-co.git
git push -u origin main
```

> **config.js is gitignored** — your credentials are not uploaded. ✓

### Step 8 · Connect to Vercel

**Option A — Vercel CLI:**
```bash
vercel
```
Follow the prompts. Choose your GitHub repo, keep all defaults.

**Option B — Vercel Dashboard:**
1. Go to **https://vercel.com** → **Add New → Project**.
2. Import your GitHub repo.
3. Click **Deploy** (no build command needed — it's a static site).

### Step 9 · Add Environment Variables in Vercel

Since `config.js` is not in Git, you need to inject credentials via
Vercel's environment variable system.

1. In Vercel, go to your project → **Settings → Environment Variables**.
2. Add two variables:

   | Name                | Value                                    |
   |---------------------|------------------------------------------|
   | `SUPABASE_URL`      | `https://YOUR_PROJECT.supabase.co`       |
   | `SUPABASE_ANON_KEY` | `eyJhbGciOiJI...` (your anon key)        |

3. Select **All Environments** (Production, Preview, Development).
4. Click **Save**.

### Step 10 · Create a build-time config injector

Vercel serves static files, so to use environment variables you need a
tiny build step that writes `config.js` from the env vars.

Create a file called **`build.sh`** in your project root:

```bash
#!/bin/sh
# build.sh — Vercel runs this before serving
cat > config.js << EOF
window.SUPABASE_URL      = '${SUPABASE_URL}';
window.SUPABASE_ANON_KEY = '${SUPABASE_ANON_KEY}';
EOF
echo "config.js written from env vars."
```

Then update **`vercel.json`** to run it:

```json
{
  "buildCommand": "sh build.sh",
  "outputDirectory": ".",
  "headers": [...]
}
```

> The `headers` array is already in vercel.json — just add the two new
> top-level keys (`buildCommand` and `outputDirectory`) alongside it.

### Step 11 · Redeploy

```bash
vercel --prod
```

Or push a new commit to GitHub — Vercel deploys automatically on push.

You'll get a URL like `https://uni-co-xyz.vercel.app`. Share it with
your users. All signups and data are now shared in real time.

---

## Part 4 — Custom domain (optional)

1. In Vercel → your project → **Settings → Domains**.
2. Enter your domain (e.g. `unicollaborate.edu`).
3. Follow the DNS instructions Vercel provides.
4. SSL is automatic and free.

---

## Part 5 — Supabase free-tier notes

The **Supabase free tier** is generous for a student project:

| Limit           | Free tier         |
|-----------------|-------------------|
| Database size   | 500 MB            |
| File storage    | 1 GB              |
| Monthly active users | Unlimited    |
| API requests    | Unlimited         |
| Auto-pause      | After 7 days of inactivity |

**Auto-pause:** If your project is idle for 7 days, Supabase pauses the
database. The first request after a pause takes a few seconds to wake it
up — users see a brief delay, not an error, because the app retries.
To disable auto-pause, upgrade to the $25/mo Pro plan.

---

## Part 6 — Security hardening (before going public)

The `schema.sql` uses open RLS policies (`for all to anon using (true)`)
to keep the initial migration simple. Before going live with real users:

### Tighten RLS policies

Replace the open policies with scoped ones. Example for `projects`:

```sql
-- Users can only read projects they're members of
drop policy "anon_all" on projects;

create policy "members_read" on projects
  for select using (
    id in (
      select project_id from members where user_id = current_setting('app.user_id', true)
    )
  );
```

To pass the user ID from the app, set it in each request:
```js
await sb().rpc('set_config', { key: 'app.user_id', value: currentUserId });
```

### Migrate to Supabase Auth (advanced)

For maximum security, replace the app's own PBKDF2 system with
[Supabase Auth](https://supabase.com/docs/guides/auth). This gives you:
- Email verification
- OAuth (Google, GitHub)
- JWT-based RLS (most secure)
- Password reset flows

This requires changes to the `login`/`signup` functions in `app.js`.

### Rate limiting

Add Supabase Edge Functions or a Vercel middleware to rate-limit
signup/login endpoints. The client-side rate limiter in `Security.rateLimit()`
is a UX convenience, not a real security boundary.

---

## Troubleshooting

| Problem | Fix |
|---------|-----|
| "Supabase credentials not configured" | Fill in `config.js` with your real URL and anon key |
| "Cannot reach Supabase" | Check your URL is correct; check your project isn't paused |
| Tables don't exist | Re-run `schema.sql` in Supabase SQL Editor |
| RLS blocks all reads | Make sure the anon policies were created by the schema |
| Vercel shows old config | Redeploy after adding env vars |
| Files are slow to upload | Files are stored as base64 in the DB (fine for demos, switch to Supabase Storage for production) |

---

## File structure

```
uni-co-supabase/
├── index.html          ← App shell (loads Supabase CDN + config.js)
├── app.js              ← All app code with Supabase StorageEngine
├── styles.css          ← Unchanged from original
├── config.js           ← YOUR CREDENTIALS (gitignored)
├── config.example.js   ← Safe template to commit
├── schema.sql          ← Run once in Supabase SQL Editor
├── vercel.json         ← Deployment & security headers config
├── build.sh            ← Injects env vars into config.js on Vercel
├── .gitignore          ← Excludes config.js
└── SETUP.md            ← This file
```
