/* ═══════════════════════════════════════════════════════════════════
   uni-co — app.js  (Supabase edition)
   Storage: Supabase (Postgres) — real-time, cross-device, multi-user
   All UI, security, and feature code is unchanged from the original.
   Only the StorageEngine has been replaced.
═══════════════════════════════════════════════════════════════════ */

/* ── Sanitization (XSS Prevention) ─────────────────────────────────── */
const esc = (s) => {
  if (s == null) return '';
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
};

/* ── Password Hashing (PBKDF2 — Web Crypto API) ─────────────────────
   100,000 iterations of PBKDF2-SHA256 with a random 16-byte salt.
─────────────────────────────────────────────────────────────────── */
async function hashPassword(password) {
  const enc = new TextEncoder();
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const keyMaterial = await crypto.subtle.importKey(
    'raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']
  );
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' },
    keyMaterial, 256
  );
  return JSON.stringify({
    salt: Array.from(salt),
    hash: Array.from(new Uint8Array(bits)),
    v: 2
  });
}

async function verifyPassword(password, stored) {
  if (!stored || stored[0] !== '{') return stored === btoa(password);
  const { salt, hash } = JSON.parse(stored);
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    'raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']
  );
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt: new Uint8Array(salt), iterations: 100000, hash: 'SHA-256' },
    keyMaterial, 256
  );
  const newHash = Array.from(new Uint8Array(bits));
  return newHash.length === hash.length && newHash.every((b, i) => b === hash[i]);
}


/* ═══════════════════════════════════════════════════════════════════
   STORAGE ENGINE — Supabase (Postgres + Storage)
   Replaces the IndexedDB engine. The public API is identical so all
   UI code above this point works without modification.

   Tables required (see SETUP.md for the SQL):
     users, departments, projects, members, tasks, files,
     messages, invite_keys, notifications, quizzes, quiz_attempts,
     permissions, vault_versions
   
   Session: stored in localStorage (just a userId string — no secrets).
   Passwords: hashed client-side with PBKDF2 before being sent to DB.
═══════════════════════════════════════════════════════════════════ */
const StorageEngine = (() => {
  // ── Supabase client ────────────────────────────────────────────────
  // Credentials come from config.js (loaded before this file in index.html)
  let _sb = null;

  const sb = () => {
    if (!_sb) throw new Error('Supabase not initialised. Call StorageEngine.init() first.');
    return _sb;
  };

  // ── Utility helpers ────────────────────────────────────────────────
  const uid  = () => ([1e7]+-1e3+-4e3+-8e3+-1e11).replace(/[018]/g, c =>
    (c ^ crypto.getRandomValues(new Uint8Array(1))[0] & 15 >> c / 4).toString(16));
  const now  = () => new Date().toISOString();
  const genKey = () => {
    const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
    return 'PROJ-' + Array.from({length:4}, () => chars[Math.floor(Math.random()*chars.length)]).join('');
  };

  // ── Low-level helpers wrapping Supabase ────────────────────────────
  // These mirror the old get/getAll/put/del signatures exactly.

  // Map camelCase store names → actual snake_case table names
  const TABLE = {
    users:         'users',
    departments:   'departments',
    projects:      'projects',
    members:       'members',
    tasks:         'tasks',
    files:         'files',
    messages:      'messages',
    inviteKeys:    'invite_keys',
    session:       null,         // handled via localStorage
    notifications: 'notifications',
    quizzes:       'quizzes',
    quizAttempts:  'quiz_attempts',
    permissions:   'permissions',
    vaultVersions: 'vault_versions',
  };

  // Map camelCase field names used in the old code → snake_case column names
  // Supabase returns snake_case; we normalize to camelCase for the UI.
  function toSnake(obj) {
    if (!obj || typeof obj !== 'object' || Array.isArray(obj)) return obj;
    const out = {};
    for (const [k, v] of Object.entries(obj)) {
      const snake = k.replace(/([A-Z])/g, '_$1').toLowerCase();
      out[snake] = v;
    }
    return out;
  }

  function toCamel(obj) {
    if (!obj || typeof obj !== 'object') return obj;
    if (Array.isArray(obj)) return obj.map(toCamel);
    const out = {};
    for (const [k, v] of Object.entries(obj)) {
      const camel = k.replace(/_([a-z])/g, (_, c) => c.toUpperCase());
      out[camel] = (v && typeof v === 'object') ? toCamel(v) : v;
    }
    return out;
  }

  async function get(store, id) {
    const table = TABLE[store];
    if (!table) return undefined;
    const keyCol = store === 'session' ? 'key' : 'id';
    const { data, error } = await sb().from(table).select('*').eq(keyCol, id).maybeSingle();
    if (error) throw error;
    return data ? toCamel(data) : undefined;
  }

  async function getAll(store, idx, val) {
    const table = TABLE[store];
    if (!table) return [];
    let q = sb().from(table).select('*');
    if (idx !== undefined && val !== undefined) {
      const col = idx.replace(/([A-Z])/g, '_$1').toLowerCase();
      q = q.eq(col, val);
    }
    const { data, error } = await q;
    if (error) throw error;
    return (data || []).map(toCamel);
  }

  async function put(store, data) {
    const table = TABLE[store];
    if (!table) return data;
    const snake = toSnake(data);
    const { data: result, error } = await sb()
      .from(table)
      .upsert(snake, { onConflict: 'id' })
      .select()
      .single();
    if (error) throw error;
    return toCamel(result);
  }

  async function del(store, id) {
    const table = TABLE[store];
    if (!table) return;
    const keyCol = 'id';
    const { error } = await sb().from(table).delete().eq(keyCol, id);
    if (error) throw error;
  }

  // ── Session (localStorage — no sensitive data, just userId) ────────
  const SESSION_KEY = 'uc_session_uid';

  function getSessionLocal() {
    try { return localStorage.getItem(SESSION_KEY); } catch { return null; }
  }
  function setSessionLocal(userId) {
    try { localStorage.setItem(SESSION_KEY, userId); } catch {}
  }
  function clearSessionLocal() {
    try { localStorage.removeItem(SESSION_KEY); } catch {}
  }

  // ── File storage — base64 stored in DB (same as before) ────────────
  // For production you can swap to Supabase Storage buckets, but storing
  // base64 in the files table keeps the migration simple and the API identical.

  // ── Seed data ──────────────────────────────────────────────────────
  const seed = async () => {
    const existing = await getAll('departments');
    if (existing.length > 0) return;

    const DEPTS = [
      { id: 'd-cs',   name: 'Computer Science',        code: 'CS',   colorHex: '#534AB7', featureKey: 'terminal_console' },
      { id: 'd-eng',  name: 'Engineering',              code: 'ENG',  colorHex: '#185FA5', featureKey: 'model_viewer' },
      { id: 'd-biz',  name: 'Business & Economics',     code: 'BIZ',  colorHex: '#0F6E56', featureKey: 'spreadsheet_viewer' },
      { id: 'd-art',  name: 'Arts & Design',            code: 'ART',  colorHex: '#BA7517', featureKey: 'visual_board' },
      { id: 'd-engl', name: 'English & Literature',     code: 'ENGL', colorHex: '#993C1D', featureKey: 'citation_engine' },
      { id: 'd-math', name: 'Mathematics',              code: 'MATH', colorHex: '#3C3489', featureKey: 'latex_editor' },
      { id: 'd-bio',  name: 'Biology & Life Sciences',  code: 'BIO',  colorHex: '#3B6D11', featureKey: 'lab_notebook' },
      { id: 'd-psy',  name: 'Psychology',               code: 'PSY',  colorHex: '#72243E', featureKey: 'survey_builder' },
      { id: 'd-law',  name: 'Law',                      code: 'LAW',  colorHex: '#854F0B', featureKey: 'case_board' },
      { id: 'd-med',  name: 'Medicine & Health',        code: 'MED',  colorHex: '#0C447C', featureKey: 'case_study_editor' },
      { id: 'd-arch', name: 'Architecture',             code: 'ARCH', colorHex: '#085041', featureKey: 'blueprint_viewer' },
      { id: 'd-pol',  name: 'Political Science',        code: 'POL',  colorHex: '#791F1F', featureKey: 'debate_board' },
    ];

    for (const d of DEPTS) await put('departments', { ...d, createdAt: now() });

    // Ghost users for demo data
    await put('users', { id: 'u-alex', fullName: 'Alex Morgan', email: null, phone: null, pw: '', departmentId: 'd-cs',  role: 'STUDENT', bio: '', gh: '', li: '', isGhost: true, createdAt: now() });
    await put('users', { id: 'u-kim',  fullName: 'Kim Lee',     email: null, phone: null, pw: '', departmentId: 'd-biz', role: 'STUDENT', bio: '', gh: '', li: '', isGhost: true, createdAt: now() });
    await put('users', { id: 'u-sara', fullName: 'Sara Nkosi',  email: null, phone: null, pw: '', departmentId: 'd-cs',  role: 'STUDENT', bio: '', gh: '', li: '', isGhost: true, createdAt: now() });

    // Demo projects
    const p1 = { id: 'p-1', title: 'Campus App Redesign', description: 'Redesigning the student portal with modern UI patterns and improved accessibility.', departmentId: 'd-cs',  isOpenCollab: true,  dueDate: '2026-06-28T00:00:00Z', status: 'ACTIVE', creatorId: 'u-alex', createdAt: now() };
    const p2 = { id: 'p-2', title: 'Startup Pitch Deck',  description: 'Cross-department pitch for the student accelerator — CS meets Business.',        departmentId: 'd-biz', isOpenCollab: true,  dueDate: '2026-07-10T00:00:00Z', status: 'ACTIVE', creatorId: 'u-kim',  createdAt: now() };
    const p3 = { id: 'p-3', title: 'ML Research Paper',   description: 'Collaborative research on federated learning for privacy-preserving ML.',         departmentId: 'd-cs',  isOpenCollab: false, dueDate: '2026-08-22T00:00:00Z', status: 'ACTIVE', creatorId: 'u-sara', createdAt: now() };

    for (const p of [p1, p2, p3]) await put('projects', p);

    const memberData = [
      { id: uid(), projectId: 'p-1', userId: 'u-alex', role: 'LEAD',        joinedAt: now() },
      { id: uid(), projectId: 'p-1', userId: 'u-kim',  role: 'CONTRIBUTOR', joinedAt: now() },
      { id: uid(), projectId: 'p-2', userId: 'u-kim',  role: 'LEAD',        joinedAt: now() },
      { id: uid(), projectId: 'p-2', userId: 'u-alex', role: 'CONTRIBUTOR', joinedAt: now() },
      { id: uid(), projectId: 'p-3', userId: 'u-sara', role: 'LEAD',        joinedAt: now() },
    ];
    for (const m of memberData) await put('members', m);

    const taskData = [
      { id: uid(), projectId: 'p-1', title: 'Wireframe home screen',    status: 'DONE',        priority: 'HIGH',   createdAt: now() },
      { id: uid(), projectId: 'p-1', title: 'User research interviews',  status: 'IN_PROGRESS', priority: 'MEDIUM', createdAt: now() },
      { id: uid(), projectId: 'p-1', title: 'Design system tokens',      status: 'TODO',        priority: 'MEDIUM', createdAt: now() },
      { id: uid(), projectId: 'p-2', title: 'Competitive analysis',      status: 'DONE',        priority: 'HIGH',   createdAt: now() },
      { id: uid(), projectId: 'p-2', title: 'Financial projections',     status: 'IN_PROGRESS', priority: 'HIGH',   createdAt: now() },
      { id: uid(), projectId: 'p-3', title: 'Literature review',         status: 'DONE',        priority: 'HIGH',   createdAt: now() },
      { id: uid(), projectId: 'p-3', title: 'Dataset preparation',       status: 'IN_PROGRESS', priority: 'MEDIUM', createdAt: now() },
    ];
    for (const t of taskData) await put('tasks', t);

    const inviteKeyData = [
      { id: uid(), projectId: 'p-1', keyCode: genKey(), keyType: 'MULTI_USE', isActive: true, usedCount: 0, expiresAt: null, createdAt: now() },
      { id: uid(), projectId: 'p-2', keyCode: genKey(), keyType: 'MULTI_USE', isActive: true, usedCount: 0, expiresAt: null, createdAt: now() },
    ];
    for (const k of inviteKeyData) await put('inviteKeys', k);

    await put('permissions', { id: uid(), projectId: 'p-1', userId: 'u-alex', canInvite: true,  canEdit: true, canDelete: true  });
    await put('permissions', { id: uid(), projectId: 'p-1', userId: 'u-kim',  canInvite: false, canEdit: true, canDelete: false });

    console.log('[uni-co] Database seeded with', DEPTS.length, 'departments and demo data.');
  };

  // ── Init ───────────────────────────────────────────────────────────
  const init = async () => {
    if (!window.SUPABASE_URL || !window.SUPABASE_ANON_KEY ||
        window.SUPABASE_URL.includes('YOUR_PROJECT_ID')) {
      throw new Error(
        'Supabase credentials not configured.<br><br>' +
        'Open <strong>config.js</strong> and set <code>SUPABASE_URL</code> and <code>SUPABASE_ANON_KEY</code>.<br><br>' +
        'See <strong>SETUP.md</strong> for step-by-step instructions.'
      );
    }
    _sb = supabase.createClient(window.SUPABASE_URL, window.SUPABASE_ANON_KEY);
    // Quick connectivity check
    const { error } = await _sb.from('departments').select('id').limit(1);
    if (error) throw new Error(`Cannot reach Supabase: ${error.message}`);
    await seed();
  };

  // ── Public API (identical surface as the old IndexedDB engine) ─────
  return {
    mode: () => 'supabase',
    _sb: () => sb(),
    init, seed, get, getAll, put, del, uid, now, genKey,

    // Session
    getSession: async () => {
      const userId = getSessionLocal();
      return userId ? { userId } : null;
    },
    setSession: (userId) => { setSessionLocal(userId); return Promise.resolve(); },
    clearSession: () => { clearSessionLocal(); return Promise.resolve(); },

    getCurrentUser: async () => {
      const userId = getSessionLocal();
      if (!userId) return null;
      const u = await get('users', userId);
      if (!u) return null;
      const dept = await get('departments', u.departmentId);
      return { ...u, department: dept };
    },

    // Auth
    login: async ({ email, phone, password }) => {
      const all = await getAll('users');
      const u = all.find(x => (email && x.email === email) || (phone && x.phone === phone));
      if (!u) throw new Error('No account found with those credentials.');
      if (!(await verifyPassword(password, u.pw))) throw new Error('Incorrect password.');
      // Migrate legacy btoa hash to PBKDF2 on successful login
      if (u.pw && u.pw[0] !== '{') { await put('users', { ...u, pw: await hashPassword(password) }); }
      setSessionLocal(u.id);
      const dept = await get('departments', u.departmentId);
      return { ...u, department: dept };
    },

    signup: async ({ fullName, email, phone, password, departmentId }) => {
      const all = await getAll('users');
      if (email && all.find(u => u.email === email)) throw new Error('An account with this email already exists.');
      if (phone && all.find(u => u.phone === phone)) throw new Error('An account with this phone already exists.');
      const u = {
        id: uid(), fullName, email: email || null, phone: phone || null,
        pw: await hashPassword(password), departmentId, role: 'STUDENT',
        bio: '', gh: '', li: '', createdAt: now()
      };
      await put('users', u);
      setSessionLocal(u.id);
      const dept = await get('departments', departmentId);
      await put('notifications', { id: uid(), userId: u.id, text: `Welcome to uni-co, ${fullName}! 🎉 Start by creating or joining a project.`, type: 'system', read: false, createdAt: now() });
      return { ...u, department: dept };
    },

    updateUser: async (id, data) => {
      const u = await get('users', id);
      const updated = { ...u, ...data };
      await put('users', updated);
      return updated;
    },

    changePassword: async (id, oldPw, newPw) => {
      const u = await get('users', id);
      if (!(await verifyPassword(oldPw, u.pw))) throw new Error('Current password is incorrect.');
      if (newPw.length < 8) throw new Error('New password must be at least 8 characters.');
      await put('users', { ...u, pw: await hashPassword(newPw) });
    },

    logout: () => { clearSessionLocal(); return Promise.resolve(); },

    getDepts: () => getAll('departments'),
    getDept: (id) => get('departments', id),

    // Projects
    createProject: async ({ title, description, departmentId, isOpenCollab, dueDate, keyType, creatorId }) => {
      if (creatorId === '__demo__') throw new Error('Sign up for a free account to create projects.');
      const id = uid();
      const kc = genKey();
      await put('projects', { id, title, description: description || '', departmentId, isOpenCollab: !!isOpenCollab, dueDate: dueDate || null, status: 'ACTIVE', creatorId, createdAt: now() });
      await put('members', { id: uid(), projectId: id, userId: creatorId, role: 'LEAD', joinedAt: now() });
      await put('inviteKeys', { id: uid(), projectId: id, keyCode: kc, keyType: keyType || 'MULTI_USE', isActive: true, usedCount: 0, expiresAt: null, createdAt: now() });
      await put('permissions', { id: uid(), projectId: id, userId: creatorId, canInvite: true, canEdit: true, canDelete: true });
      return { id, keyCode: kc };
    },

    getMyProjects: async (userId) => {
      const mems = await getAll('members', 'userId', userId);
      const projs = await Promise.all(mems.map(m => get('projects', m.projectId)));
      const depts = await getAll('departments');
      const dm = Object.fromEntries(depts.map(d => [d.id, d]));
      return projs.filter(p => p && p.status !== 'ARCHIVED').map(p => ({ ...p, department: dm[p.departmentId] }));
    },

    getProject: async (id) => {
      const p = await get('projects', id);
      if (!p) return null;
      const [mems, tasks, files, msgs, keys, dept, quizzes, allPerms] = await Promise.all([
        getAll('members',     'projectId', id),
        getAll('tasks',       'projectId', id),
        getAll('files',       'projectId', id),
        getAll('messages',    'projectId', id),
        getAll('inviteKeys',  'projectId', id),
        get('departments', p.departmentId),
        getAll('quizzes',     'projectId', id),
        getAll('permissions', 'projectId', id),
      ]);
      const allUsers = await getAll('users');
      const um = Object.fromEntries(allUsers.map(u => [u.id, u]));
      const membersRich = mems.map(m => ({ ...m, user: { ...um[m.userId], department: dept } }));
      const msgsRich = msgs.sort((a, b) => a.sentAt.localeCompare(b.sentAt)).map(m => ({ ...m, sender: um[m.senderId] }));
      const activeKey = keys.find(k => k.isActive);
      const sessionUserId = getSessionLocal();
      const myPerm = allPerms.find(perm => perm.userId === sessionUserId);
      return { ...p, department: dept, members: membersRich, tasks, files, messages: msgsRich, inviteKey: activeKey || null, quizzes, _myPerms: myPerm || null };
    },

    updateProject: async (id, data) => {
      const p = await get('projects', id);
      await put('projects', { ...p, ...data });
    },

    archiveProject: async (id) => {
      const p = await get('projects', id);
      await put('projects', { ...p, status: 'ARCHIVED' });
    },

    deleteProject: async (id) => {
      for (const store of ['tasks', 'files', 'messages', 'members', 'inviteKeys', 'permissions', 'quizzes']) {
        const items = await getAll(store, 'projectId', id);
        for (const item of items) await del(store, item.id);
      }
      await del('projects', id);
    },

    getExplore: async (userId, { dept, openOnly, q } = {}) => {
      const mems = await getAll('members', 'userId', userId);
      const myIds = new Set(mems.map(m => m.projectId));
      const all = await getAll('projects');
      const depts = await getAll('departments');
      const dm = Object.fromEntries(depts.map(d => [d.id, d]));
      return all.filter(p => {
        if (p.status === 'ARCHIVED') return false;
        if (myIds.has(p.id)) return false;
        if (dept && dept !== 'all') { const d = dm[p.departmentId]; if (!d || d.code !== dept) return false; }
        if (openOnly && !p.isOpenCollab) return false;
        if (q) {
          const lq = q.toLowerCase();
          const titleLow = p.title.toLowerCase();
          const descLow = (p.description || '').toLowerCase();
          if (!titleLow.includes(lq) && !descLow.includes(lq)) {
            const words = [...titleLow.split(/\s+/), ...descLow.split(/\s+/)];
            if (!words.some(w => (w.startsWith(lq) || lq.startsWith(w)) && lq.length >= 3)) return false;
          }
        }
        return true;
      }).map(p => ({ ...p, department: dm[p.departmentId] }));
    },

    joinByKey: async (keyCode, userId) => {
      const all = await getAll('inviteKeys');
      const k = all.find(x => x.keyCode === keyCode.trim().toUpperCase());
      if (!k) throw new Error('Key not found. Check and try again.');
      if (!k.isActive) throw new Error('This key has been deactivated.');
      if (k.keyType === 'SINGLE_USE' && k.usedCount > 0) throw new Error('This single-use key has already been used.');
      if (k.expiresAt && new Date() > new Date(k.expiresAt)) throw new Error('This key has expired.');
      const mems = await getAll('members', 'projectId', k.projectId);
      if (mems.find(m => m.userId === userId)) throw new Error('You are already a member of this project.');
      await put('members', { id: uid(), projectId: k.projectId, userId, role: 'CONTRIBUTOR', joinedAt: now() });
      await put('permissions', { id: uid(), projectId: k.projectId, userId, canInvite: false, canEdit: true, canDelete: false });
      await put('inviteKeys', { ...k, usedCount: k.usedCount + 1, isActive: false });
      if (k.keyType === 'MULTI_USE') {
        const newKey = genKey();
        await put('inviteKeys', { id: uid(), projectId: k.projectId, keyCode: newKey, keyType: 'MULTI_USE', isActive: true, usedCount: 0, expiresAt: null, createdAt: now() });
      }
      return k.projectId;
    },

    joinOpen: async (projectId, userId) => {
      const mems = await getAll('members', 'projectId', projectId);
      if (mems.find(m => m.userId === userId)) throw new Error('Already a member.');
      await put('members', { id: uid(), projectId, userId, role: 'CONTRIBUTOR', joinedAt: now() });
      await put('permissions', { id: uid(), projectId, userId, canInvite: false, canEdit: true, canDelete: false });
    },

    regenKey: async (projectId) => {
      const keys = await getAll('inviteKeys', 'projectId', projectId);
      for (const k of keys) await put('inviteKeys', { ...k, isActive: false });
      const kc = genKey();
      await put('inviteKeys', { id: uid(), projectId, keyCode: kc, keyType: 'MULTI_USE', isActive: true, usedCount: 0, expiresAt: null, createdAt: now() });
      return kc;
    },

    // Tasks
    createTask: async (data) => {
      const t = { id: uid(), description: '', dueDate: null, ...data, createdAt: now() };
      await put('tasks', t);
      return t;
    },
    updateTask: async (id, data) => {
      const t = await get('tasks', id);
      const u = { ...t, ...data };
      await put('tasks', u);
      return u;
    },
    deleteTask: (id) => del('tasks', id),
    getTask: (id) => get('tasks', id),

    // Files (base64 stored in DB — works without Supabase Storage bucket)
    uploadFile: (projectId, uploadedById, file) => new Promise(resolve => {
      const reader = new FileReader();
      reader.onload = async () => {
        const f = { id: uid(), projectId, uploadedById, filename: file.name, fileType: file.name.split('.').pop() || 'bin', sizeBytes: file.size, dataUrl: reader.result, version: 1, tags: [], createdAt: now() };
        await put('files', f);
        await put('vaultVersions', { id: uid(), fileId: f.id, version: 1, dataUrl: reader.result, createdAt: now() });
        resolve(f);
      };
      reader.readAsDataURL(file);
    }),

    updateFileTags: async (fileId, tags) => {
      const f = await get('files', fileId);
      await put('files', { ...f, tags });
    },

    downloadFile: async (id) => {
      const f = await get('files', id);
      if (!f?.dataUrl) return;
      const a = document.createElement('a');
      a.href = f.dataUrl;
      a.download = f.filename;
      a.click();
    },

    deleteFile: async (id) => {
      await del('files', id);
      const versions = await getAll('vaultVersions', 'fileId', id);
      for (const v of versions) await del('vaultVersions', v.id);
    },

    // Messages
    sendMsg: async (projectId, senderId, content) => {
      if (senderId === '__demo__') throw new Error('Sign up to send messages.');
      const m = { id: uid(), projectId, senderId, content, sentAt: now() };
      await put('messages', m);
      return m;
    },

    deleteMsg: async (id) => del('messages', id),

    // Notifications
    getNotifs: (userId) => getAll('notifications', 'userId', userId).then(n => n.sort((a, b) => b.createdAt.localeCompare(a.createdAt))),
    markAllRead: async (userId) => {
      const n = await getAll('notifications', 'userId', userId);
      for (const x of n) await put('notifications', { ...x, read: true });
    },
    addNotif: (userId, text, type = 'system') => put('notifications', { id: uid(), userId, text, type, read: false, createdAt: now() }),

    // Quizzes
    createQuiz: (data) => put('quizzes', { id: uid(), ...data, createdAt: now() }),
    getQuiz: (id) => get('quizzes', id),
    submitQuizAttempt: (data) => put('quizAttempts', { id: uid(), ...data, attemptedAt: now() }),
    getQuizAttempts: (quizId, userId) => getAll('quizAttempts', 'quizId', quizId).then(a => a.filter(x => x.userId === userId)),

    // Permissions
    getPermissions: (projectId) => getAll('permissions', 'projectId', projectId),
    updatePermission: async (id, data) => {
      const p = await get('permissions', id);
      await put('permissions', { ...p, ...data });
    },

    // Export/Import (Data Vault — now exports from Supabase, re-imports to Supabase)
    exportAll: async () => {
      const stores = ['users','departments','projects','members','tasks','files','messages','inviteKeys','notifications','quizzes','quizAttempts','permissions','vaultVersions'];
      const data = {};
      for (const name of stores) {
        data[name] = await getAll(name);
      }
      return data;
    },

    importAll: async (data) => {
      const stores = ['departments','users','projects','members','tasks','files','messages','inviteKeys','notifications','quizzes','quizAttempts','permissions','vaultVersions'];
      for (const name of stores) {
        if (!data[name]) continue;
        for (const item of data[name]) {
          try { await put(name, item); } catch(e) { console.warn(`Import skip ${name}:`, e.message); }
        }
      }
    },
  };
})();

/* ═══════════════════════════════════════════════════════════════════
   SECTION 2 — UI Framework
   State, Icons, Theme Engine, Toast System, FLIP Morphing Modals,
   Skeleton Loaders, Staggered Animations, Router, Shell, Auth,
   Dashboard, Projects, Explore, Notifications, Settings + Data Vault
═══════════════════════════════════════════════════════════════════ */

/* ── App State ──────────────────────────────────────────────────────── */
const S = {
  user: null,
  page: null,
  project: null,
  theme: localStorage.getItem('uc-theme') || 'light',
  glass: localStorage.getItem('uc-glass') !== 'false', // default true
};

/* ── SVG Icon Library ───────────────────────────────────────────────── */
const I = {
  db: `<svg width="16" height="16" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/></svg>`,
  fo: `<svg width="16" height="16" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path d="M3 7a2 2 0 012-2h3l2 2h9a2 2 0 012 2v9a2 2 0 01-2 2H5a2 2 0 01-2-2V7z"/></svg>`,
  ex: `<svg width="16" height="16" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><path d="M21 21l-4.35-4.35"/></svg>`,
  be: `<svg width="16" height="16" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path d="M18 8A6 6 0 006 8c0 7-3 9-3 9h18s-3-2-3-9M13.73 21a2 2 0 01-3.46 0"/></svg>`,
  se: `<svg width="16" height="16" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 00.33 1.82l.06.06a2 2 0 010 2.83 2 2 0 01-2.83 0l-.06-.06a1.65 1.65 0 00-1.82-.33 1.65 1.65 0 00-1 1.51V21a2 2 0 01-4 0v-.09A1.65 1.65 0 009 19.4a1.65 1.65 0 00-1.82.33l-.06.06a2 2 0 01-2.83-2.83l.06-.06A1.65 1.65 0 004.68 15a1.65 1.65 0 00-1.51-1H3a2 2 0 010-4h.09A1.65 1.65 0 004.6 9a1.65 1.65 0 00-.33-1.82l-.06-.06a2 2 0 012.83-2.83l.06.06A1.65 1.65 0 009 4.68a1.65 1.65 0 001-1.51V3a2 2 0 014 0v.09a1.65 1.65 0 001 1.51 1.65 1.65 0 001.82-.33l.06-.06a2 2 0 012.83 2.83l-.06.06A1.65 1.65 0 0019.4 9a1.65 1.65 0 001.51 1H21a2 2 0 010 4h-.09a1.65 1.65 0 00-1.51 1z"/></svg>`,
  pl: `<svg width="13" height="13" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5"><path d="M12 5v14M5 12h14"/></svg>`,
  cl: `<svg width="15" height="15" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path d="M18 6L6 18M6 6l12 12"/></svg>`,
  cp: `<svg width="13" height="13" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1"/></svg>`,
  ck: `<svg width="13" height="13" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5"><path d="M20 6L9 17l-5-5"/></svg>`,
  sd: `<svg width="13" height="13" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path d="M22 2L11 13M22 2l-7 20-4-9-9-4 20-7z"/></svg>`,
  up: `<svg width="18" height="18" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4M17 8l-5-5-5 5M12 3v12"/></svg>`,
  fi: `<svg width="13" height="13" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/><polyline points="14,2 14,8 20,8"/></svg>`,
  tr: `<svg width="13" height="13" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14H6L5 6M10 11v6M14 11v6M9 6V4h6v2"/></svg>`,
  ed: `<svg width="13" height="13" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path d="M11 4H4a2 2 0 00-2 2v14a2 2 0 002 2h14a2 2 0 002-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 013 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>`,
  ky: `<svg width="13" height="13" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 11-7.778 7.778 5.5 5.5 0 017.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4"/></svg>`,
  rf: `<svg width="13" height="13" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path d="M23 4v6h-6M1 20v-6h6"/><path d="M3.51 9a9 9 0 0114.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0020.49 15"/></svg>`,
  lo: `<svg width="13" height="13" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path d="M9 21H5a2 2 0 01-2-2V5a2 2 0 012-2h4M16 17l5-5-5-5M21 12H9"/></svg>`,
  va: `<svg width="13" height="13" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0110 0v4"/></svg>`,
  qu: `<svg width="13" height="13" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M9.09 9a3 3 0 015.83 1c0 2-3 3-3 3"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>`,
  gr: `<svg width="13" height="13" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><circle cx="6" cy="6" r="2"/><circle cx="18" cy="18" r="2"/><circle cx="12" cy="12" r="2"/><circle cx="18" cy="6" r="2"/><circle cx="6" cy="18" r="2"/><path d="M8 7l8 10M16 7L8 17"/></svg>`,
};

/* ── Color Utilities ────────────────────────────────────────────────── */
const DCOLS = {
  CS: '#534AB7', ENG: '#185FA5', BIZ: '#0F6E56', ART: '#BA7517', ENGL: '#993C1D',
  MATH: '#3C3489', BIO: '#3B6D11', PSY: '#72243E', LAW: '#854F0B', MED: '#0C447C',
  ARCH: '#085041', POL: '#791F1F'
};
const DBGS = {
  CS: '#EEEDFE', ENG: '#E6F1FB', BIZ: '#E1F5EE', ART: '#FAEEDA', ENGL: '#FAECE7',
  MATH: '#EEEDFE', BIO: '#EAF3DE', PSY: '#FBEAF0', LAW: '#FAEEDA', MED: '#E6F1FB',
  ARCH: '#E1F5EE', POL: '#FCEBEB'
};
const dc = (code) => DCOLS[code] || '#534AB7';
const db_ = (code) => DBGS[code] || '#EEEDFE';
const ini = (name) => (name || '?').split(' ').map(n => n[0]).join('').slice(0, 2).toUpperCase();
const fmtD = (d) => d ? new Date(d).toLocaleDateString('en-US', { month: 'short', day: 'numeric' }) : '';
const isOD = (d) => d && new Date(d) < new Date() && new Date(d).toDateString() !== new Date().toDateString();
const isTD = (d) => d && new Date(d).toDateString() === new Date().toDateString();
const fmtSz = (b) => b < 1024 ? b + 'B' : b < 1048576 ? (b / 1024).toFixed(1) + 'KB' : (b / 1048576).toFixed(1) + 'MB';
const ftCol = (ext) => {
  const m = { py: ['#EEEDFE', '#3C3489'], js: ['#FAEEDA', '#633806'], ts: ['#E6F1FB', '#0C447C'],
    pdf: ['#FCEBEB', '#791F1F'], docx: ['#E6F1FB', '#0C447C'], xlsx: ['#EAF3DE', '#27500A'],
    csv: ['#EAF3DE', '#27500A'], png: ['#FBEAF0', '#72243E'], jpg: ['#FBEAF0', '#72243E'],
    zip: ['#F1EFE8', '#444441'], tex: ['#EEEDFE', '#3C3489'], md: ['#EAF3DE', '#27500A'],
    fig: ['#EEEDFE', '#3C3489'] };
  return m[(ext || '').toLowerCase()] || ['#F1EFE8', '#444441'];
};

const av = (user, sz = 'sm') => {
  if (!user) return `<div class="av av-${sz}" style="background:var(--bg3);color:var(--tx3)">??</div>`;
  const code = user?.department?.code || '';
  const bg = db_(code.toUpperCase()), col = dc(code.toUpperCase());
  const uid = user?.id ? `data-uid="${user.id}" style="position:relative;background:${bg};color:${col}"` : `style="background:${bg};color:${col}"`;
  return `<div class="av av-${sz}" ${uid}>${ini(user?.fullName)}</div>`;
};
const avStack = (members, max = 4) => {
  const vis = members.slice(0, max), ex = members.length - max;
  return `<div class="av-stack">${vis.map(m => av(m.user || m, 'sm')).join('')}${ex > 0 ? `<div class="av av-sm" style="background:var(--bg3);color:var(--tx2)">+${ex}</div>` : ''}</div>`;
};


// Theme Engine
function setTheme(t) {
  S.theme = t;
  document.documentElement.setAttribute('data-theme', t);
  localStorage.setItem('uc-theme', t);
}

function toggleGlass(enabled) {
  S.glass = enabled !== undefined ? enabled : !S.glass;
  document.documentElement.setAttribute('data-glass', S.glass.toString());
  localStorage.setItem('uc-glass', S.glass.toString());
}

// Initialize theme and glass
setTheme(S.theme);
toggleGlass(S.glass);

/* ── Unified Toast System ────────────────────────────────────────────── */
function toast(msg, type = '') {
  let c = document.getElementById('toasts');
  if (!c) {
    c = document.createElement('div');
    c.id = 'toasts';
    c.style.cssText = 'position:fixed;bottom:20px;right:20px;z-index:99999;display:flex;flex-direction:column;gap:6px';
    document.body.appendChild(c);
  }
  const el = document.createElement('div');
  el.className = `toast ${type === 'success' ? 'ok' : type === 'error' ? 'er' : type === 'info' ? 'info' : ''}`;
  el.textContent = msg;
  c.appendChild(el);
  requestAnimationFrame(() => el.classList.add('on'));
  setTimeout(() => {
    el.classList.remove('on');
    setTimeout(() => el.remove(), 300);
  }, 3000);
}

/* ── Router ──────────────────────────────────────────────────────────── */
window.go = async function go(page, data = {}) {
  S.page = page;

  // Auth guard
  if (!S.user && page !== 'login' && page !== 'signup') { go('login'); return; }

  // Update sidebar active states
  document.querySelectorAll('.ni').forEach(n => n.classList.toggle('on', n.dataset.p === page || (page === 'ws' && n.dataset.p === 'projects')));
  // Update mobile bottom nav
  document.querySelectorAll('.mob-nav-item').forEach(n => {
    n.classList.toggle('on', n.dataset.p === page || (page === 'ws' && n.dataset.p === 'projects'));
  });

  if (page === 'login') { showLogin(); return; }
  if (page === 'signup') { showSignup(); return; }

  const main = document.getElementById('main');
  if (!main) return;

  showSkeleton(page);

  // Re-attach nav scroll listener — #main content is replaced on every navigation
  if (window._reattachNavMainListener) window._reattachNavMainListener();

  stopChatRealtime();
  if (page === 'dashboard') await showDashboard();
  else if (page === 'projects') await showProjects();
  else if (page === 'explore') await showExplore();
  else if (page === 'notifs') await showNotifs();
  else if (page === 'settings') await showSettings();
  else if (page === 'invite') await showInvitePage();
  else if (page === 'ws') await showWorkspace(data.id);
}

/* ── Skeleton Loading ──────────────────────────────────────────────── */
function showSkeleton(page) {
  const main = document.getElementById('main');
  if (!main) return;
  if (page === 'dashboard') {
    main.innerHTML = `<div class="pg">
      <div class="ph"><div class="skel skel-text" style="width:180px;height:20px"></div><div class="skel" style="width:100px;height:32px;border-radius:8px"></div></div>
      <div class="stats">${Array(4).fill(`<div class="skel skel-card"></div>`).join('')}</div>
      <div class="skel skel-text" style="width:120px;margin-bottom:12px"></div>
      <div class="pgrid">${Array(3).fill(`<div class="skel skel-card"></div>`).join('')}</div>
    </div>`;
  } else if (page === 'projects' || page === 'explore') {
    main.innerHTML = `<div class="pg">
      <div class="ph"><div class="skel skel-text" style="width:140px;height:20px"></div><div class="skel" style="width:120px;height:32px;border-radius:8px"></div></div>
      <div class="pgrid">${Array(6).fill(`<div class="skel skel-card"></div>`).join('')}</div>
    </div>`;
  } else {
    main.innerHTML = `<div class="pg"><div class="skel skel-card" style="height:200px"></div></div>`;
  }
}

/* ── Shell Renderer ─────────────────────────────────────────────────── */
function renderShell() {
  const u = S.user;
  const code = u.department?.code || '';

  document.getElementById('root').innerHTML = `
<div class="mob-header" id="mob-header">
  <button class="mob-btn" onclick="openSidebar()" aria-label="Open menu">
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="3" y1="6" x2="21" y2="6"/><line x1="3" y1="12" x2="21" y2="12"/><line x1="3" y1="18" x2="21" y2="18"/></svg>
  </button>
  <div class="mob-brand"><span>uni</span>-co</div>
  <button class="mob-btn" onclick="openGlobalSearch()" aria-label="Search" style="margin-left:auto;margin-right:4px">
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
  </button>
  <button class="mob-btn" onclick="go('notifs')" aria-label="Notifications" style="position:relative">
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75"><path d="M18 8A6 6 0 006 8c0 7-3 9-3 9h18s-3-2-3-9M13.73 21a2 2 0 01-3.46 0"/></svg>
    <span id="mob-notif-dot" style="display:none;position:absolute;top:6px;right:6px;width:7px;height:7px;border-radius:50%;background:var(--err)"></span>
  </button>
</div>
<div id="sidebar-overlay" onclick="closeSidebar()"></div>
<div id="app">
  <aside class="sidebar glass-el" id="sidebar">
    <div class="sb-brand">
      <div class="sb-logo-mark">uc</div>
      <div class="sb-logo-text">uni<span class="sb-co">-co</span></div>
      <button class="sb-close" onclick="closeSidebar()" aria-label="Close sidebar">${I.cl}</button>
    </div>
    <nav class="snav" role="navigation" aria-label="Main navigation">
      <div class="nsec">Menu</div>
      ${ni('dashboard', 'Dashboard', I.db)}
      ${ni('projects', 'My Projects', I.fo)}
      ${ni('explore', 'Explore', I.ex)}
      ${ni('notifs', 'Notifications', I.be, 'nbadge')}
      ${ni('invite', 'Invite Friends', `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><line x1="19" y1="8" x2="19" y2="14"/><line x1="22" y1="11" x2="16" y2="11"/></svg>`)}
      <div class="nsec" style="margin-top:8px">Account</div>
      ${ni('settings', 'Settings', I.se)}
    </nav>
    <div class="sfoot">
      <div class="uchip" onclick="go('settings');closeSidebar()" role="button" aria-label="Profile settings" tabindex="0">
        ${av(u, 'md')}
        <div style="flex:1;min-width:0">
          <div class="uname">${esc(u.fullName)}</div>
          <div class="udept">${esc(u.department?.name || '')}</div>
          ${u.isDemo ? '<div style="font-size:10px;font-weight:600;color:var(--tx3);letter-spacing:.5px;text-transform:uppercase;margin-top:2px">View only</div>' : ''}
        </div>
      </div>
      ${u.isDemo ? `<button class="btn btn-primary btn-block" onclick="go('signup')" style="margin-top:8px;font-size:12px">Create free account →</button>` : ''}
    </div>
  </aside>
  <main id="main" role="main"></main>
</div>
<!-- Mobile bottom nav -->
<nav id="mob-nav" aria-label="Bottom navigation">
  <div style="display:flex;justify-content:space-around;align-items:center;padding:0 8px">
    ${[
      ['dashboard', `<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/></svg>`, 'Home'],
      ['projects', `<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/></svg>`, 'Projects'],
      ['explore', `<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>`, 'Explore'],
      ['notifs', `<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.73 21a2 2 0 0 1-3.46 0"/></svg>`, 'Alerts'],
      ['settings', `<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>`, 'Settings'],
    ].map(([page, icon, label]) => `
      <div class="mob-nav-item" data-p="${page}" onclick="go('${page}')" role="button" aria-label="${label}" tabindex="0" onkeydown="if(event.key==='Enter'||event.key===' ')go('${page}')">
        <span style="display:flex;align-items:center;justify-content:center">${icon}</span>
        <span>${label}</span>
      </div>`).join('')}
  </div>
</nav>`;
  updateNBadge();
  // Show mobile nav only on small screens
  const mobNav = document.getElementById('mob-nav');
  if (mobNav) mobNav.style.display = window.innerWidth <= 860 ? 'block' : 'none';
  initNavAutoHide();
}

function ni(page, label, icon, badgeId = '') {
  return `<div class="ni" data-p="${page}" onclick="go('${page}');closeSidebar()">
    ${icon}<span>${label}</span>
    ${badgeId ? `<span class="nbadge" id="${badgeId}" style="display:none">0</span>` : ''}
  </div>`;
}

window.openSidebar = function() {
  document.getElementById('sidebar')?.classList.add('open');
  document.getElementById('sidebar-overlay')?.classList.add('on');
};
window.closeSidebar = function() {
  document.getElementById('sidebar')?.classList.remove('open');
  document.getElementById('sidebar-overlay')?.classList.remove('on');
};

/* ── Auto-hide bottom nav on scroll ──────────────────────────────────
   Hides nav when scrolling DOWN, reveals it when scrolling UP.
   Always shows when near the top or bottom of the page.
   Tapping anywhere on the hidden nav strip reveals it instantly.
   On page navigation the nav always resets to visible.
─────────────────────────────────────────────────────────────────── */
function initNavAutoHide() {
  if (window.innerWidth > 860) return;
  const nav = document.getElementById('mob-nav');
  if (!nav) return;

  // Only initialise the window scroll listener once
  if (window._navAutoHideReady) {
    // Re-attach #main listener after every navigation (DOM is replaced)
    if (window._reattachNavMainListener) window._reattachNavMainListener();
    return;
  }
  window._navAutoHideReady = true;

  let lastY = 0;
  let ticking = false;
  let isHidden = false;
  let _mainEl = null;

  const NO_HIDE_PAGES = ['settings', 'notifs', 'invite'];

  function showNav() {
    if (!isHidden) return;
    isHidden = false;
    nav.classList.remove('nav-hidden');
    nav.classList.add('nav-visible');
  }

  function hideNav() {
    if (isHidden) return;
    if (NO_HIDE_PAGES.includes(S.page)) return;
    isHidden = true;
    nav.classList.add('nav-hidden');
    nav.classList.remove('nav-visible');
  }

  function onScroll(e) {
    if (ticking) return;
    ticking = true;
    requestAnimationFrame(() => {
      const isWin = !e || !e.target || e.target === document || e.target === document.documentElement;
      const el = isWin ? document.documentElement : e.target;
      const y = isWin ? (window.scrollY || el.scrollTop) : el.scrollTop;
      const maxScroll = el.scrollHeight - (isWin ? window.innerHeight : el.clientHeight);
      const delta = y - lastY;

      if (y < 80 || (maxScroll > 0 && y >= maxScroll - 40)) {
        showNav();
      } else if (delta > 8) {
        hideNav();
      } else if (delta < -6) {
        showNav();
      }

      lastY = y;
      ticking = false;
    });
  }

  // Re-attach to #main after each navigation (called from go() and renderShell)
  window._reattachNavMainListener = function() {
    if (_mainEl) { try { _mainEl.removeEventListener('scroll', onScroll); } catch(e) {} }
    _mainEl = document.getElementById('main');
    if (_mainEl) _mainEl.addEventListener('scroll', onScroll, { passive: true });
    showNav();
    lastY = 0;
  };

  window.addEventListener('scroll', onScroll, { passive: true });
  window._reattachNavMainListener();

  nav.addEventListener('touchstart', () => { if (isHidden) showNav(); }, { passive: true });
}

async function updateNBadge() {
  if (!S.user) return;
  const n = await StorageEngine.getNotifs(S.user.id);
  const unread = n.filter(x => !x.read).length;
  const el = document.getElementById('nbadge');
  if (el) { el.style.display = unread > 0 ? 'inline' : 'none'; el.textContent = unread; }
  const mobDot = document.getElementById('mob-notif-dot');
  if (mobDot) mobDot.style.display = unread > 0 ? 'block' : 'none';
}

function updateMobNav(page) {
  document.querySelectorAll('.mob-nav-item').forEach(n => {
    n.classList.toggle('on', n.dataset.p === page || (page === 'ws' && n.dataset.p === 'projects'));
  });
}

/* ── Modal Controller (with FLIP morph support) ────────────────────── */
const M = {
  open: (id, sourceEl = null) => {
    const modal = document.getElementById('m-' + id);
    const overlay = modal?.closest('.ov');
    if (!modal || !overlay) return;

    // FLIP morph from source element
    if (sourceEl) {
      const sourceRect = sourceEl.getBoundingClientRect();
      modal.style.position = 'fixed';
      modal.style.left = sourceRect.left + 'px';
      modal.style.top = sourceRect.top + 'px';
      modal.style.width = sourceRect.width + 'px';
      modal.style.height = sourceRect.height + 'px';
      modal.style.borderRadius = 'var(--r)';
      modal.style.transition = 'all .35s cubic-bezier(.34,1.4,.64,1)';
      modal.style.opacity = '1';
      modal.style.transform = 'none';
    }

    overlay.classList.add('on');

    if (sourceEl) {
      requestAnimationFrame(() => {
        requestAnimationFrame(() => {
          modal.style.left = '';
          modal.style.top = '';
          modal.style.width = '';
          modal.style.height = '';
          modal.style.borderRadius = '';
          setTimeout(() => {
            modal.style.transition = '';
            modal.style.position = '';
            modal.style.opacity = '';
            modal.style.transform = '';
          }, 360);
        });
      });
    }
  },

  close: (id) => {
    const modal = document.getElementById('m-' + id);
    const overlay = modal?.closest('.ov');
    if (overlay) overlay.classList.remove('on');
  },
};

document.addEventListener('click', e => {
  if (e.target.classList.contains('ov')) e.target.classList.remove('on');
});
document.addEventListener('keydown', e => {
  if (e.key === 'Escape') document.querySelectorAll('.ov.on').forEach(x => x.classList.remove('on'));
});

/* ── Auth Pages ─────────────────────────────────────────────────────── */
function showLogin() {
  document.getElementById('root').innerHTML = `
<div class="authpg">
  <div class="authcard">
    <div class="authbrand"><span>uni</span>-co</div>
    <div class="authsub">Sign in to your workspace</div>
    <div class="autherr" id="aerr"></div>
    <div style="display:flex;gap:6px;margin-bottom:16px;background:var(--bg2);padding:4px;border-radius:6px">
      <button class="btn btn-block" id="t-email" style="background:var(--sur);box-shadow:var(--sh)" onclick="swTab('email')">Email</button>
      <button class="btn btn-block" id="t-phone" style="background:transparent;border-color:transparent;box-shadow:none" onclick="swTab('phone')">Phone</button>
    </div>
    <div id="f-email"><div class="fg"><label class="fl" for="lin-email">University email</label><input class="fi" id="lin-email" type="email" placeholder="you@university.edu" autocomplete="email" onkeydown="if(event.key==='Enter')doLogin()"></div></div>
    <div id="f-phone" style="display:none"><div class="fg"><label class="fl" for="lin-phone">Phone number</label><input class="fi" id="lin-phone" type="tel" placeholder="+1 555 000 0000" autocomplete="tel" onkeydown="if(event.key==='Enter')doLogin()"></div></div>
    <div class="fg"><label class="fl" for="lin-pw">Password</label>
      <div style="position:relative">
        <input class="fi" id="lin-pw" type="password" placeholder="Your password" autocomplete="current-password" onkeydown="if(event.key==='Enter')doLogin()" style="padding-right:40px">
        <button onclick="togglePw('lin-pw')" style="position:absolute;right:10px;top:50%;transform:translateY(-50%);color:var(--tx3);font-size:16px;padding:2px;line-height:1">👁</button>
      </div>
    </div>
    <button class="btn btn-primary btn-block btn-lg" onclick="doLogin()" id="lbtn">Sign in</button>
    <div class="authlink">No account? <a href="#" onclick="go('signup')">Create one</a></div>
    <div class="authlink" style="margin-top:6px;font-size:11px;color:var(--tx3)">By using uni-co you agree to our <a href="/terms.pdf" target="_blank" style="color:var(--tx3)">Terms of Service</a></div>
  </div>
</div>`;
  setTimeout(() => document.getElementById('lin-email')?.focus(), 80);
}

function swTab(t) {
  const isE = t === 'email';
  document.getElementById('f-email').style.display = isE ? '' : 'none';
  document.getElementById('f-phone').style.display = isE ? 'none' : '';
  document.getElementById('t-email').style.cssText = isE ? 'background:var(--sur);box-shadow:var(--sh)' : 'background:transparent;border-color:transparent;box-shadow:none';
  document.getElementById('t-phone').style.cssText = !isE ? 'background:var(--sur);box-shadow:var(--sh)' : 'background:transparent;border-color:transparent;box-shadow:none';
}

async function doLogin() {
  const email = document.getElementById('f-email').style.display !== 'none' ? document.getElementById('lin-email').value.trim() : null;
  const phone = document.getElementById('f-phone').style.display !== 'none' ? document.getElementById('lin-phone').value.trim() : null;
  const pw = document.getElementById('lin-pw').value;
  const err = document.getElementById('aerr'); err.style.display = 'none';
  if (!email && !phone) { err.textContent = 'Please enter your email or phone.'; err.style.display = 'block'; return; }
  if (!pw) { err.textContent = 'Please enter your password.'; err.style.display = 'block'; return; }
  const btn = document.getElementById('lbtn'); btn.disabled = true; btn.textContent = 'Signing in...';
  try {
    S.user = await StorageEngine.login({ email, phone, password: pw });
    renderShell();
    await go('dashboard');
    toast(`Welcome back, ${S.user.fullName.split(' ')[0]}!`, 'success');
  } catch (e) { err.textContent = e.message; err.style.display = 'block'; btn.disabled = false; btn.textContent = 'Sign in'; }
}

/* ── Guided Demo (read-only — no input accepted except navigation) ───
   The demo user can browse all seed data but every action that would
   mutate state is silently intercepted and shows a "sign up" prompt.
─────────────────────────────────────────────────────────────────── */
async function startGuidedDemo() {
  const depts = await StorageEngine.getDepts();
  const dept = depts.find(d => d.code === 'CS') || depts[0];

  S.user = {
    id: '__demo__',
    fullName: 'Demo User',
    email: null,
    phone: null,
    departmentId: dept?.id || 'd-cs',
    department: dept,
    role: 'STUDENT',
    bio: '',
    gh: '', li: '',
    isDemo: true,
    createdAt: new Date().toISOString(),
  };

  renderShell();
  await go('dashboard');
  setTimeout(() => startTour(), 600);
}

/* ── Demo guard — blocks any mutating action ─────────────────────── */
function demoGuard() {
  if (!S.user?.isDemo) return false; // not demo, allow
  // Show a clean, non-toast prompt
  const existing = document.getElementById('demo-gate');
  if (existing) { existing.remove(); }
  const el = document.createElement('div');
  el.id = 'demo-gate';
  el.innerHTML = `
    <div style="position:fixed;inset:0;z-index:99999;display:flex;align-items:center;justify-content:center;background:rgba(0,0,0,0.4);backdrop-filter:blur(4px)" onclick="this.parentElement.remove()">
      <div style="background:var(--sur);border-radius:16px;padding:32px 28px;max-width:340px;text-align:center;box-shadow:0 20px 60px rgba(0,0,0,0.25)" onclick="event.stopPropagation()">
        <div style="font-size:22px;font-weight:700;color:var(--tx);margin-bottom:8px">This is a demo</div>
        <p style="font-size:14px;color:var(--tx2);line-height:1.6;margin-bottom:24px">You can browse uni-co here, but creating, editing, and messaging requires a free account.</p>
        <div style="display:flex;gap:10px">
          <button class="btn btn-block" onclick="document.getElementById('demo-gate')?.remove()">Keep browsing</button>
          <button class="btn btn-primary btn-block" onclick="document.getElementById('demo-gate')?.remove();go('signup')">Create account</button>
        </div>
      </div>
    </div>`;
  document.body.appendChild(el);
  return true; // blocked
}

/* ═══════════════════════════════════════════════════════════════════
   GUIDED WALKTHROUGH TOUR — 6 steps, spotlight + tooltip
═══════════════════════════════════════════════════════════════════ */
const TOUR_STEPS = [
  {
    target: '.ph h1',
    title: 'Your dashboard',
    body: 'Quick stats, your projects, and tasks due soon — all in one place.',
    pos: 'bottom',
  },
  {
    target: '.stats',
    title: 'At a glance',
    body: 'See active projects, tasks due today, completions, and how many departments you\'re collaborating across.',
    pos: 'bottom',
  },
  {
    target: '.pgrid',
    title: 'Your projects',
    body: 'Each card shows progress, team members, and due dates. Click any card to open the workspace.',
    pos: 'top',
  },
  {
    target: '[data-p="projects"]',
    title: 'My Projects',
    body: 'All your active and archived projects. Filter by status, or create a new one here.',
    pos: 'right',
  },
  {
    target: '[data-p="explore"]',
    title: 'Explore & join',
    body: 'Discover open projects from any department and join instantly — or enter an invite key to join a private one.',
    pos: 'right',
  },
  {
    target: '[data-p="settings"]',
    title: 'Settings & themes',
    body: 'Switch between 5 themes, toggle glassmorphism, manage your profile, and connect a database when you\'re ready to go live.',
    pos: 'right',
  },
];

let _tourStep = 0;
let _tourEl = null;

function startTour() {
  _tourStep = 0;
  injectTourOverlay();
  showTourStep();
}

function injectTourOverlay() {
  if (document.getElementById('tour-overlay')) return;
  const div = document.createElement('div');
  div.id = 'tour-overlay';
  div.innerHTML = `
    <div id="tour-backdrop"></div>
    <div id="tour-spotlight"></div>
    <div id="tour-card" role="dialog" aria-modal="true" aria-label="Product tour">
      <div id="tour-step-label"></div>
      <div id="tour-title"></div>
      <div id="tour-body"></div>
      <div id="tour-dots"></div>
      <div id="tour-actions">
        <button id="tour-skip" onclick="endTour()" aria-label="Skip tour">Skip</button>
        <button id="tour-next" onclick="advanceTour()" aria-label="Next step">Next →</button>
      </div>
    </div>`;
  document.body.appendChild(div);
}

function showTourStep() {
  const step = TOUR_STEPS[_tourStep];
  const total = TOUR_STEPS.length;

  const target = document.querySelector(step.target);
  const card   = document.getElementById('tour-card');
  const spotlight = document.getElementById('tour-spotlight');
  if (!card) return;

  // Content
  document.getElementById('tour-step-label').textContent = `STEP ${_tourStep + 1} OF ${total}`;
  document.getElementById('tour-title').textContent = step.title;
  document.getElementById('tour-body').textContent = step.body;
  document.getElementById('tour-next').textContent = _tourStep === total - 1 ? 'Finish ✓' : 'Next →';

  // Dots
  document.getElementById('tour-dots').innerHTML = Array.from({ length: total }, (_, i) =>
    `<div class="tour-dot${i === _tourStep ? ' on' : ''}"></div>`).join('');

  // Position spotlight on target element
  if (target) {
    target.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    setTimeout(() => positionTourCard(target, card, spotlight, step.pos), 120);
  } else {
    // Fallback: centre card, no spotlight
    spotlight.style.cssText = 'display:none';
    card.style.cssText = 'position:fixed;top:50%;left:50%;transform:translate(-50%,-50%)';
  }

  // Animate card in
  card.style.opacity = '0';
  card.style.transform += ' scale(0.95)';
  requestAnimationFrame(() => {
    card.style.transition = 'all 0.25s cubic-bezier(0.34,1.3,0.64,1)';
    card.style.opacity = '1';
    card.style.transform = card.style.transform.replace(' scale(0.95)', '');
  });
}

function positionTourCard(target, card, spotlight, pos) {
  const tr = target.getBoundingClientRect();
  const PAD = 12;

  // Spotlight
  spotlight.style.cssText = `
    display:block;
    position:fixed;
    top:${tr.top - PAD}px;
    left:${tr.left - PAD}px;
    width:${tr.width + PAD * 2}px;
    height:${tr.height + PAD * 2}px;
    border-radius:12px;
    box-shadow:0 0 0 9999px rgba(0,0,0,0.52);
    transition:all 0.3s ease;
    pointer-events:none;
    z-index:10001;
    outline:2px solid rgba(107,78,255,0.7);
    outline-offset:2px;
  `;

  // Card position
  const cw = 300, ch = 200;
  let top, left;

  if (pos === 'bottom') {
    top  = tr.bottom + PAD + 8;
    left = Math.max(PAD, Math.min(tr.left + tr.width / 2 - cw / 2, window.innerWidth - cw - PAD));
  } else if (pos === 'top') {
    top  = tr.top - ch - PAD - 8;
    left = Math.max(PAD, Math.min(tr.left + tr.width / 2 - cw / 2, window.innerWidth - cw - PAD));
  } else if (pos === 'right') {
    top  = Math.max(PAD, Math.min(tr.top + tr.height / 2 - ch / 2, window.innerHeight - ch - PAD));
    left = tr.right + PAD + 8;
  } else {
    top  = Math.max(PAD, tr.top + tr.height / 2 - ch / 2);
    left = tr.left - cw - PAD - 8;
  }

  // Clamp within viewport
  top  = Math.max(PAD, Math.min(top,  window.innerHeight - ch - PAD));
  left = Math.max(PAD, Math.min(left, window.innerWidth  - cw - PAD));

  card.style.cssText = `
    position:fixed;top:${top}px;left:${left}px;width:${cw}px;
    z-index:10002;opacity:1;transition:all 0.25s cubic-bezier(0.34,1.3,0.64,1);
  `;
}

window.advanceTour = function() {
  _tourStep++;
  if (_tourStep >= TOUR_STEPS.length) { endTour(); return; }
  showTourStep();
};

window.endTour = function() {
  const overlay = document.getElementById('tour-overlay');
  if (overlay) {
    overlay.style.opacity = '0';
    overlay.style.transition = 'opacity 0.3s ease';
    setTimeout(() => overlay.remove(), 320);
  }
  // If demo user, prompt to sign up after tour ends
  if (S.user?.isDemo) {
    setTimeout(() => {
      const banner = document.createElement('div');
      banner.id = 'demo-cta';
      banner.innerHTML = `
        <div style="position:fixed;bottom:80px;left:50%;transform:translateX(-50%);z-index:9000;
          background:var(--brand);color:#fff;border-radius:14px;padding:14px 22px;
          display:flex;align-items:center;gap:14px;box-shadow:0 8px 32px rgba(83,74,183,0.4);
          animation:slideUp 0.4s cubic-bezier(0.34,1.3,0.64,1);white-space:nowrap;max-width:90vw;flex-wrap:wrap">
          <span style="font-size:14px;font-weight:600">Liked what you saw?</span>
          <button onclick="go('signup');document.getElementById('demo-cta')?.remove()"
            style="background:#fff;color:var(--brand);border:none;border-radius:8px;padding:8px 16px;font-weight:700;cursor:pointer;font-size:13px;font-family:inherit">
            Create free account →
          </button>
          <button onclick="document.getElementById('demo-cta')?.remove()"
            style="background:rgba(255,255,255,0.2);color:#fff;border:none;border-radius:8px;padding:8px 12px;cursor:pointer;font-size:13px;font-family:inherit">
            ✕
          </button>
        </div>`;
      document.body.appendChild(banner);
      setTimeout(() => banner.remove(), 12000);
    }, 400);
  }
};

/* ── Onboarding modal — shown once after first real signup ─────────── */
function showOnboarding() {
  if (localStorage.getItem('uc-onboarded')) return;
  const overlay = document.createElement('div');
  overlay.className = 'ov on';
  overlay.id = 'onboarding-overlay';
  overlay.innerHTML = `
    <div class="modal" style="max-width:420px;text-align:center;padding:0;overflow:hidden">
      <div style="background:linear-gradient(135deg,var(--brand),var(--brand-m));padding:28px 24px 20px;position:relative">
        <div style="font-size:36px;margin-bottom:8px">🎉</div>
        <h2 style="font-size:20px;font-weight:700;color:#fff;margin-bottom:6px">Welcome to uni-co!</h2>
        <p style="font-size:13px;color:rgba(255,255,255,0.8)">You're all set. Here's how to get started:</p>
      </div>
      <div style="padding:20px 24px">
        <div style="display:flex;flex-direction:column;gap:10px;margin-bottom:20px;text-align:left">
          ${[
            ['📁','Create a project','Hit "+ New project", pick your department, and invite teammates with a key.'],
            ['🔑','Join a project','Use "Join with key" if a teammate shared an invite code with you.'],
            ['📋','Manage tasks','Inside any project, use the Tasks tab to track work with a Kanban board.'],
            ['🎨','Pick a theme','Go to Settings → Appearance to switch themes and toggle glassmorphism.'],
          ].map(([icon, title, desc]) => `
            <div style="display:flex;gap:12px;align-items:flex-start;padding:10px 12px;background:var(--bg2);border-radius:var(--r)">
              <span style="font-size:20px;flex-shrink:0">${icon}</span>
              <div>
                <div style="font-size:13px;font-weight:600;color:var(--tx);margin-bottom:2px">${title}</div>
                <div style="font-size:12px;color:var(--tx2);line-height:1.45">${desc}</div>
              </div>
            </div>`).join('')}
        </div>
        <div style="display:flex;gap:8px">
          <button class="btn btn-secondary btn-block" onclick="startTour();document.getElementById('onboarding-overlay')?.remove()">
            Take a tour →
          </button>
          <button class="btn btn-primary btn-block" onclick="document.getElementById('onboarding-overlay')?.remove();localStorage.setItem('uc-onboarded','1');openNewProject(this)">
            Create first project →
          </button>
        </div>
        <button onclick="document.getElementById('onboarding-overlay')?.remove();localStorage.setItem('uc-onboarded','1')"
          style="background:none;border:none;font-size:12px;color:var(--tx3);cursor:pointer;margin-top:10px;font-family:inherit">
          Skip for now
        </button>
      </div>
    </div>`;
  document.body.appendChild(overlay);
  overlay.addEventListener('click', e => { if (e.target === overlay) { overlay.remove(); localStorage.setItem('uc-onboarded', '1'); } });
}

async function showSignup() {
  const depts = await StorageEngine.getDepts();
  document.getElementById('root').innerHTML = `
<div class="authpg">
  <div class="authcard" style="width:480px">
    <div class="authbrand"><span>uni</span>-co</div>
    <div class="authsub">Create your account</div>
    <div class="autherr" id="aerr"></div>
    <div style="display:flex;gap:6px;margin-bottom:16px;background:var(--bg2);padding:4px;border-radius:6px">
      <button class="btn btn-block" id="st-email" style="background:var(--sur);box-shadow:var(--sh)" onclick="swSTab('email')">Email</button>
      <button class="btn btn-block" id="st-phone" style="background:transparent;border-color:transparent;box-shadow:none" onclick="swSTab('phone')">Phone</button>
    </div>
    <div class="frow">
      <div class="fg"><label class="fl" for="su-fn">First name</label><input class="fi" id="su-fn" placeholder="Jamie" autocomplete="given-name"></div>
      <div class="fg"><label class="fl" for="su-ln">Last name</label><input class="fi" id="su-ln" placeholder="Davis" autocomplete="family-name"></div>
    </div>
    <div id="sf-email"><div class="fg"><label class="fl" for="su-email">Email</label><input class="fi" id="su-email" type="email" placeholder="you@university.edu" autocomplete="email" oninput="detectDept(this.value)"><div class="fh">Use your .edu email to auto-detect department</div></div></div>
    <div id="sf-phone" style="display:none"><div class="fg"><label class="fl" for="su-phone">Phone</label><input class="fi" id="su-phone" type="tel" placeholder="+1 555 000 0000"></div></div>
    <div class="fg"><label class="fl" for="su-dept">Department *</label>
      <select class="fi fi-select" id="su-dept" onchange="handleDeptChange(this)">
        <option value="">Select your department...</option>
        ${depts.map(d => `<option value="${d.id}">${esc(d.name)} (${esc(d.code)})</option>`).join('')}
        <option value="__custom__">Other / Not listed</option>
      </select>
      <div class="fh" id="dept-msg" style="display:none;color:var(--ok)">✓ Department auto-detected</div>
    </div>
    <div id="custom-dept-wrap" style="display:none">
      <div class="fg"><label class="fl" for="su-custom-dept">Your department name *</label>
        <input class="fi" id="su-custom-dept" placeholder="e.g. Urban Planning, Journalism, Architecture...">
        <div class="fh">You'll have access to all features except the specialised workstation tool (available for the 12 built-in departments).</div>
      </div>
    </div>
    <div class="fg"><label class="fl" for="su-pw">Password</label>
      <div style="position:relative">
        <input class="fi" id="su-pw" type="password" placeholder="Min. 8 characters" oninput="pwStr(this.value)" style="padding-right:40px">
        <button onclick="togglePw('su-pw')" style="position:absolute;right:10px;top:50%;transform:translateY(-50%);color:var(--tx3);font-size:16px;padding:2px;line-height:1">👁</button>
      </div>
      <div class="pw-bar"><div class="pw-fill" id="pw-fill"></div></div>
      <div class="fh" id="pw-lbl"></div>
    </div>
    <div class="fg"><label class="fl" for="su-pw2">Confirm password</label><input class="fi" id="su-pw2" type="password" placeholder="Repeat password" onkeydown="if(event.key==='Enter')doSignup()"></div>
    <label class="fcheck" style="margin-bottom:16px"><input type="checkbox" id="su-terms"><span>I agree to the <a href="/terms.pdf" target="_blank">Terms of Service</a></span></label>
    <button class="btn btn-primary btn-block btn-lg" onclick="doSignup()" id="sbtn">Create account</button>
    <div class="authlink">Already have an account? <a href="#" onclick="go('login')">Sign in</a></div>
  </div>
</div>`;
  setTimeout(() => document.getElementById('su-fn')?.focus(), 80);
}

function swSTab(t) {
  const isE = t === 'email';
  document.getElementById('sf-email').style.display = isE ? '' : 'none';
  document.getElementById('sf-phone').style.display = isE ? 'none' : '';
  document.getElementById('st-email').style.cssText = isE ? 'background:var(--sur);box-shadow:var(--sh)' : 'background:transparent;border-color:transparent;box-shadow:none';
  document.getElementById('st-phone').style.cssText = !isE ? 'background:var(--sur);box-shadow:var(--sh)' : 'background:transparent;border-color:transparent;box-shadow:none';
}

function detectDept(email) {
  const sub = (email.split('@')[1] || '').split('.')[0].toUpperCase();
  const sel = document.getElementById('su-dept'); if (!sel) return;
  const opt = Array.from(sel.options).find(o => o.text.includes(`(${sub})`));
  const msg = document.getElementById('dept-msg');
  if (opt) { sel.value = opt.value; if (msg) msg.style.display = 'block'; handleDeptChange(sel); }
  else if (msg) msg.style.display = 'none';
}

function handleDeptChange(sel) {
  const wrap = document.getElementById('custom-dept-wrap');
  if (wrap) wrap.style.display = sel.value === '__custom__' ? 'block' : 'none';
}

function pwStr(pw) {
  let s = 0;
  if (pw.length >= 8) s++; if (pw.length >= 12) s++; if (/[A-Z]/.test(pw)) s++; if (/[0-9]/.test(pw)) s++; if (/[^A-Za-z0-9]/.test(pw)) s++;
  const cols = ['#C0392B', '#C0392B', '#BA7517', '#1D9E75', '#1D9E75'];
  const lbls = ['Too short', 'Weak', 'Fair', 'Strong', 'Very strong'];
  const i = Math.min(s, 4);
  const f = document.getElementById('pw-fill'); if (f) { f.style.width = (s * 20) + '%'; f.style.background = cols[i]; }
  const l = document.getElementById('pw-lbl'); if (l && pw.length > 0) { l.textContent = lbls[i]; l.style.color = cols[i]; }
}

function togglePw(id) { const el = document.getElementById(id); if (el) el.type = el.type === 'password' ? 'text' : 'password'; }

async function doSignup() {
  const fn = document.getElementById('su-fn')?.value?.trim();
  const ln = document.getElementById('su-ln')?.value?.trim();
  const emailEl = document.getElementById('su-email'); const phoneEl = document.getElementById('su-phone');
  const email = document.getElementById('sf-email').style.display !== 'none' ? emailEl?.value?.trim() : null;
  const phone = document.getElementById('sf-phone').style.display !== 'none' ? phoneEl?.value?.trim() : null;
  const dept = document.getElementById('su-dept')?.value;
  const pw = document.getElementById('su-pw')?.value;
  const pw2 = document.getElementById('su-pw2')?.value;
  const terms = document.getElementById('su-terms')?.checked;
  const err = document.getElementById('aerr'); err.style.display = 'none';
  if (!fn || !ln) { err.textContent = 'Enter your full name.'; err.style.display = 'block'; return; }
  if (!email && !phone) { err.textContent = 'Enter your email or phone.'; err.style.display = 'block'; return; }
  if (!dept) { err.textContent = 'Select your department.'; err.style.display = 'block'; return; }
  if (dept === '__custom__') {
    const customName = document.getElementById('su-custom-dept')?.value?.trim();
    if (!customName) { err.textContent = 'Enter your department name.'; err.style.display = 'block'; return; }
  }
  if (!pw || pw.length < 8) { err.textContent = 'Password must be at least 8 characters.'; err.style.display = 'block'; return; }
  if (pw !== pw2) { err.textContent = 'Passwords do not match.'; err.style.display = 'block'; return; }
  if (!terms) { err.textContent = 'Please accept the Terms of Service.'; err.style.display = 'block'; return; }
  // Optional university email domain check
  const requiredDomain = localStorage.getItem('uni_co_edu_domain');
  if (requiredDomain && email) {
    const emailDomain = email.split('@')[1]?.toLowerCase();
    if (emailDomain !== requiredDomain) {
      err.textContent = `This platform requires a @${requiredDomain} email address.`;
      err.style.display = 'block'; return;
    }
  }
  const btn = document.getElementById('sbtn'); btn.disabled = true; btn.textContent = 'Creating account...';
  try {
    let finalDeptId = dept;
    if (dept === '__custom__') {
      const customName = document.getElementById('su-custom-dept').value.trim();
      const code = customName.replace(/[^A-Z]/gi, '').slice(0, 5).toUpperCase() || 'CUST';
      const customDept = { id: StorageEngine.uid(), name: customName, code, colorHex: '#534AB7', featureKey: null, custom: true, createdAt: StorageEngine.now() };
      await StorageEngine.put('departments', customDept);
      finalDeptId = customDept.id;
    }
    S.user = await StorageEngine.signup({ fullName: `${fn} ${ln}`, email, phone, password: pw, departmentId: finalDeptId });
    renderShell();
    await go('dashboard');
    toast(`Welcome to uni-co, ${fn}! 🎉`, 'success');
    // Show onboarding modal for brand-new users
    setTimeout(() => showOnboarding(), 800);
  } catch (e) { err.textContent = e.message; err.style.display = 'block'; btn.disabled = false; btn.textContent = 'Create account'; }
}

/* ── Dashboard ──────────────────────────────────────────────────────── */
/* ── Date helpers — extended ───────────────────────────────────────── */
const isThisWeek = (d) => {
  if (!d) return false;
  const now = new Date(), target = new Date(d);
  if (isOD(d) || isTD(d)) return false; // already handled separately
  const diffMs = target - now;
  const diffDays = diffMs / (1000 * 60 * 60 * 24);
  return diffDays > 0 && diffDays <= 7;
};
const isNextWeek = (d) => {
  if (!d) return false;
  const now = new Date(), target = new Date(d);
  if (isOD(d) || isTD(d) || isThisWeek(d)) return false;
  const diffDays = (target - now) / (1000 * 60 * 60 * 24);
  return diffDays > 7 && diffDays <= 14;
};

/* ── Build the "due soon" task list ───────────────────────────────── */
function buildDueSoonTasks(enriched) {
  // Only tasks from ACTIVE (non-archived) projects
  const allTasks = enriched
    .filter(p => p.status !== 'ARCHIVED')
    .flatMap(p => (p.tasks || []).map(t => ({ ...t, _ptitle: p.title, _pid: p.id })));

  // Bucket by urgency — MUST have a due date, MUST not be done
  const overdue   = allTasks.filter(t => t.status !== 'DONE' && isOD(t.dueDate));
  const today     = allTasks.filter(t => t.status !== 'DONE' && isTD(t.dueDate));
  const thisWeek  = allTasks.filter(t => t.status !== 'DONE' && isThisWeek(t.dueDate));
  const nextWeek  = allTasks.filter(t => t.status !== 'DONE' && isNextWeek(t.dueDate));
  // Tasks with no due date are EXCLUDED — they don't belong in "due soon"

  return { overdue, today, thisWeek, nextWeek, all: [...overdue, ...today, ...thisWeek, ...nextWeek] };
}

async function showDashboard() {
  const m = document.getElementById('main');
  try {
  const [_rawProjects, depts] = await Promise.all([
    S.user.isDemo
      ? StorageEngine.getAll('projects').then(ps => ps.filter(p => p.status !== 'ARCHIVED'))
      : StorageEngine.getMyProjects(S.user.id),
    StorageEngine.getDepts()
  ]);
  const projects = _rawProjects;
  const enriched = await Promise.all(projects.map(p => StorageEngine.getProject(p.id)));
  const allTasksFlat = enriched.flatMap(p => (p.tasks || []).map(t => ({ ...t, _ptitle: p.title })));
  const done = allTasksFlat.filter(t => t.status === 'DONE');
  const { overdue, today, thisWeek, nextWeek, all: dueTasks } = buildDueSoonTasks(enriched);
  const hr = new Date().getHours();
  const greet = hr < 12 ? 'Good morning' : hr < 17 ? 'Good afternoon' : 'Good evening';

  // Greeting urgency signal
  let urgencyNote = '';
  if (overdue.length) urgencyNote = `<span style="font-size:15px;font-weight:400;color:var(--err)"> — ${overdue.length} overdue</span>`;
  else if (today.length) urgencyNote = `<span style="font-size:15px;font-weight:400;color:var(--tx2)"> — ${today.length} due today</span>`;

  m.innerHTML = `<div class="pg stagger">
    <div class="ph">
      <h1>${greet}, ${esc(S.user.fullName.split(' ')[0])}${urgencyNote}</h1>
      <button class="btn btn-primary" onclick="openNewProject(this)">${I.pl} New project</button>
    </div>
    <div class="stats">
      <div class="stat"><div class="stat-ic" style="background:var(--brand-l);color:var(--brand)">${I.fo}</div><div class="stat-lbl">Active projects</div><div class="stat-val">${projects.length}</div><div class="stat-sub">${enriched.filter(p => p.isOpenCollab).length} open collab</div></div>
      <div class="stat"><div class="stat-ic" style="background:#FAEEDA;color:#633806">${I.be}</div><div class="stat-lbl">Due today</div><div class="stat-val">${today.length}</div><div class="stat-sub" style="color:${overdue.length ? 'var(--err)' : 'var(--tx3)'}">${overdue.length ? `${overdue.length} overdue` : 'Nothing overdue ✓'}</div></div>
      <div class="stat"><div class="stat-ic" style="background:#EAF3DE;color:#27500A">${I.ck}</div><div class="stat-lbl">Completed tasks</div><div class="stat-val">${done.length}</div><div class="stat-sub">all time</div></div>
      <div class="stat"><div class="stat-ic" style="background:#E6F1FB;color:#0C447C">${I.db}</div><div class="stat-lbl">Departments</div><div class="stat-val">${new Set(projects.map(p => p.departmentId)).size}</div><div class="stat-sub">involved</div></div>
    </div>
    <h2 style="margin-bottom:10px">My projects</h2>
    ${enriched.length === 0
      ? `<div class="empty"><div class="emico">${I.fo}</div><p style="font-weight:600;margin-bottom:6px">No projects yet</p><button class="btn btn-primary" onclick="openNewProject(this)">${I.pl} New project</button></div>`
      : `<div class="pgrid">${enriched.map(p => pcrd(p)).join('')}</div>`}
    ${renderDueSoonSection(overdue, today, thisWeek, nextWeek)}
    ${renderActivityFeed(enriched)}
  </div>`;
  } catch(e) {
    console.error('Dashboard error:', e);
    m.innerHTML = `<div class="pg"><div class="empty"><div class="emico">⚠</div><p style="font-weight:600">Something went wrong loading the dashboard.</p><button class="btn btn-primary" onclick="go('dashboard')" style="margin-top:12px">Retry</button></div></div>`;
  }
}

function renderDueSoonSection(overdue, today, thisWeek, nextWeek) {
  const all = [...overdue, ...today, ...thisWeek, ...nextWeek];
  if (all.length === 0) return '';

  const bands = [
    { label: '🔴 Overdue',       tasks: overdue,  labelCol: 'var(--err)' },
    { label: '🟡 Due today',     tasks: today,    labelCol: 'var(--warn)' },
    { label: '📅 This week',     tasks: thisWeek, labelCol: 'var(--brand)' },
    { label: '🗓 Next week',     tasks: nextWeek, labelCol: 'var(--tx2)' },
  ].filter(b => b.tasks.length > 0);

  return `<div style="margin-top:24px">
    <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:12px">
      <h2>Tasks due soon <span style="font-size:13px;font-weight:400;color:var(--tx3)">${all.length} task${all.length !== 1 ? 's' : ''}</span></h2>
    </div>
    <div id="due-soon-list" style="background:var(--sur);border:1px solid var(--bor);border-radius:var(--rl);overflow:hidden">
      ${bands.map(band => `
        <div data-bandheader="1" style="padding:8px 16px 4px;background:var(--bg2);border-bottom:1px solid var(--bor)">
          <span style="font-size:11px;font-weight:700;color:${band.labelCol};letter-spacing:0.04em">${band.label}</span>
        </div>
        ${band.tasks.map(t => taskrow(t)).join('')}
      `).join('')}
    </div>
  </div>`;
}

/* ── University email domain ─────────────────────────────────────────── */
window.saveEduDomain = function() {
  const val = document.getElementById('edu-domain')?.value?.trim().toLowerCase().replace(/^@/, '');
  if (val) {
    localStorage.setItem('uni_co_edu_domain', val);
    toast(`Domain restricted to @${val}`, 'success');
  } else {
    localStorage.removeItem('uni_co_edu_domain');
    toast('Domain restriction cleared', 'success');
  }
  showSettings(); // re-render to show updated status
};

/* ── Export Tasks to PDF ────────────────────────────────────────────── */
function exportTasksPDF() {
  const p = window._wsProject;
  if (!p) return;
  const tasks = p.tasks || [];
  const members = p.members || [];
  const cols = [
    { k: 'TODO', label: 'To Do' },
    { k: 'IN_PROGRESS', label: 'In Progress' },
    { k: 'DONE', label: 'Done' },
  ];

  const colHTML = cols.map(col => {
    const colTasks = tasks.filter(t => t.status === col.k);
    const rows = colTasks.length === 0
      ? '<tr><td colspan="4" style="color:#999;font-style:italic;padding:8px">No tasks</td></tr>'
      : colTasks.map(t => {
          const assignee = members.find(m => m.userId === t.assigneeId)?.user?.fullName || '—';
          const due = t.dueDate ? new Date(t.dueDate).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' }) : '—';
          const pri = t.priority || 'MEDIUM';
          const priColor = pri === 'HIGH' ? '#e53e3e' : pri === 'LOW' ? '#718096' : '#805ad5';
          return `<tr>
            <td style="padding:8px;border-bottom:1px solid #eee">${t.title}</td>
            <td style="padding:8px;border-bottom:1px solid #eee;color:${priColor};font-weight:600;font-size:11px">${pri}</td>
            <td style="padding:8px;border-bottom:1px solid #eee;color:#555">${assignee}</td>
            <td style="padding:8px;border-bottom:1px solid #eee;color:#555">${due}</td>
          </tr>`;
        }).join('');
    return `<div style="margin-bottom:24px">
      <div style="font-size:13px;font-weight:700;color:#534AB7;margin-bottom:8px;text-transform:uppercase;letter-spacing:0.05em">${col.label} (${colTasks.length})</div>
      <table style="width:100%;border-collapse:collapse;font-size:12px">
        <thead><tr style="background:#f5f5f5">
          <th style="padding:8px;text-align:left;border-bottom:2px solid #ddd">Task</th>
          <th style="padding:8px;text-align:left;border-bottom:2px solid #ddd">Priority</th>
          <th style="padding:8px;text-align:left;border-bottom:2px solid #ddd">Assignee</th>
          <th style="padding:8px;text-align:left;border-bottom:2px solid #ddd">Due</th>
        </tr></thead>
        <tbody>${rows}</tbody>
      </table>
    </div>`;
  }).join('');

  const done = tasks.filter(t => t.status === 'DONE').length;
  const pct  = tasks.length ? Math.round(done / tasks.length * 100) : 0;
  const date = new Date().toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' });

  const html = `<!DOCTYPE html><html><head><meta charset="utf-8">
    <title>${p.title} — Task Board</title>
    <style>
      body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; margin: 40px; color: #1a1a2e; }
      h1 { font-size: 22px; color: #534AB7; margin-bottom: 4px; }
      .meta { font-size: 12px; color: #777; margin-bottom: 8px; }
      .progress { height: 6px; background: #eee; border-radius: 3px; margin-bottom: 28px; }
      .progress-fill { height: 100%; background: #534AB7; border-radius: 3px; width: ${pct}%; }
    </style>
  </head><body>
    <h1>${p.title}</h1>
    <div class="meta">Exported ${date} · ${tasks.length} tasks · ${pct}% complete</div>
    <div class="progress"><div class="progress-fill"></div></div>
    ${colHTML}
  </body></html>`;

  const win = window.open('', '_blank');
  if (!win) { toast('Allow popups to export PDF', 'error'); return; }
  win.document.write(html);
  win.document.close();
  win.focus();
  setTimeout(() => { win.print(); }, 400);
}

/* ── Global Search ─────────────────────────────────────────────────── */
async function openGlobalSearch() {
  const existing = document.getElementById('global-search-modal');
  if (existing) { existing.querySelector('#gs-input')?.focus(); return; }

  const modal = document.createElement('div');
  modal.id = 'global-search-modal';
  modal.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,0.55);z-index:400;display:flex;align-items:flex-start;justify-content:center;padding:60px 16px 16px;backdrop-filter:blur(4px)';
  modal.innerHTML = `
    <div style="background:var(--sur);border:1px solid var(--bor);border-radius:var(--rl);width:100%;max-width:560px;box-shadow:0 12px 48px rgba(0,0,0,0.2);overflow:hidden">
      <div style="display:flex;align-items:center;gap:10px;padding:14px 16px;border-bottom:1px solid var(--bor)">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--tx3)" stroke-width="2"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
        <input id="gs-input" placeholder="Search tasks, files, messages…"
          style="flex:1;background:none;border:none;outline:none;font-size:15px;color:var(--tx);font-family:inherit"
          oninput="runGlobalSearch(this.value)" autocomplete="off">
        <button onclick="document.getElementById('global-search-modal').remove()"
          style="background:none;border:none;color:var(--tx3);cursor:pointer;font-size:18px;padding:0;line-height:1">✕</button>
      </div>
      <div id="gs-results" style="max-height:60vh;overflow-y:auto;padding:8px 0">
        <div style="padding:24px;text-align:center;color:var(--tx3);font-size:13px">Start typing to search…</div>
      </div>
    </div>`;

  modal.addEventListener('click', e => { if (e.target === modal) modal.remove(); });
  document.body.appendChild(modal);
  setTimeout(() => document.getElementById('gs-input')?.focus(), 50);
}

async function runGlobalSearch(query) {
  const box = document.getElementById('gs-results');
  if (!box) return;
  const q = query.trim().toLowerCase();
  if (q.length < 2) {
    box.innerHTML = '<div style="padding:24px;text-align:center;color:var(--tx3);font-size:13px">Start typing to search…</div>';
    return;
  }

  box.innerHTML = '<div style="padding:16px;text-align:center;color:var(--tx3);font-size:13px">Searching…</div>';

  try {
    const projects = await StorageEngine.getMyProjects(S.user.id);
    const enriched = await Promise.all(projects.map(p => StorageEngine.getProject(p.id)));

    const results = [];

    enriched.forEach(p => {
      // Tasks
      (p.tasks || []).filter(t => t.title?.toLowerCase().includes(q) || t.description?.toLowerCase().includes(q)).forEach(t => {
        results.push({ type: 'task', icon: '📋', title: t.title, sub: p.title, pid: p.id, action: () => { document.getElementById('global-search-modal')?.remove(); go('ws', { id: p.id }); setTimeout(() => openTaskDetail(t.id), 600); } });
      });
      // Files
      (p.files || []).filter(f => f.filename?.toLowerCase().includes(q)).forEach(f => {
        results.push({ type: 'file', icon: '📎', title: f.filename, sub: p.title, pid: p.id, action: () => { document.getElementById('global-search-modal')?.remove(); go('ws', { id: p.id }); } });
      });
      // Messages
      (p.messages || []).filter(m => m.content?.toLowerCase().includes(q)).forEach(m => {
        const snippet = m.content.length > 60 ? m.content.slice(0, 60) + '…' : m.content;
        results.push({ type: 'message', icon: '💬', title: snippet, sub: p.title, pid: p.id, action: () => { document.getElementById('global-search-modal')?.remove(); go('ws', { id: p.id }); } });
      });
    });

    if (results.length === 0) {
      box.innerHTML = `<div style="padding:24px;text-align:center;color:var(--tx3);font-size:13px">No results for "<b>${esc(query)}</b>"</div>`;
      return;
    }

    box.innerHTML = results.slice(0, 20).map(r => `
      <div onclick="(${r.action.toString()})()" style="display:flex;align-items:center;gap:10px;padding:10px 16px;cursor:pointer;transition:background 0.1s"
        onmouseover="this.style.background='var(--bg2)'" onmouseout="this.style.background=''">
        <div style="width:28px;height:28px;border-radius:7px;background:var(--bg2);display:flex;align-items:center;justify-content:center;font-size:13px;flex-shrink:0">${r.icon}</div>
        <div style="flex:1;min-width:0">
          <div style="font-size:13px;color:var(--tx);font-weight:500;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">${esc(r.title)}</div>
          <div style="font-size:11px;color:var(--tx3)">${esc(r.sub)} · ${r.type}</div>
        </div>
      </div>`).join('');
  } catch(e) {
    box.innerHTML = '<div style="padding:16px;text-align:center;color:var(--err);font-size:13px">Search failed</div>';
  }
}

/* ── Activity Feed ─────────────────────────────────────────────────── */
const _dismissedActivities = new Set();

function dismissActivity(idx) {
  _dismissedActivities.add(idx);
  const item = document.getElementById('activity-item-' + idx);
  if (item) item.remove();
  const feed = document.getElementById('activity-feed-list');
  if (feed && feed.children.length === 0) {
    const wrap = document.getElementById('activity-feed-wrap');
    if (wrap) wrap.remove();
  }
}

function clearAllActivities() {
  const wrap = document.getElementById('activity-feed-wrap');
  if (wrap) wrap.remove();
  const items = document.querySelectorAll('[id^="activity-item-"]');
  items.forEach(el => {
    const idx = el.id.replace('activity-item-', '');
    _dismissedActivities.add(idx);
  });
}

function renderActivityFeed(projects) {
  // Build activity events from tasks and messages across all projects
  const events = [];
  const now = Date.now();
  const cutoff = now - 7 * 24 * 60 * 60 * 1000; // last 7 days

  projects.forEach(p => {
    const members = p.members || [];
    const getMember = (userId) => members.find(m => m.userId === userId);

    // Task events
    (p.tasks || []).forEach(t => {
      const ts = new Date(t.updatedAt || t.createdAt).getTime();
      if (ts < cutoff) return;
      const actor = getMember(t.assigneeId || '')?.user?.fullName || 'Someone';
      if (t.status === 'DONE') {
        events.push({ ts, icon: '✅', text: `<b>${esc(actor)}</b> completed <b>${esc(t.title)}</b>`, project: p.title, pid: p.id });
      } else if (t.createdAt === t.updatedAt || !t.updatedAt) {
        events.push({ ts, icon: '📋', text: `New task <b>${esc(t.title)}</b> added`, project: p.title, pid: p.id });
      }
    });

    // File events
    (p.files || []).forEach(f => {
      const ts = new Date(f.createdAt).getTime();
      if (ts < cutoff) return;
      const actor = getMember(f.uploadedById)?.user?.fullName || 'Someone';
      events.push({ ts, icon: '📎', text: `<b>${esc(actor)}</b> uploaded <b>${esc(f.filename)}</b>`, project: p.title, pid: p.id });
    });

    // Member join events
    (p.members || []).forEach(m => {
      const ts = new Date(m.joinedAt).getTime();
      if (ts < cutoff) return;
      const name = m.user?.fullName || 'Someone';
      events.push({ ts, icon: '👥', text: `<b>${esc(name)}</b> joined the project`, project: p.title, pid: p.id });
    });
  });

  if (events.length === 0) return '';

  events.sort((a, b) => b.ts - a.ts);
  const recent = events.slice(0, 12);

  const rows = recent.map((e, i) => {
    if (_dismissedActivities.has(String(i))) return '';
    const ago = fmtAgo(e.ts);
    return `<div id="activity-item-${i}" style="display:flex;align-items:flex-start;gap:10px;padding:10px 0;border-bottom:1px solid var(--bor)">
      <div style="width:28px;height:28px;border-radius:8px;background:var(--bg2);display:flex;align-items:center;justify-content:center;font-size:14px;flex-shrink:0;cursor:pointer" onclick="dismissActivity('${i}');go('ws',{id:'${e.pid}'})">${e.icon}</div>
      <div style="flex:1;min-width:0;cursor:pointer" onclick="dismissActivity('${i}');go('ws',{id:'${e.pid}'})">
        <div style="font-size:13px;color:var(--tx);line-height:1.4">${e.text}</div>
        <div style="font-size:11px;color:var(--tx3);margin-top:2px">${esc(e.project)} · ${ago}</div>
      </div>
      <div onclick="dismissActivity('${i}')" title="Remove" style="flex-shrink:0;width:20px;height:20px;display:flex;align-items:center;justify-content:center;border-radius:6px;color:var(--tx3);cursor:pointer;font-size:14px;line-height:1;transition:background 0.15s" onmouseover="this.style.background='var(--bg3)'" onmouseout="this.style.background=''">&times;</div>
    </div>`;
  }).join('');

  if (!rows.trim()) return '';

  return `<div id="activity-feed-wrap" style="margin-top:24px">
    <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:10px">
      <h2 style="margin:0">Recent activity</h2>
      <button onclick="clearAllActivities()" style="font-size:12px;color:var(--tx3);background:none;border:none;cursor:pointer;padding:4px 8px;border-radius:6px;transition:background 0.15s" onmouseover="this.style.background='var(--bg3)'" onmouseout="this.style.background=''">Clear all</button>
    </div>
    <div id="activity-feed-list" style="background:var(--sur);border:1px solid var(--bor);border-radius:var(--rl);padding:0 16px">
      ${rows}
    </div>
  </div>`;
}

function fmtAgo(ts) {
  const diff = Date.now() - ts;
  const m = Math.floor(diff / 60000);
  if (m < 1) return 'just now';
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  const d = Math.floor(h / 24);
  return `${d}d ago`;
}

/* ── Project Card ──────────────────────────────────────────────────── */
function pcrd(p) {
  const tasks = p.tasks || [], done = tasks.filter(t => t.status === 'DONE').length;
  const pct = tasks.length ? Math.round(done / tasks.length * 100) : 0;
  const col = p.department?.colorHex || '#534AB7';
  const isLead = p.members?.some(m => m.userId === S.user.id && m.role === 'LEAD');
  return `<div class="pcrd card-c ${p.isOpenCollab ? 'open-c' : ''}" style="position:relative">
    <div onclick="go('ws',{id:'${p.id}'})" style="cursor:pointer">
      <div class="pch">
        <div class="ptitle">${esc(p.title)}</div>
        <div style="display:flex;gap:4px;flex-shrink:0;flex-wrap:wrap">
          <span class="badge" style="background:${col}22;color:${col}">${p.department?.code || ''}</span>
          ${p.isOpenCollab ? '<span class="badge b-open">Open</span>' : ''}
        </div>
      </div>
      ${p.description ? `<div class="pdesc">${esc(p.description)}</div>` : ''}
      <div class="prog" style="margin-bottom:10px"><div class="prog-fill" style="width:${pct}%;background:${col}"></div></div>
      <div class="pfoot">
        ${avStack(p.members || [])}
        ${p.dueDate ? `<span class="pdue" style="${isOD(p.dueDate) ? 'color:var(--err)' : ''}">${isOD(p.dueDate) ? 'Overdue · ' : ''}Due ${fmtD(p.dueDate)}</span>` : ''}
      </div>
    </div>
    ${isLead ? `<div style="position:absolute;top:12px;right:12px" onclick="event.stopPropagation()">
      <div class="pcrd-menu-btn" onclick="togglePcrdMenu('menu-${p.id}')" title="Project options" style="width:26px;height:26px;border-radius:6px;display:flex;align-items:center;justify-content:center;color:var(--tx3);cursor:pointer;font-size:17px;line-height:1;background:var(--sur);border:1px solid var(--bor);transition:all 0.15s" onmouseover="this.style.background='var(--bg3)'" onmouseout="this.style.background='var(--sur)'">⋯</div>
      <div id="menu-${p.id}" style="display:none;position:absolute;top:30px;right:0;background:var(--sur);border:1px solid var(--bor);border-radius:10px;box-shadow:0 8px 24px rgba(0,0,0,0.12);z-index:50;min-width:160px;overflow:hidden">
        <div onclick="go('ws',{id:'${p.id}'})" style="padding:9px 14px;font-size:13px;cursor:pointer;color:var(--tx)" onmouseover="this.style.background='var(--bg2)'" onmouseout="this.style.background=''">✏️ Open workspace</div>
        <div onclick="archiveProj('${p.id}')" style="padding:9px 14px;font-size:13px;cursor:pointer;color:var(--warn)" onmouseover="this.style.background='var(--warn-bg)'" onmouseout="this.style.background=''">📦 Archive project</div>
        <div style="height:1px;background:var(--bor)"></div>
        <div onclick="leaveProj('${p.id}','${esc(p.title)}')" style="padding:9px 14px;font-size:13px;cursor:pointer;color:var(--tx2)" onmouseover="this.style.background='var(--bg2)'" onmouseout="this.style.background=''">Leave project</div>
        <div onclick="deleteProj('${p.id}','${esc(p.title)}')" style="padding:9px 14px;font-size:13px;cursor:pointer;color:var(--err)" onmouseover="this.style.background='var(--err-bg)'" onmouseout="this.style.background=''">🗑 Delete project</div>
      </div>
    </div>` : `<div style="position:absolute;top:12px;right:12px" onclick="event.stopPropagation()">
      <div class="pcrd-menu-btn" onclick="togglePcrdMenu('menu-${p.id}')" title="Project options" style="width:26px;height:26px;border-radius:6px;display:flex;align-items:center;justify-content:center;color:var(--tx3);cursor:pointer;font-size:17px;line-height:1;background:var(--sur);border:1px solid var(--bor);transition:all 0.15s" onmouseover="this.style.background='var(--bg3)'" onmouseout="this.style.background='var(--sur)'">⋯</div>
      <div id="menu-${p.id}" style="display:none;position:absolute;top:30px;right:0;background:var(--sur);border:1px solid var(--bor);border-radius:10px;box-shadow:0 8px 24px rgba(0,0,0,0.12);z-index:50;min-width:160px;overflow:hidden">
        <div onclick="go('ws',{id:'${p.id}'})" style="padding:9px 14px;font-size:13px;cursor:pointer;color:var(--tx)" onmouseover="this.style.background='var(--bg2)'" onmouseout="this.style.background=''">Open workspace</div>
        <div style="height:1px;background:var(--bor)"></div>
        <div onclick="leaveProj('${p.id}','${esc(p.title)}')" style="padding:9px 14px;font-size:13px;cursor:pointer;color:var(--err)" onmouseover="this.style.background='var(--err-bg)'" onmouseout="this.style.background=''">Leave project</div>
      </div>
    </div>`}
  </div>`;
}

function togglePcrdMenu(id) {
  document.querySelectorAll('[id^="menu-"]').forEach(m => { if (m.id !== id) m.style.display = 'none'; });
  const el = document.getElementById(id);
  if (el) el.style.display = el.style.display === 'none' ? 'block' : 'none';
}
document.addEventListener('click', () => document.querySelectorAll('[id^="menu-"]').forEach(m => m.style.display = 'none'));

async function leaveProj(id, title) {
  if (demoGuard()) return;
  const p = await StorageEngine.getProject(id);
  const isLead = p?.members?.some(m => m.userId === S.user.id && m.role === 'LEAD');
  if (isLead) {
    const otherLeads = p.members.filter(m => m.role === 'LEAD' && m.userId !== S.user.id);
    if (otherLeads.length === 0) {
      toast('You are the only Lead. Transfer leadership to a member before leaving.', 'error');
      return;
    }
  }
  if (!confirm(`Leave "${title}"? You will lose access unless you are re-invited.`)) return;
  try {
    const mems = await StorageEngine.getAll('members', 'projectId', id);
    const myMem = mems.find(m => m.userId === S.user.id);
    if (myMem) await StorageEngine.del('members', myMem.id);
    const perms = await StorageEngine.getAll('permissions', 'projectId', id);
    const myPerm = perms.find(p => p.userId === S.user.id);
    if (myPerm) await StorageEngine.del('permissions', myPerm.id);
    toast('You have left the project.', 'success');
    await go('projects');
  } catch(e) { toast(e.message, 'error'); }
}

async function archiveProj(id) {
  if (demoGuard()) return;
  if (!confirm('Archive this project? It will be hidden from your projects list.')) return;
  await StorageEngine.archiveProject(id);
  toast('Project archived', 'info');
  await showProjects();
}

async function deleteProj(id, title) {
  if (demoGuard()) return;
  if (!confirm(`Permanently delete "${title}"?\n\nThis will delete all tasks, files, messages, and members. This cannot be undone.`)) return;
  await StorageEngine.deleteProject(id);
  toast('Project deleted', 'success');
  await showProjects();
}

/* ── Task Row (Dashboard) — with clickable checkbox ─────────────────── */
function taskrow(t) {
  const isDone = t.status === 'DONE';
  const od = isOD(t.dueDate), td = isTD(t.dueDate), tw = isThisWeek(t.dueDate);
  const badgeBg  = isDone ? 'var(--ok-bg)' : od ? 'var(--err-bg)' : td ? 'var(--warn-bg)' : tw ? 'var(--brand-l)' : 'var(--bg3)';
  const badgeCol = isDone ? 'var(--ok)'    : od ? 'var(--err)'    : td ? 'var(--warn)'    : tw ? 'var(--brand)'   : 'var(--tx2)';
  const badgeTxt = isDone ? 'Done' : od ? 'Overdue' : td ? 'Today' : fmtD(t.dueDate);
  return `<div data-taskrow="${t.id}" style="display:flex;align-items:center;gap:12px;padding:11px 16px;border-bottom:1px solid var(--bor);transition:background 0.15s,opacity 0.3s,max-height 0.3s;overflow:hidden;max-height:80px" onmouseover="this.style.background='var(--bg2)'" onmouseout="this.style.background=''">
    <div class="task-check ${isDone ? 'done' : ''}" data-tid="${t.id}" onclick="toggleTaskDone('${t.id}',this)" title="${isDone ? 'Mark incomplete' : 'Mark complete'}" style="width:18px;height:18px;border-radius:4px;border:2px solid ${isDone ? 'var(--brand)' : 'var(--bor2)'};background:${isDone ? 'var(--brand)' : 'transparent'};flex-shrink:0;display:flex;align-items:center;justify-content:center;color:#fff;font-size:11px;cursor:pointer;transition:all 0.2s;user-select:none">${isDone ? '✓' : ''}</div>
    <div style="flex:1;min-width:0" onclick="openTaskDetail('${t.id}')">
      <div style="font-size:13px;font-weight:500;transition:all 0.2s;${isDone ? 'text-decoration:line-through;color:var(--tx3)' : ''}">${esc(t.title)}</div>
      ${t._ptitle ? `<div style="font-size:11px;color:var(--tx3)">${esc(t._ptitle)}</div>` : ''}
    </div>
    <span style="font-size:11px;padding:2px 8px;border-radius:6px;white-space:nowrap;cursor:pointer;background:${badgeBg};color:${badgeCol}" onclick="openTaskDetail('${t.id}')">${badgeTxt}</span>
  </div>`;
}


async function toggleTaskDone(taskId, el) {
  const t = await StorageEngine.getTask(taskId);
  if (!t) return;
  const newStatus = t.status === 'DONE' ? 'TODO' : 'DONE';
  await StorageEngine.updateTask(taskId, { status: newStatus });

  const isDone = newStatus === 'DONE';
  const row = el.closest('[data-taskrow]');

  if (isDone) {
    // Animate the row out, then remove it
    el.style.background = 'var(--brand)';
    el.style.borderColor = 'var(--brand)';
    el.textContent = '✓';

    if (row) {
      row.style.transition = 'all 0.3s ease';
      row.style.opacity = '0';
      row.style.maxHeight = row.offsetHeight + 'px';
      requestAnimationFrame(() => {
        row.style.maxHeight = '0';
        row.style.paddingTop = '0';
        row.style.paddingBottom = '0';
      });
      setTimeout(() => {
        row.remove();
        // If a band header is now empty (no sibling task rows), remove it too
        document.querySelectorAll('#due-soon-list [data-bandheader]').forEach(header => {
          const next = header.nextElementSibling;
          if (!next || next.dataset.bandheader) header.remove();
        });
        // If the whole list is empty, remove the section
        const list = document.getElementById('due-soon-list');
        if (list && !list.querySelector('[data-taskrow]')) {
          list.closest('[id]')?.remove() || list.parentElement?.parentElement?.remove();
        }
      }, 320);
    }
    el.animate([{ transform: 'scale(1.35)' }, { transform: 'scale(1)' }], { duration: 220, easing: 'cubic-bezier(0.34,1.5,0.64,1)' });
    toast('Task done ✓', 'success');
  } else {
    // Unchecked: restore visual state in-place, task stays until next reload
    // (it no longer qualifies for this section, so refresh the whole section)
    el.style.background = 'transparent';
    el.style.borderColor = 'var(--bor2)';
    el.textContent = '';

    const titleEl = el.nextElementSibling?.querySelector('div');
    if (titleEl) { titleEl.style.textDecoration = ''; titleEl.style.color = ''; }

    const badge = el.parentElement?.querySelector('span:last-child');
    if (badge) {
      badge.textContent = isOD(t.dueDate) ? 'Overdue' : isTD(t.dueDate) ? 'Today' : isThisWeek(t.dueDate) ? fmtD(t.dueDate) : fmtD(t.dueDate);
      badge.style.background = isOD(t.dueDate) ? 'var(--err-bg)' : isTD(t.dueDate) ? 'var(--warn-bg)' : isThisWeek(t.dueDate) ? 'var(--brand-l)' : 'var(--bg3)';
      badge.style.color = isOD(t.dueDate) ? 'var(--err)' : isTD(t.dueDate) ? 'var(--warn)' : isThisWeek(t.dueDate) ? 'var(--brand)' : 'var(--tx2)';
    }
    toast('Task marked incomplete');
  }
}

/* ── Projects List ─────────────────────────────────────────────────── */
async function showProjects() {
  const m = document.getElementById('main');
  const projects = await StorageEngine.getMyProjects(S.user.id);
  const enriched = await Promise.all(projects.map(p => StorageEngine.getProject(p.id)));
  m.innerHTML = `<div class="pg stagger">
    <div class="ph">
      <h1>My projects <span style="font-size:14px;color:var(--tx3);font-weight:400">${enriched.length}</span></h1>
      <div style="display:flex;gap:8px">
        <button class="btn" onclick="M.open('join-key')">${I.ky} Join with key</button>
        <button class="btn btn-primary" onclick="openNewProject(this)">${I.pl} New project</button>
      </div>
    </div>
    ${enriched.length === 0 ? `<div class="empty">
          <div class="emico">${I.fo}</div>
          <h3 style="font-weight:700;margin-bottom:6px;color:var(--tx)">No projects yet</h3>
          <p style="color:var(--tx3);margin-bottom:18px;max-width:280px">Create your first project or join one with an invite key from a teammate.</p>
          <div style="display:flex;gap:8px;flex-wrap:wrap;justify-content:center">
            <button class="btn btn-primary" onclick="openNewProject(this)">${I.pl} Create project</button>
            <button class="btn btn-secondary" onclick="M.open('join-key')">${I.ky} Join with key</button>
          </div>
        </div>`
      : `<div class="pgrid">${enriched.map(p => pcrd(p)).join('')}</div>`}
  </div>`;
}

/* ── Explore with Fuzzy Search ─────────────────────────────────────── */
async function showExplore() {
  const m = document.getElementById('main');
  const depts = await StorageEngine.getDepts();
  let curDept = 'all', openOnly = false;

  async function render() {
    const q = document.getElementById('exp-q')?.value || '';
    const projects = await StorageEngine.getExplore(S.user.id, { dept: curDept, openOnly, q });
    const grid = document.getElementById('exp-grid');
    if (!grid) return;
    grid.innerHTML = projects.length === 0
      ? `<div class="empty" style="grid-column:1/-1"><div class="emico">${I.ex}</div><p>No projects found${q ? ` for "${esc(q)}"` : ''}</p></div>`
      : `<div class="pgrid stagger">${projects.map(p => `<div class="pcrd card-c ${p.isOpenCollab ? 'open-c' : ''}" onclick="expJoin('${p.id}',${p.isOpenCollab})">
        <div class="pch">
          <div class="ptitle">${esc(p.title)}</div>
          <div style="display:flex;gap:3px;flex-wrap:wrap;flex-shrink:0">
            <span class="badge" style="background:${(p.department?.colorHex || '#534AB7')}22;color:${p.department?.colorHex || '#534AB7'}">${p.department?.code || ''}</span>
            ${p.isOpenCollab ? '<span class="badge b-open">Open</span>' : ''}
          </div>
        </div>
        ${p.description ? `<div class="pdesc">${esc(p.description)}</div>` : ''}
        <div class="pfoot">
          <span style="font-size:12px;color:var(--tx2)">${(p.members || []).length} member${(p.members || []).length !== 1 ? 's' : ''}</span>
          <button class="btn btn-sm" onclick="event.stopPropagation();expJoin('${p.id}',${p.isOpenCollab})">${p.isOpenCollab ? 'Join' : 'Enter key'}</button>
        </div>
      </div>`).join('')}</div>`;
  }

  m.innerHTML = `<div class="pg">
    <div class="ph"><h1>Explore</h1><button class="btn" onclick="M.open('join-key')">${I.ky} Enter invite key</button></div>
    <div class="sbar">
      <div class="swrap"><span class="sico">${I.ex}</span><input class="sinput" id="exp-q" placeholder="Search projects (fuzzy)..." oninput="expRender()"></div>
      <button class="btn btn-primary" onclick="expRender()">Search</button>
    </div>
    <div class="fchips-row">
      <span class="fcp on" data-d="all" onclick="expDept(this,'all')">All departments</span>
      ${depts.map(d => `<span class="fcp" data-d="${d.code}" onclick="expDept(this,'${d.code}')">${d.name}</span>`).join('')}
      <span class="fcp" id="open-fp" onclick="expToggleOpen(this)" style="margin-left:auto">Open collab only</span>
    </div>
    <div id="exp-grid" style="display:contents"><div class="pgrid">${Array(4).fill('<div class="skel skel-card"></div>').join('')}</div></div>
  </div>`;

  window.expRender = render;
  window.expDept = (el, d) => { curDept = d; document.querySelectorAll('.fcp[data-d]').forEach(c => c.classList.remove('on')); el.classList.add('on'); render(); };
  window.expToggleOpen = (el) => { openOnly = !openOnly; el.classList.toggle('on'); render(); };
  await render();
}

async function expJoin(pid, isOpen) {
  if (demoGuard()) return;
  try {
    if (isOpen) {
      await StorageEngine.joinOpen(pid, S.user.id);
      toast('Joined project!', 'success');
      go('ws', { id: pid });
    } else {
      document.getElementById('jk-input').value = '';
      M.open('join-key');
    }
  } catch (e) { toast(e.message, 'error'); }
}

/* ── Notifications ─────────────────────────────────────────────────── */
async function showNotifs() {
  const m = document.getElementById('main');
  const notifs = await StorageEngine.getNotifs(S.user.id);
  await StorageEngine.markAllRead(S.user.id);
  updateNBadge();
  m.innerHTML = `<div class="pg stagger">
    <div class="ph"><h1>Notifications</h1><button class="btn" onclick="go('notifs')">Refresh</button></div>
    <div style="background:var(--sur);border:1px solid var(--bor);border-radius:var(--rl);overflow:hidden">
      ${notifs.length === 0 ? `<div class="empty"><div class="emico">${I.be}</div><p>All caught up!</p></div>`
        : notifs.map(n => `<div class="nitem ${n.read ? '' : 'unr'}">
          ${!n.read ? '<div class="ndot"></div>' : '<div style="width:7px;flex-shrink:0"></div>'}
          <div><div class="ntx">${esc(n.text)}</div><div class="ntm">${fmtD(n.createdAt)}</div></div>
        </div>`).join('')}
    </div>
  </div>`;
}

/* ── Invite Friends Page ─────────────────────────────────────────── */
async function showInvitePage() {
  if (demoGuard()) return;
  const m = document.getElementById('main');
  const signupUrl = `${window.location.origin}`;
  const u = S.user;

  const shareMsg = `Hey! I've been using uni-co for university project collaboration — tasks, files, chat, and department-specific tools all in one place. Join me here: ${signupUrl}`;

  const canShare = !!navigator.share;

  m.innerHTML = `<div class="pg stagger" style="max-width:560px">
    <div class="ph"><h1>Invite to uni-co</h1></div>

    <!-- Hero -->
    <div class="card" style="text-align:center;padding:32px 24px;background:linear-gradient(135deg,var(--brand-bg) 0%,var(--bg2) 100%);border-color:var(--brand-bg)">
      <div style="font-size:40px;margin-bottom:12px">👥</div>
      <div style="font-size:18px;font-weight:700;color:var(--tx);margin-bottom:8px">Bring your team to uni-co</div>
      <div style="font-size:14px;color:var(--tx2);line-height:1.6;max-width:380px;margin:0 auto">
        Share the platform with classmates, labmates, or anyone collaborating on university work.
      </div>
    </div>

    <!-- Signup link -->
    <div class="card">
      <div style="font-size:13px;font-weight:600;color:var(--tx);margin-bottom:10px">Platform link</div>
      <div style="display:flex;gap:8px;align-items:center">
        <div style="flex:1;background:var(--bg2);border:1px solid var(--bor);border-radius:10px;padding:11px 14px;font-family:var(--mono);font-size:13px;color:var(--tx2);overflow:hidden;white-space:nowrap;text-overflow:ellipsis">${esc(signupUrl)}</div>
        <button class="btn btn-primary" onclick="copyInviteLink()" id="copy-btn" style="flex-shrink:0;min-width:80px">Copy</button>
      </div>
      <div style="font-size:12px;color:var(--tx3);margin-top:8px">Anyone with this link can sign up for a free account.</div>
    </div>

    <!-- Share options -->
    <div class="card">
      <div style="font-size:13px;font-weight:600;color:var(--tx);margin-bottom:14px">Share via</div>
      <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(130px,1fr));gap:10px">

        ${canShare ? `
        <button class="btn" onclick="nativeShare()" style="flex-direction:column;gap:6px;padding:14px 10px;height:auto;min-height:70px;align-items:center;justify-content:center;font-size:12px;font-weight:500">
          <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><circle cx="18" cy="5" r="3"/><circle cx="6" cy="12" r="3"/><circle cx="18" cy="19" r="3"/><line x1="8.59" y1="13.51" x2="15.42" y2="17.49"/><line x1="15.41" y1="6.51" x2="8.59" y2="10.49"/></svg>
          Share
        </button>` : ''}

        <a href="mailto:?subject=Join me on uni-co&body=${encodeURIComponent(shareMsg)}" class="btn" style="flex-direction:column;gap:6px;padding:14px 10px;height:auto;min-height:70px;align-items:center;justify-content:center;font-size:12px;font-weight:500;text-decoration:none">
          <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/><polyline points="22,6 12,13 2,6"/></svg>
          Email
        </a>

        <a href="https://wa.me/?text=${encodeURIComponent(shareMsg)}" target="_blank" rel="noopener" class="btn" style="flex-direction:column;gap:6px;padding:14px 10px;height:auto;min-height:70px;align-items:center;justify-content:center;font-size:12px;font-weight:500;text-decoration:none">
          <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M21 11.5a8.38 8.38 0 0 1-.9 3.8 8.5 8.5 0 0 1-7.6 4.7 8.38 8.38 0 0 1-3.8-.9L3 21l1.9-5.7a8.38 8.38 0 0 1-.9-3.8 8.5 8.5 0 0 1 4.7-7.6 8.38 8.38 0 0 1 3.8-.9h.5a8.48 8.48 0 0 1 8 8v.5z"/></svg>
          WhatsApp
        </a>

        <a href="https://t.me/share/url?url=${encodeURIComponent(signupUrl)}&text=${encodeURIComponent('Join me on uni-co — university collaboration platform')}" target="_blank" rel="noopener" class="btn" style="flex-direction:column;gap:6px;padding:14px 10px;height:auto;min-height:70px;align-items:center;justify-content:center;font-size:12px;font-weight:500;text-decoration:none">
          <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><line x1="22" y1="2" x2="11" y2="13"/><polygon points="22 2 15 22 11 13 2 9 22 2"/></svg>
          Telegram
        </a>

        <button class="btn" onclick="copyShareMsg()" style="flex-direction:column;gap:6px;padding:14px 10px;height:auto;min-height:70px;align-items:center;justify-content:center;font-size:12px;font-weight:500">
          <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
          Copy message
        </button>
      </div>
    </div>

    <!-- What they get -->
    <div class="card">
      <div style="font-size:13px;font-weight:600;color:var(--tx);margin-bottom:14px">What your invite gets them</div>
      <div style="display:flex;flex-direction:column;gap:10px">
        ${[
          ['Free account', 'Sign up in under a minute — no payment required'],
          ['Project collaboration', 'Join your projects with an invite key'],
          ['Department tools', '12 specialised workstations for their subject'],
          ['Tasks, files & chat', 'Everything needed for university group work'],
        ].map(([title, desc]) => `
          <div style="display:flex;gap:12px;align-items:flex-start">
            <div style="width:20px;height:20px;border-radius:50%;background:var(--brand-bg);display:flex;align-items:center;justify-content:center;flex-shrink:0;margin-top:1px">
              <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="var(--brand)" stroke-width="3"><polyline points="20 6 9 17 4 12"/></svg>
            </div>
            <div>
              <div style="font-size:13px;font-weight:600;color:var(--tx)">${esc(title)}</div>
              <div style="font-size:12px;color:var(--tx2);margin-top:1px">${esc(desc)}</div>
            </div>
          </div>`).join('')}
      </div>
    </div>
  </div>`;

  window.copyInviteLink = async () => {
    try {
      await navigator.clipboard.writeText(signupUrl);
      const btn = document.getElementById('copy-btn');
      if (btn) { btn.textContent = 'Copied!'; btn.style.background = 'var(--ok)'; setTimeout(() => { btn.textContent = 'Copy'; btn.style.background = ''; }, 2000); }
    } catch { toast('Could not copy — please copy the link manually.', 'error'); }
  };

  window.copyShareMsg = async () => {
    try {
      await navigator.clipboard.writeText(shareMsg);
      toast('Message copied to clipboard', 'success');
    } catch { toast('Could not copy', 'error'); }
  };

  window.nativeShare = async () => {
    try {
      await navigator.share({ title: 'Join me on uni-co', text: shareMsg, url: signupUrl });
    } catch(e) { if (e.name !== 'AbortError') toast('Share failed', 'error'); }
  };
}

/* ── Settings (with Data Vault, Theme Picker, Glass, Permissions) ──── */
async function showSettings() {
  const m = document.getElementById('main');
  const depts = await StorageEngine.getDepts();
  let sec = 'profile';

  const sections = {
    profile: () => `
      <div class="setsec"><div class="setsec-t">Profile</div><div class="setsec-d">Your personal information and department.</div>
        <div style="display:flex;align-items:center;gap:14px;margin-bottom:18px;padding:14px;background:var(--bg2);border-radius:var(--rl)">${av(S.user, 'lg')}<div><div style="font-size:16px;font-weight:600">${esc(S.user.fullName)}</div><div style="font-size:13px;color:var(--tx2)">${esc(S.user.email || S.user.phone || '')} · ${esc(S.user.department?.name || '')}</div></div></div>
        <div class="frow">
          <div class="fg"><label class="fl" for="s-name">Full name</label><input class="fi" id="s-name" value="${esc(S.user.fullName)}"></div>
          <div class="fg"><label class="fl" for="s-dept">Department</label><select class="fi fi-select" id="s-dept">${depts.map(d => `<option value="${d.id}"${d.id === S.user.departmentId ? ' selected' : ''}>${esc(d.name)} (${esc(d.code)})</option>`).join('')}</select></div>
        </div>
        <div class="fg"><label class="fl" for="s-bio">Bio</label><textarea class="fi fi-ta" id="s-bio" rows="3">${esc(S.user.bio || '')}</textarea></div>
        <div class="frow">
          <div class="fg"><label class="fl" for="s-gh">GitHub</label><input class="fi" id="s-gh" value="${esc(S.user.gh || '')}" placeholder="https://github.com/..."></div>
          <div class="fg"><label class="fl" for="s-li">LinkedIn</label><input class="fi" id="s-li" value="${esc(S.user.li || '')}" placeholder="https://linkedin.com/in/..."></div>
        </div>
        <button class="btn btn-primary" onclick="saveProfile()">Save changes</button>
      </div>`,

    appearance: () => `
      <div class="setsec"><div class="setsec-t">Appearance</div><div class="setsec-d">Switch between themes and toggle glassmorphism.</div>
        <div class="setrow"><div><div class="setrow-l">Glassmorphism</div><div class="setrow-d">Blurred translucent surfaces</div></div>
          <label class="tog"><input type="checkbox" ${S.glass ? 'checked' : ''} onchange="toggleGlass(this.checked);reRenderAppear()"><span class="tslider"></span></label>
        </div>
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-top:16px">
          ${[
            ['light', 'Default', '#fff', '#E4E3F0', '#534AB7'],
            ['dark', 'Dark', '#0F0E1A', '#2D2B45', '#7F77DD'],
            ['neon', 'Neon Protocol', '#0A0A14', '#1E1E40', '#00FFC8'],
            ['zen', 'Zen Minimalist', '#FAFAF7', '#E5DED3', '#8B7355'],
            ['cosmic', 'Cosmic Horizon', '#0D0B1E', '#2A2560', '#7B68EE'],
          ].map(([t, label, bg, borCol, accent]) => `
            <div onclick="setTheme('${t}');reRenderAppear()" style="border:2px solid ${S.theme === t ? accent : borCol};border-radius:var(--rl);padding:14px;cursor:pointer;background:${bg};transition:border-color .2s">
              <div style="font-size:12px;font-weight:600;color:${t === 'dark' || t === 'neon' || t === 'cosmic' ? '#F0EFF8' : '#1C1814'};margin-bottom:8px">${label}</div>
              <div style="height:5px;background:${borCol};border-radius:3px;margin-bottom:4px"></div>
              <div style="height:5px;background:${accent};border-radius:3px;width:60%"></div>
            </div>`).join('')}
        </div>
      </div>`,

    security: () => `
      <div class="setsec"><div class="setsec-t">Security</div><div class="setsec-d">Change your password.</div>
        <div class="fg"><label class="fl" for="s-cur">Current password</label><input class="fi" id="s-cur" type="password" placeholder="Current password"></div>
        <div class="frow">
          <div class="fg"><label class="fl" for="s-new">New password</label><input class="fi" id="s-new" type="password" placeholder="New password"></div>
          <div class="fg"><label class="fl" for="s-conf">Confirm new</label><input class="fi" id="s-conf" type="password" placeholder="Confirm"></div>
        </div>
        <div class="fe" id="s-perr" style="display:none"></div>
        <button class="btn btn-primary" onclick="changePw()">Update password</button>
      </div>`,

    vault: () => `
      <div class="setsec"><div class="setsec-t">Data Vault</div><div class="setsec-d">Export or import your entire workspace data. Keep a backup of everything in uni-co.</div>
        <p style="font-size:12px;color:var(--tx2);margin-bottom:12px"><strong>Storage mode:</strong> ${'✅ Supabase (cloud — shared across all devices)'}</p>
        <div class="vault-actions">
          <button class="btn btn-primary" onclick="exportVault()" id="vault-export-btn">${I.fi} Export all data (.json)</button>
          <button class="btn" onclick="document.getElementById('vault-import-input').click()">${I.up} Import data</button>
          <input type="file" id="vault-import-input" accept=".json" style="display:none" onchange="importVault(this)">
        </div>
        <div class="vault-status" id="vault-status"></div>
      </div>`,

    account: () => `
      <div class="setsec"><div class="setsec-t">Account</div><div class="setsec-d">Account details and actions.</div>
        ${[['Email', S.user.email || 'Not set'], ['Phone', S.user.phone || 'Not set'], ['Role', S.user.role], ['Member since', fmtD(S.user.createdAt)]].map(([l, v]) => `
        <div class="setrow"><div><div class="setrow-l">${l}</div><div class="setrow-d">${esc(v)}</div></div></div>`).join('')}
        <div style="margin-top:18px;padding-top:18px;border-top:1px solid var(--bor);display:flex;flex-direction:column;gap:10px">
          <button class="btn btn-danger" onclick="doLogout()" style="align-self:flex-start">${I.lo} Sign out</button>
        </div>
      </div>
      <div class="setsec" style="margin-top:16px">
        <div class="setsec-t">🔔 Notifications</div>
        <div class="setsec-d">Get notified about new messages and task updates, even when the app is in the background.</div>
        <button class="btn btn-primary btn-sm" onclick="PushEngine.requestPermission()" style="margin-top:6px">
          Enable push notifications
        </button>
      </div>
      <div class="setsec" style="margin-top:16px">
        <div class="setsec-t">🎓 University email</div>
        <div class="setsec-d">Optionally restrict your account to a specific email domain (e.g. <code>unilag.edu.ng</code>). Leave blank to allow any email.</div>
        <div style="display:flex;gap:8px;align-items:center;margin-top:8px">
          <input class="fi" id="edu-domain" placeholder="e.g. unilag.edu.ng or leave blank"
            style="flex:1;max-width:280px"
            value="${esc(localStorage.getItem('uni_co_edu_domain') || '')}">
          <button class="btn btn-primary btn-sm" onclick="saveEduDomain()">Save</button>
          <button class="btn btn-ghost btn-sm" onclick="document.getElementById('edu-domain').value='';saveEduDomain()">Clear</button>
        </div>
        <div style="font-size:12px;color:var(--tx3);margin-top:6px">
          ${localStorage.getItem('uni_co_edu_domain')
            ? `✓ Currently restricted to <b>@${esc(localStorage.getItem('uni_co_edu_domain'))}</b>`
            : 'Currently open to any email address.'}
        </div>
      </div>
      <div class="setsec" style="border-color:var(--err-bg);margin-top:16px">
        <div class="setsec-t" style="color:var(--err)">Danger zone</div>
        <div class="setsec-d">Permanently delete your account and all associated data. This cannot be undone.</div>
        <button class="btn btn-danger" onclick="deleteAccount()">Delete my account</button>
      </div>`,
  };

  function render() {
    document.querySelectorAll('.setni').forEach(n => n.classList.toggle('on', n.dataset.s === sec));
    const c = document.getElementById('set-content');
    if (c) c.innerHTML = sections[sec]?.() ?? '';
  }

  m.innerHTML = `<div class="pg">
    <div class="ph"><h1>Settings</h1></div>
    <div class="setlayout">
      <div class="setnav">
        ${[['profile', 'Profile', I.ed], ['appearance', 'Appearance', '☀'], ['security', 'Security', I.ky], ['vault', 'Data Vault', I.va], ['account', 'Account', I.lo]].map(([s, l, ic]) =>
          `<div class="setni" data-s="${s}" onclick="setSec('${s}')">${typeof ic === 'string' && ic.length > 10 ? ic : `<span style="font-size:14px">${ic}</span>`} ${l}</div>`).join('')}
      </div>
      <div id="set-content"></div>
    </div>
  </div>`;

  window.setSec = s => { sec = s; render(); };
  window.reRenderAppear = () => { if (sec === 'appearance') render(); };
  render();
}

async function saveProfile() {
  if (demoGuard()) return;
  const name = document.getElementById('s-name')?.value?.trim();
  if (!name) { toast('Name required', 'error'); return; }
  const deptId = document.getElementById('s-dept').value;
  const dept = await StorageEngine.getDept(deptId);
  const updated = await StorageEngine.updateUser(S.user.id, { fullName: name, departmentId: deptId, bio: document.getElementById('s-bio').value, gh: document.getElementById('s-gh').value, li: document.getElementById('s-li').value });
  S.user = { ...S.user, ...updated, department: dept };
  const un = document.querySelector('.uname'); if (un) un.textContent = name;
  const ud = document.querySelector('.udept'); if (ud) ud.textContent = dept?.name || '';
  toast('Profile saved', 'success');
}

async function changePw() {
  if (demoGuard()) return;
  const cur = document.getElementById('s-cur')?.value;
  const nw = document.getElementById('s-new')?.value;
  const conf = document.getElementById('s-conf')?.value;
  const err = document.getElementById('s-perr'); err.style.display = 'none';
  if (nw !== conf) { err.textContent = 'Passwords do not match.'; err.style.display = 'block'; return; }
  try {
    await StorageEngine.changePassword(S.user.id, cur, nw);
    toast('Password updated', 'success');
    ['s-cur', 's-new', 's-conf'].forEach(id => { const el = document.getElementById(id); if (el) el.value = ''; });
  } catch (e) { err.textContent = e.message; err.style.display = 'block'; }
}

async function exportVault() {
  const btn = document.getElementById('vault-export-btn');
  if (btn) { btn.disabled = true; btn.textContent = 'Exporting...'; }
  try {
    const data = await StorageEngine.exportAll();
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `uni-co-vault-${new Date().toISOString().slice(0, 10)}.json`;
    a.click();
    toast('Data exported successfully!', 'success');
    const status = document.getElementById('vault-status');
    if (status) status.textContent = `✅ Last export: ${new Date().toLocaleString()}`;
  } catch (e) { toast('Export failed: ' + e.message, 'error'); }
  if (btn) { btn.disabled = false; btn.textContent = '📥 Export all data (.json)'; }
}

async function importVault(input) {
  const file = input.files[0];
  if (!file) return;
  if (!confirm('This will replace ALL existing data with the imported data. Are you sure?')) {
    input.value = '';
    return;
  }
  try {
    const text = await file.text();
    const data = JSON.parse(text);
    await StorageEngine.importAll(data);
    toast('Data imported! Reloading...', 'success');
    setTimeout(() => location.reload(), 1500);
  } catch (e) { toast('Import failed: ' + e.message, 'error'); }
  input.value = '';
}

async function doLogout() {
  if (!confirm('Sign out?')) return;
  await StorageEngine.logout();
  S.user = null;
  document.getElementById('root').innerHTML = '';
  showLogin();
}

async function deleteAccount() {
  if (demoGuard()) return;
  const uid = S.user.id;
  const name = S.user.fullName;

  if (!confirm(`Delete your account?\n\nThis will permanently remove your profile, notifications, and project memberships. Project content you created will remain but be unattributed.\n\nThis cannot be undone.`)) return;

  const typed = prompt(`To confirm, type your full name exactly:\n"${name}"`);
  if (typed !== name) { toast('Name did not match. Account not deleted.', 'error'); return; }

  try {
    toast('Deleting account…');

    // Remove memberships and permissions
    const mems = await StorageEngine.getAll('members', 'userId', uid);
    for (const m of mems) await StorageEngine.del('members', m.id);
    const perms = await StorageEngine.getAll('permissions');
    for (const p of perms.filter(p => p.userId === uid)) await StorageEngine.del('permissions', p.id);

    // Remove notifications
    const notifs = await StorageEngine.getAll('notifications', 'userId', uid);
    for (const n of notifs) await StorageEngine.del('notifications', n.id);

    // Anonymise messages (keep content, remove sender link)
    const allMsgs = await StorageEngine.getAll('messages');
    for (const msg of allMsgs.filter(m => m.senderId === uid)) {
      await StorageEngine.put('messages', { ...msg, senderId: null });
    }

    // Remove quiz attempts
    const attempts = await StorageEngine.getAll('quizAttempts');
    for (const a of attempts.filter(a => a.userId === uid)) await StorageEngine.del('quizAttempts', a.id);

    // Delete the user record
    await StorageEngine.del('users', uid);
    await StorageEngine.logout();

    toast('Account permanently deleted.', 'success');
    setTimeout(() => { S.user = null; showLogin(); }, 1400);
  } catch(e) {
    toast('Could not delete account: ' + e.message, 'error');
  }
}


async function openNewProject(sourceEl) {
  if (demoGuard()) return;
  const depts = await StorageEngine.getDepts();
  const sel = document.getElementById('np-dept');
  if (sel) sel.innerHTML = depts.map(d => `<option value="${d.id}"${d.id === S.user.departmentId ? ' selected' : ''}>${esc(d.name)} (${esc(d.code)})</option>`).join('');
  M.open('new-project', sourceEl);
  document.getElementById('np-title')?.focus();
}

async function submitNewProject() {
  if (demoGuard()) return;
  const title = document.getElementById('np-title')?.value?.trim();
  if (!title) { toast('Enter a project title', 'error'); return; }
  try {
    const { id, keyCode } = await StorageEngine.createProject({
      title,
      description: document.getElementById('np-desc').value.trim(),
      departmentId: document.getElementById('np-dept').value,
      isOpenCollab: document.getElementById('np-open').checked,
      dueDate: document.getElementById('np-due').value || null,
      keyType: document.getElementById('np-keytype').value,
      creatorId: S.user.id,
    });
    M.close('new-project');
    document.getElementById('np-title').value = '';
    document.getElementById('np-desc').value = '';
    toast(`Created! Key: ${keyCode}`, 'success');
    go('ws', { id });
  } catch (e) { toast(e.message, 'error'); }
}

async function submitJoinKey() {
  if (demoGuard()) return;
  const code = document.getElementById('jk-input')?.value?.trim().toUpperCase();
  const err = document.getElementById('jk-err'); err.style.display = 'none';
  if (!code) { err.textContent = 'Enter a key.'; err.style.display = 'block'; return; }
  try {
    const pid = await StorageEngine.joinByKey(code, S.user.id);
    M.close('join-key');
    toast('Joined project!', 'success');
    go('ws', { id: pid });
  } catch (e) { err.textContent = e.message; err.style.display = 'block'; }
}

let _editTaskId = null, _editProjectId = null;

function openAddTask(pid, status, prefillDate) {
  _editTaskId = null;
  _editProjectId = pid;
  document.getElementById('nt-title').value = '';
  document.getElementById('nt-desc').value = '';
  document.getElementById('nt-priority').value = 'MEDIUM';
  document.getElementById('nt-due').value = prefillDate || '';
  document.getElementById('nt-status').value = status;
  M.open('new-task');
  document.getElementById('nt-title')?.focus();
}

async function submitTask() {
  if (demoGuard()) return;
  const title = document.getElementById('nt-title')?.value?.trim();
  if (!title) { toast('Enter a title', 'error'); return; }
  await StorageEngine.createTask({
    projectId: _editProjectId,
    title,
    description: document.getElementById('nt-desc').value,
    priority: document.getElementById('nt-priority').value,
    status: document.getElementById('nt-status').value,
    dueDate: document.getElementById('nt-due').value || null,
  });
  M.close('new-task');
  toast('Task added', 'success');
  if (S.project) reloadWs();
}

async function openTaskDetail(taskId) {
  _editTaskId = taskId;
  const t = await StorageEngine.getTask(taskId);
  if (!t) return;
  document.getElementById('td-title').value = t.title;
  document.getElementById('td-desc').value = t.description || '';
  document.getElementById('td-status').value = t.status;
  document.getElementById('td-priority').value = t.priority;
  document.getElementById('td-due').value = t.dueDate ? t.dueDate.slice(0, 10) : '';
  M.open('task-detail');
  // Load comments after modal opens
  const box = document.getElementById('td-comments');
  if (box) box.innerHTML = '<div style="font-size:12px;color:var(--tx3);font-style:italic">Loading…</div>';
  setTimeout(() => loadTaskComments(taskId), 50);
}

async function saveTask() {
  if (demoGuard()) return;
  if (!_editTaskId) return;
  const prev = await StorageEngine.getTask(_editTaskId);
  const newStatus = document.getElementById('td-status').value;
  await StorageEngine.updateTask(_editTaskId, {
    title: document.getElementById('td-title').value.trim(),
    description: document.getElementById('td-desc').value,
    status: newStatus,
    priority: document.getElementById('td-priority').value,
    dueDate: document.getElementById('td-due').value || null,
  });
  M.close('task-detail');
  toast('Task saved', 'success');
  // Trigger done-glow if moved to DONE
  if (newStatus === 'DONE' && prev.status !== 'DONE') {
    setTimeout(() => {
      const card = document.querySelector(`.tkcard[data-tid="${_editTaskId}"]`);
      if (card) { card.classList.add('done-glow'); setTimeout(() => card.classList.remove('done-glow'), 1000); }
    }, 100);
  }
  if (S.project) reloadWs();
}

async function deleteTask() {
  if (demoGuard()) return;
  if (!_editTaskId || !confirm('Delete this task?')) return;
  await StorageEngine.deleteTask(_editTaskId);
  M.close('task-detail');
  toast('Task deleted');
  if (S.project) reloadWs();
}

async function reloadWs() { await showWorkspace(S.project); }

/* ── Workspace ─────────────────────────────────────────────────────── */
async function showWorkspace(id) {
  S.project = id;
  const m = document.getElementById('main');
  m.innerHTML = '<div style="padding:20px;color:var(--tx3);display:flex;align-items:center;gap:8px"><div style="width:16px;height:16px;border-radius:50%;border:2px solid var(--brand);border-top-color:transparent;animation:spin 0.7s linear infinite"></div> Loading...</div>';
  const p = await StorageEngine.getProject(id);
  if (!p) { toast('Project not found', 'error'); go('projects'); return; }

  const dept = p.department || {};
  const col = dept.colorHex || '#534AB7';
  const isLead = p.members?.some(m => m.userId === S.user.id && m.role === 'LEAD');
  const tasks = p.tasks || [];
  const done = tasks.filter(t => t.status === 'DONE').length;
  const pct = tasks.length ? Math.round(done / tasks.length * 100) : 0;

  m.innerHTML = `<div class="ws">
    <div class="wsh">
      <div style="display:flex;align-items:center;gap:10px;min-width:0;flex:1">
        <button class="btn btn-ghost btn-sm" onclick="go('projects')" style="padding:4px 10px;font-size:12px;flex-shrink:0">← Back</button>
        <div style="min-width:0">
          <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap">
            <h2 style="font-size:15px;font-weight:700;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">${esc(p.title)}</h2>
            <span class="badge" style="background:${col}22;color:${col};flex-shrink:0">${dept.code || ''}</span>
            ${p.isOpenCollab ? '<span class="badge b-open" style="flex-shrink:0">Open</span>' : ''}
          </div>
          <div style="font-size:12px;color:var(--tx3);margin-top:2px">${esc(dept.name || '')}${p.dueDate ? ` · Due ${fmtD(p.dueDate)}` : ''} · ${done}/${tasks.length} tasks done</div>
        </div>
      </div>
      <div style="display:flex;align-items:center;gap:8px;flex-shrink:0">
        ${avStack(p.members || [])}
        ${isLead ? `<div style="position:relative">
          <button class="btn btn-ghost btn-sm" onclick="toggleWsMenu()" id="ws-menu-btn" style="font-size:18px;padding:4px 8px">⋯</button>
          <div id="ws-menu" style="display:none;position:absolute;top:34px;right:0;background:var(--sur);border:1px solid var(--bor);border-radius:10px;box-shadow:0 8px 24px rgba(0,0,0,0.13);z-index:50;min-width:170px;overflow:hidden">
            <div onclick="editProjTitle('${p.id}')" style="padding:9px 14px;font-size:13px;cursor:pointer;color:var(--tx)" onmouseover="this.style.background='var(--bg2)'" onmouseout="this.style.background=''">✏️ Rename project</div>
            <div onclick="showPermissionsAuditor('${p.id}')" style="padding:9px 14px;font-size:13px;cursor:pointer;color:var(--tx)" onmouseover="this.style.background='var(--bg2)'" onmouseout="this.style.background=''">🔐 Permissions</div>
            <div onclick="archiveProj('${p.id}')" style="padding:9px 14px;font-size:13px;cursor:pointer;color:var(--warn)" onmouseover="this.style.background='var(--warn-bg)'" onmouseout="this.style.background=''">📦 Archive</div>
            <div style="height:1px;background:var(--bor)"></div>
            <div onclick="leaveProj('${p.id}','${esc(p.title)}')" style="padding:9px 14px;font-size:13px;cursor:pointer;color:var(--tx2)" onmouseover="this.style.background='var(--bg2)'" onmouseout="this.style.background=''">Leave project</div>
            <div onclick="deleteProj('${p.id}','${esc(p.title)}')" style="padding:9px 14px;font-size:13px;cursor:pointer;color:var(--err)" onmouseover="this.style.background='var(--err-bg)'" onmouseout="this.style.background=''">🗑 Delete project</div>
          </div>
        </div>` : `<div style="position:relative">
          <button class="btn btn-ghost btn-sm" onclick="toggleWsMenu()" id="ws-menu-btn" style="font-size:18px;padding:4px 8px">⋯</button>
          <div id="ws-menu" style="display:none;position:absolute;top:34px;right:0;background:var(--sur);border:1px solid var(--bor);border-radius:10px;box-shadow:0 8px 24px rgba(0,0,0,0.13);z-index:50;min-width:170px;overflow:hidden">
            <div onclick="leaveProj('${p.id}','${esc(p.title)}')" style="padding:9px 14px;font-size:13px;cursor:pointer;color:var(--err)" onmouseover="this.style.background='var(--err-bg)'" onmouseout="this.style.background=''">Leave project</div>
          </div>
        </div>`}
      </div>
    </div>
    <div class="wstabs">
      <div class="tab on" data-t="board"    onclick="wsTab(this,'board')">📋 Tasks</div>
      <div class="tab"    data-t="calendar" onclick="wsTab(this,'calendar')">📅 Calendar</div>
      <div class="tab"    data-t="files"    onclick="wsTab(this,'files')">📎 Files</div>
      <div class="tab"    data-t="chat"     onclick="wsTab(this,'chat')">💬 Chat</div>
      <div class="tab"    data-t="quiz"     onclick="wsTab(this,'quiz')">📝 Quiz</div>
      <div class="tab"    data-t="graph"    onclick="wsTab(this,'graph')">🕸 Graph</div>
      <div class="tab"    data-t="overview" onclick="wsTab(this,'overview')">⚙ Overview</div>
    </div>
    <div class="wsbody">
      <div class="wsmain" id="ws-main"></div>
      <div class="wsside" id="ws-side">${renderSide(p, isLead)}</div>
    </div>
  </div>`;

  window._wsProject = p;

  // Close ws menu on outside click
  document.addEventListener('click', function wsMenuClose(e) {
    if (!document.getElementById('ws-menu-btn')?.contains(e.target)) {
      const menu = document.getElementById('ws-menu');
      if (menu) menu.style.display = 'none';
      document.removeEventListener('click', wsMenuClose);
    }
  });

  renderWsTab('board', p);
}

window.toggleWsMenu = function() {
  const menu = document.getElementById('ws-menu');
  if (menu) menu.style.display = menu.style.display === 'none' ? 'block' : 'none';
};

window.editProjTitle = async function(id) {
  const p = await StorageEngine.getProject(id);
  const title = prompt('Rename project:', p.title);
  if (!title || title === p.title) return;
  await StorageEngine.updateProject(id, { title });
  toast('Project renamed', 'success');
  reloadWs();
};

function wsTab(el, t) {
  document.querySelectorAll('.wstabs .tab').forEach(b => b.classList.remove('on'));
  el.classList.add('on');
  renderWsTab(t, window._wsProject);
}

function renderWsTab(t, p) {
  const m = document.getElementById('ws-main');
  if (!m) return;
  if (t === 'board')       renderKanban(m, p);
  else if (t === 'calendar')  renderCalendar(m, p);
  else if (t === 'chat')     { clearChatUnread(p.id); renderChat(m, p); return; }
  else if (t === 'files')    renderFiles(m, p);
  else if (t === 'chat')     renderChat(m, p);
  else if (t === 'quiz')     renderQuiz(m, p);
  else if (t === 'graph')    renderDependencyGraph(m, p);
  else if (t === 'overview') renderOverview(m, p);
}

/* ── Project Overview Tab ─────────────────────────────────────────── */
function renderOverview(container, p) {
  const dept = p.department || {};
  const col = dept.colorHex || '#534AB7';
  const tasks = p.tasks || [];
  const done = tasks.filter(t => t.status === 'DONE').length;
  const inP = tasks.filter(t => t.status === 'IN_PROGRESS').length;
  const todo = tasks.filter(t => t.status === 'TODO').length;
  const pct = tasks.length ? Math.round(done / tasks.length * 100) : 0;
  const isLead = p.members?.some(m => m.userId === S.user.id && m.role === 'LEAD');

  container.innerHTML = `<div style="max-width:680px;display:flex;flex-direction:column;gap:14px">

    <!-- Project info -->
    <div class="card">
      <div style="display:flex;align-items:flex-start;justify-content:space-between;gap:12px;margin-bottom:14px">
        <div style="flex:1">
          <div style="font-size:18px;font-weight:700;margin-bottom:4px">${esc(p.title)}</div>
          <div style="font-size:13px;color:var(--tx2);line-height:1.55">${esc(p.description || 'No description.')}</div>
        </div>
        <span class="badge" style="background:${col}22;color:${col};flex-shrink:0;font-size:13px;padding:4px 12px">${dept.name || dept.code || ''}</span>
      </div>
      <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:10px">
        ${[
          ['Status', p.status === 'ACTIVE' ? '🟢 Active' : '📦 Archived'],
          ['Due date', p.dueDate ? fmtD(p.dueDate) : 'Not set'],
          ['Open collab', p.isOpenCollab ? 'Yes' : 'No'],
          ['Members', p.members?.length || 0],
        ].map(([l, v]) => `<div style="background:var(--bg2);border-radius:var(--r);padding:10px 12px">
          <div style="font-size:11px;color:var(--tx3);font-weight:600;text-transform:uppercase;letter-spacing:0.05em;margin-bottom:3px">${l}</div>
          <div style="font-size:13.5px;font-weight:600;color:var(--tx)">${v}</div>
        </div>`).join('')}
      </div>
    </div>

    <!-- Invite key (mobile only — desktop sees this in the side panel) -->
    ${window.innerWidth <= 900 && p._myPerms?.canInvite && p.inviteKey ? `<div class=\"card mob-key-card\">
      <div style=\"font-size:12px;font-weight:700;color:var(--tx3);text-transform:uppercase;letter-spacing:0.06em;margin-bottom:10px\">Invite key</div>
      <div class=\"keybox\">
        <span class=\"keycode\">${p.inviteKey.keyCode}</span>
        <button class=\"btn btn-ghost btn-sm\" onclick=\"navigator.clipboard.writeText('${p.inviteKey.keyCode}').then(()=>toast('Key copied!','success'))\">${I.cp}</button>
      </div>
      <div class=\"keymeta\" style=\"margin-top:6px\">${p.inviteKey.keyType === 'MULTI_USE' ? 'Multi-use' : 'Single-use'} · ${p.inviteKey.usedCount} used</div>
      ${isLead ? `<button class=\"btn btn-ghost btn-sm btn-block\" style=\"margin-top:8px;color:var(--tx2)\" onclick=\"regenKey('${p.id}')\">${I.rf} Regenerate</button>` : ''}
    </div>` : ''}

    <!-- Progress -->
    <div class="card">
      <div style="font-size:13px;font-weight:600;margin-bottom:10px">Progress</div>
      <div style="display:flex;align-items:center;gap:10px;margin-bottom:8px">
        <div class="prog" style="flex:1;height:8px;border-radius:6px"><div class="prog-fill" style="width:${pct}%;background:${col};height:100%"></div></div>
        <span style="font-size:13px;font-weight:700;color:${col}">${pct}%</span>
      </div>
      <div style="display:flex;gap:16px;margin-bottom:16px">
        <span style="font-size:12px;color:var(--tx3)">✓ ${done} done</span>
        <span style="font-size:12px;color:var(--brand)">▶ ${inP} in progress</span>
        <span style="font-size:12px;color:var(--tx3)">○ ${todo} to do</span>
      </div>

      <!-- Weekly completion sparkline -->
      ${(() => {
        const days = 7;
        const bars = [];
        for (let i = days - 1; i >= 0; i--) {
          const d = new Date(); d.setDate(d.getDate() - i);
          const ds = d.toDateString();
          const count = tasks.filter(t =>
            t.status === 'DONE' && t.updatedAt && new Date(t.updatedAt).toDateString() === ds
          ).length;
          const label = i === 0 ? 'Today' : d.toLocaleDateString('en-US',{weekday:'short'});
          bars.push({ label, count });
        }
        const max = Math.max(...bars.map(b => b.count), 1);
        return `<div style="margin-bottom:12px">
          <div style="font-size:11px;color:var(--tx3);font-weight:600;text-transform:uppercase;letter-spacing:0.05em;margin-bottom:8px">Tasks completed — last 7 days</div>
          <div style="display:flex;align-items:flex-end;gap:4px;height:48px">
            ${bars.map(b => `
              <div style="flex:1;display:flex;flex-direction:column;align-items:center;gap:3px">
                <div style="font-size:10px;color:var(--tx3)">${b.count > 0 ? b.count : ''}</div>
                <div style="width:100%;border-radius:3px 3px 0 0;background:${b.count > 0 ? col : 'var(--bor)'};
                            height:${Math.max(b.count / max * 32, b.count > 0 ? 4 : 2)}px;transition:height 0.3s"></div>
                <div style="font-size:9px;color:var(--tx3);white-space:nowrap">${b.label}</div>
              </div>`).join('')}
          </div>
        </div>`;
      })()}

      <!-- Per-member breakdown -->
      ${(() => {
        const memberRows = (p.members || []).map(m => {
          const assigned = tasks.filter(t => t.assigneeId === m.userId);
          const mdone    = assigned.filter(t => t.status === 'DONE').length;
          const mpct     = assigned.length ? Math.round(mdone / assigned.length * 100) : 0;
          if (assigned.length === 0) return '';
          const name = m.user?.fullName || 'Unknown';
          const code = m.user?.department?.code || '';
          const mbg  = db_(code.toUpperCase()), mcol = dc(code.toUpperCase());
          return `<div style="display:flex;align-items:center;gap:8px;margin-bottom:6px">
            <div style="width:22px;height:22px;border-radius:50%;background:${mbg};color:${mcol};
                        font-size:9px;font-weight:700;display:flex;align-items:center;justify-content:center;flex-shrink:0">${ini(name)}</div>
            <div style="flex:1;min-width:0">
              <div style="font-size:11px;color:var(--tx2);margin-bottom:2px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">${esc(name)}</div>
              <div style="height:4px;border-radius:2px;background:var(--bor);overflow:hidden">
                <div style="height:100%;width:${mpct}%;background:${col};border-radius:2px;transition:width 0.4s"></div>
              </div>
            </div>
            <div style="font-size:11px;color:var(--tx3);white-space:nowrap;flex-shrink:0">${mdone}/${assigned.length}</div>
          </div>`;
        }).filter(Boolean).join('');
        if (!memberRows) return '';
        return `<div>
          <div style="font-size:11px;color:var(--tx3);font-weight:600;text-transform:uppercase;letter-spacing:0.05em;margin-bottom:8px">By member</div>
          ${memberRows}
        </div>`;
      })()}
    </div>

    <!-- Danger zone for leads -->
    ${isLead ? `<div class="card" style="border-color:var(--err-bg)">
      <div style="font-size:13px;font-weight:700;color:var(--err);margin-bottom:12px">⚠ Danger zone</div>
      <div style="display:flex;gap:10px;flex-wrap:wrap">
        <button class="btn btn-sm" style="background:var(--warn-bg);color:var(--warn);border:1px solid var(--warn-bg)" onclick="archiveProj('${p.id}')">📦 Archive project</button>
        <button class="btn btn-sm" style="background:var(--bg2);color:var(--tx2);border:1px solid var(--bor)" onclick="leaveProj('${p.id}','${esc(p.title)}')">Leave project</button>
        <button class="btn btn-sm btn-danger" onclick="deleteProj('${p.id}','${esc(p.title)}')">🗑 Delete project</button>
      </div>
      <div style="font-size:11.5px;color:var(--tx3);margin-top:8px">Deleting is permanent and removes all tasks, files and messages. As Lead, transfer leadership before leaving.</div>
    </div>` : `<div class="card" style="border-color:var(--err-bg)">
      <div style="font-size:13px;font-weight:700;color:var(--err);margin-bottom:12px">⚠ Danger zone</div>
      <div style="display:flex;gap:10px;flex-wrap:wrap">
        <button class="btn btn-sm" style="background:var(--err-bg);color:var(--err);border:1px solid var(--err-bg)" onclick="leaveProj('${p.id}','${esc(p.title)}')">Leave project</button>
      </div>
      <div style="font-size:11.5px;color:var(--tx3);margin-top:8px">You will lose access and will need to be re-invited to rejoin.</div>
    </div>`}
  </div>`;
}

function renderSide(p, isLead) {
  // Check if current user has canInvite permission
  const myPerms = p._myPerms;

  return `
  <div class="ssec"><div class="sslbl">Team</div>
    ${(p.members || []).map(m => `<div class="mrow">${av(m.user || m, 'sm')}
      <div class="minfo"><div class="mname">${esc(m.user?.fullName || '')}</div><div class="mrole">${(m.role || '').charAt(0) + (m.role || '').slice(1).toLowerCase()}</div></div>
      <div class="mdot ${Math.random() > .4 ? 'on' : ''}"></div>
    </div>`).join('')}
    ${isLead ? `<button class="btn btn-ghost btn-sm btn-block" style="margin-top:6px;color:var(--brand)" onclick="M.open('join-key')">${I.pl} Invite</button>` : ''}
  </div>
  <div class="ssec"><div class="sslbl">Invite key</div>
    ${myPerms?.canInvite
      ? (p.inviteKey
        ? `<div class="keybox"><span class="keycode">${p.inviteKey.keyCode}</span><button class="btn btn-ghost btn-sm" onclick="navigator.clipboard.writeText('${p.inviteKey.keyCode}').then(()=>toast('Key copied!','success'))">${I.cp}</button></div>
           <div class="keymeta">${p.inviteKey.keyType === 'MULTI_USE' ? 'Multi-use' : 'Single-use'} · ${p.inviteKey.usedCount} used</div>
           ${isLead ? `<button class="btn btn-ghost btn-sm btn-block" style="margin-top:5px;color:var(--tx2)" onclick="regenKey('${p.id}')">${I.rf} Regenerate</button>` : ''}`
        : '<p style="font-size:12px;color:var(--tx3)">No active key</p>')
      : '<p style="font-size:12px;color:var(--tx3)">Ask the project lead for the invite key.</p>'
    }
  </div>
  <div class="ssec"><div class="sslbl">Recent files</div>
    ${(p.files || []).slice(0, 4).map(f => {
      const [bg, c] = ftCol(f.fileType);
      return `<div class="frow" onclick="StorageEngine.downloadFile('${f.id}')"><div class="fic" style="background:${bg};color:${c}">${f.fileType.slice(0, 3).toUpperCase()}</div><div class="fname">${esc(f.filename)}</div><div class="fmeta">v${f.version || 1}</div></div>`;
    }).join('') || '<p style="font-size:12px;color:var(--tx3)">No files yet</p>'}
  </div>`;
}

async function regenKey(pid) {
  if (demoGuard()) return;
  const kc = await StorageEngine.regenKey(pid);
  toast(`New key: ${kc}`, 'success');
  go('ws', { id: pid });
}

/* ── Permissions Auditor ─────────────────────────────────────────────── */
async function showPermissionsAuditor(projectId) {
  const p = await StorageEngine.getProject(projectId);
  if (!p) return;
  const allPerms = await StorageEngine.getPermissions(projectId);

  const permRows = p.members.map(m => {
    const perm = allPerms.find(pm => pm.userId === m.userId) || { canInvite: false, canEdit: false, canDelete: false };
    const isLead = m.role === 'LEAD';
    return `<tr style="border-bottom:1px solid var(--bor)">
      <td style="padding:10px 14px;display:flex;align-items:center;gap:8px">
        ${av(m.user || m, 'sm')}
        <div><div style="font-size:13px;font-weight:500">${esc(m.user?.fullName || '')}</div>
        <div style="font-size:11px;color:var(--tx3)">${esc(m.user?.email || '')} · ${isLead ? '<strong style="color:var(--brand)">Lead</strong>' : 'Contributor'}</div></div>
      </td>
      ${['canInvite','canEdit','canDelete'].map(cap => `
        <td style="padding:10px 14px;text-align:center">
          <label class="tog" ${isLead ? 'title="Lead always has full access"' : ''}>
            <input type="checkbox" ${perm[cap] || isLead ? 'checked' : ''} ${isLead ? 'disabled' : ''}
              onchange="updatePerm('${perm.id || ''}','${m.userId}','${projectId}','${cap}',this.checked)">
            <span class="tslider"></span>
          </label>
        </td>`).join('')}
    </tr>`;
  }).join('');

  // Show in a modal-like panel inline
  const main = document.getElementById('ws-main');
  main.innerHTML = `<div style="max-width:700px">
    <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:16px">
      <h2 style="font-size:16px;font-weight:700">🔐 Permissions — ${esc(p.title)}</h2>
      <button class="btn btn-ghost btn-sm" onclick="renderWsTab('overview',window._wsProject)">← Back</button>
    </div>
    <div style="background:var(--sur);border:1px solid var(--bor);border-radius:var(--rl);overflow:hidden">
      <table style="width:100%;border-collapse:collapse">
        <thead>
          <tr style="background:var(--bg2);border-bottom:1px solid var(--bor)">
            <th style="padding:10px 14px;text-align:left;font-size:12px;color:var(--tx2)">Member</th>
            <th style="padding:10px 14px;text-align:center;font-size:12px;color:var(--tx2)">Can Invite</th>
            <th style="padding:10px 14px;text-align:center;font-size:12px;color:var(--tx2)">Can Edit</th>
            <th style="padding:10px 14px;text-align:center;font-size:12px;color:var(--tx2)">Can Delete</th>
          </tr>
        </thead>
        <tbody>${permRows}</tbody>
      </table>
    </div>
    <div style="margin-top:10px;padding:10px 14px;background:var(--bg2);border-radius:var(--r);font-size:12px;color:var(--tx2)">
      <strong>Can Invite</strong> — can see and share the invite key &nbsp;·&nbsp;
      <strong>Can Edit</strong> — can modify tasks and files &nbsp;·&nbsp;
      <strong>Can Delete</strong> — can delete tasks and files
    </div>
  </div>`;
}

window.updatePerm = async function(permId, userId, projectId, cap, value) {
  if (demoGuard()) return;
  const allPerms = await StorageEngine.getPermissions(projectId);
  let perm = allPerms.find(p => p.userId === userId);
  if (perm) {
    await StorageEngine.updatePermission(perm.id, { [cap]: value });
  } else {
    await StorageEngine.put('permissions', {
      id: StorageEngine.uid(), projectId, userId,
      canInvite: false, canEdit: false, canDelete: false, [cap]: value
    });
  }
  toast(`Permission updated`, 'success');
  // Reload side panel
  const p = await StorageEngine.getProject(projectId);
  window._wsProject = p;
  const isLead = p.members?.some(m => m.userId === S.user.id && m.role === 'LEAD');
  const side = document.getElementById('ws-side');
  if (side) side.innerHTML = renderSide(p, isLead);
};

/* ═══════════════════════════════════════════════════════════════════
   SECTION 3 — Workspace Engine
   Kanban, Files (Vault tagging), Chat, Quiz Module,
   Dependency Graph, 12 Department Workstations
═══════════════════════════════════════════════════════════════════ */

/* ── Kanban Board ──────────────────────────────────────────────────── */
/* ── Kanban with sort + drag-drop ──────────────────────────────────── */
let _kanbanSort = 'priority';

function sortTasks(tasks, sort) {
  const PRI = { HIGH: 0, MEDIUM: 1, LOW: 2 };
  return [...tasks].sort((a, b) => {
    if (sort === 'priority') return (PRI[a.priority] ?? 1) - (PRI[b.priority] ?? 1);
    if (sort === 'due') {
      if (!a.dueDate && !b.dueDate) return 0;
      if (!a.dueDate) return 1; if (!b.dueDate) return -1;
      return new Date(a.dueDate) - new Date(b.dueDate);
    }
    return new Date(a.createdAt || 0) - new Date(b.createdAt || 0);
  });
}

/* ── Calendar View ─────────────────────────────────────────────────── */
let _calYear  = new Date().getFullYear();
let _calMonth = new Date().getMonth(); // 0-based

function renderCalendar(container, p) {
  const tasks    = p.tasks || [];
  const members  = p.members || [];
  const today    = new Date();
  const year     = _calYear;
  const month    = _calMonth;

  // Build a map: "YYYY-MM-DD" -> [tasks]
  const taskMap  = {};
  tasks.forEach(t => {
    if (!t.dueDate) return;
    const d = new Date(t.dueDate);
    const key = `${d.getFullYear()}-${String(d.getMonth()+1).padStart(2,'0')}-${String(d.getDate()).padStart(2,'0')}`;
    if (!taskMap[key]) taskMap[key] = [];
    taskMap[key].push(t);
  });

  const monthName  = new Date(year, month, 1).toLocaleString('en-US', { month: 'long', year: 'numeric' });
  const firstDay   = new Date(year, month, 1).getDay(); // 0=Sun
  const daysInMonth = new Date(year, month + 1, 0).getDate();

  // Build calendar grid cells
  let cells = '';
  // Empty leading cells
  for (let i = 0; i < firstDay; i++) cells += `<div class="cal-cell cal-empty"></div>`;

  for (let d = 1; d <= daysInMonth; d++) {
    const key      = `${year}-${String(month+1).padStart(2,'0')}-${String(d).padStart(2,'0')}`;
    const dayTasks = taskMap[key] || [];
    const isToday  = today.getFullYear()===year && today.getMonth()===month && today.getDate()===d;
    const isPast   = new Date(year, month, d) < new Date(today.getFullYear(), today.getMonth(), today.getDate());

    const taskPills = dayTasks.slice(0, 3).map(t => {
      const done = t.status === 'DONE';
      const od   = !done && isPast;
      const bg   = done ? 'var(--ok)' : od ? 'var(--err)' : t.priority === 'HIGH' ? 'var(--err)' : t.priority === 'LOW' ? 'var(--tx3)' : 'var(--brand)';
      return `<div class="cal-pill" style="background:${bg};opacity:${done?0.5:1};text-decoration:${done?'line-through':''}"
        onclick="event.stopPropagation();openTaskDetail('${t.id}')" title="${esc(t.title)}">${esc(t.title)}</div>`;
    }).join('');

    const overflow = dayTasks.length > 3
      ? `<div class="cal-pill" style="background:var(--bg3);color:var(--tx3)">+${dayTasks.length - 3} more</div>`
      : '';

    cells += `
      <div class="cal-cell${isToday ? ' cal-today' : ''}${isPast ? ' cal-past' : ''}"
           onclick="calDayClick('${key}', '${p.id}')">
        <div class="cal-day-num${isToday ? ' cal-today-num' : ''}">${d}</div>
        <div class="cal-pills">${taskPills}${overflow}</div>
      </div>`;
  }

  // Upcoming tasks list (next 30 days, not done)
  const soon = tasks
    .filter(t => t.dueDate && t.status !== 'DONE')
    .map(t => ({ ...t, _d: new Date(t.dueDate) }))
    .filter(t => t._d >= new Date(today.getFullYear(), today.getMonth(), today.getDate()))
    .sort((a, b) => a._d - b._d)
    .slice(0, 8);

  const upcomingHTML = soon.length === 0
    ? `<div style="color:var(--tx3);font-size:13px;padding:12px 0">No upcoming tasks with due dates.</div>`
    : soon.map(t => {
        const od  = isOD(t.dueDate), td = isTD(t.dueDate);
        const col = od ? 'var(--err)' : td ? 'var(--warn)' : 'var(--brand)';
        const assignee = members.find(m => m.userId === t.assigneeId);
        return `<div style="display:flex;align-items:center;gap:10px;padding:8px 0;border-bottom:1px solid var(--bor);cursor:pointer"
          onclick="openTaskDetail('${t.id}')">
          <div style="width:3px;border-radius:2px;align-self:stretch;background:${col};flex-shrink:0"></div>
          <div style="flex:1;min-width:0">
            <div style="font-size:13px;font-weight:500;color:var(--tx);white-space:nowrap;overflow:hidden;text-overflow:ellipsis">${esc(t.title)}</div>
            ${assignee ? `<div style="font-size:11px;color:var(--tx3);margin-top:1px">👤 ${esc(assignee.user?.fullName || '')}</div>` : ''}
          </div>
          <div style="font-size:11px;font-weight:500;color:${col};white-space:nowrap">${td ? 'Today' : fmtD(t.dueDate)}</div>
          <span class="pri pri-${t.priority==='HIGH'?'h':t.priority==='LOW'?'l':'m'}" style="flex-shrink:0">${(t.priority||'Med').charAt(0)+(t.priority||'Med').slice(1).toLowerCase()}</span>
        </div>`;
      }).join('');

  container.innerHTML = `
    <div style="display:flex;gap:16px;align-items:flex-start;flex-wrap:wrap">

      <!-- Calendar grid -->
      <div style="flex:1;min-width:280px;background:var(--sur);border:1px solid var(--bor);border-radius:var(--rl);overflow:hidden">

        <!-- Month nav -->
        <div style="display:flex;align-items:center;justify-content:space-between;padding:12px 16px;border-bottom:1px solid var(--bor);background:var(--bg2)">
          <button class="btn btn-ghost btn-sm" onclick="calNav(-1,'${p.id}')">‹ Prev</button>
          <div style="font-size:14px;font-weight:600;color:var(--tx2)">${monthName}</div>
          <button class="btn btn-ghost btn-sm" onclick="calNav(1,'${p.id}')">Next ›</button>
        </div>

        <!-- Day headers -->
        <div class="cal-grid cal-head">
          ${['Sun','Mon','Tue','Wed','Thu','Fri','Sat'].map(d =>
            `<div style="text-align:center;font-size:11px;font-weight:600;color:var(--tx3);padding:6px 0">${d}</div>`
          ).join('')}
        </div>

        <!-- Day cells -->
        <div class="cal-grid">${cells}</div>
      </div>

      <!-- Upcoming list -->
      <div style="width:240px;flex-shrink:0;background:var(--sur);border:1px solid var(--bor);border-radius:var(--rl);overflow:hidden">
        <div style="padding:10px 14px;border-bottom:1px solid var(--bor);background:var(--bg2)">
          <div style="font-size:13px;font-weight:600;color:var(--tx2)">📋 Upcoming</div>
        </div>
        <div style="padding:0 14px 8px">${upcomingHTML}</div>
      </div>

    </div>

    <style>
      .cal-grid { display:grid; grid-template-columns:repeat(7,1fr); }
      .cal-head  { border-bottom:1px solid var(--bor); }
      .cal-cell  { min-height:72px; padding:4px 5px; border-right:1px solid var(--bor); border-bottom:1px solid var(--bor); cursor:pointer; transition:background 0.15s; }
      .cal-cell:hover { background:var(--bg2); }
      .cal-cell:nth-child(7n) { border-right:none; }
      .cal-empty { background:var(--bg2); opacity:0.4; cursor:default; }
      .cal-past  { opacity:0.6; }
      .cal-today { background:color-mix(in srgb, var(--brand) 8%, var(--sur)); }
      .cal-day-num { font-size:12px; font-weight:500; color:var(--tx3); margin-bottom:3px; }
      .cal-today-num { color:var(--brand); font-weight:700; }
      .cal-pills { display:flex; flex-direction:column; gap:2px; }
      .cal-pill  { font-size:10px; color:#fff; padding:1px 5px; border-radius:3px; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; cursor:pointer; }
    </style>`;
}

window.calNav = function(dir, pid) {
  _calMonth += dir;
  if (_calMonth > 11) { _calMonth = 0;  _calYear++; }
  if (_calMonth < 0)  { _calMonth = 11; _calYear--; }
  renderCalendar(document.getElementById('ws-main'), window._wsProject);
};

window.calDayClick = function(dateKey, pid) {
  // Show tasks for that day in a modal, or open add task with pre-filled date
  const tasks = (window._wsProject?.tasks || []).filter(t => {
    if (!t.dueDate) return false;
    const d = new Date(t.dueDate);
    const k = `${d.getFullYear()}-${String(d.getMonth()+1).padStart(2,'0')}-${String(d.getDate()).padStart(2,'0')}`;
    return k === dateKey;
  });
  if (tasks.length === 0) {
    // Open add task with due date pre-filled
    openAddTask(pid, 'TODO', dateKey);
  } else if (tasks.length === 1) {
    openTaskDetail(tasks[0].id);
  } else {
    // Show a quick popover listing tasks for that day
    const existing = document.getElementById('cal-day-modal');
    if (existing) existing.remove();
    const fmt = new Date(dateKey + 'T12:00:00').toLocaleDateString('en-US', { weekday:'long', month:'long', day:'numeric' });
    const html = tasks.map(t =>
      `<div style="padding:8px 0;border-bottom:1px solid var(--bor);cursor:pointer;font-size:13px;color:var(--tx)"
        onclick="document.getElementById('cal-day-modal').remove();openTaskDetail('${t.id}')">${esc(t.title)}</div>`
    ).join('');
    const modal = document.createElement('div');
    modal.id = 'cal-day-modal';
    modal.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,0.4);z-index:900;display:flex;align-items:center;justify-content:center';
    modal.innerHTML = `<div style="background:var(--sur);border-radius:var(--rl);padding:20px;min-width:260px;max-width:340px;box-shadow:0 8px 32px rgba(0,0,0,0.18)">
      <div style="font-size:14px;font-weight:600;color:var(--tx2);margin-bottom:12px">${fmt}</div>
      ${html}
      <div style="display:flex;gap:8px;margin-top:14px">
        <button class="btn btn-primary btn-sm" onclick="document.getElementById('cal-day-modal').remove();openAddTask('${pid}','TODO','${dateKey}')">+ Add task</button>
        <button class="btn btn-ghost btn-sm"   onclick="document.getElementById('cal-day-modal').remove()">Close</button>
      </div>
    </div>`;
    modal.addEventListener('click', e => { if (e.target === modal) modal.remove(); });
    document.body.appendChild(modal);
  }
};

function renderKanban(container, p) {
  const tasks = p.tasks || [];
  const cols = [
    { k: 'TODO',        l: 'To do',       c: 'var(--tx3)' },
    { k: 'IN_PROGRESS', l: 'In progress', c: 'var(--brand)' },
    { k: 'DONE',        l: 'Done',        c: 'var(--ok)' },
  ];
  container.innerHTML = `
    <div class="task-sort-bar">
      <span style="font-size:12px;font-weight:500;color:var(--tx3)">Sort:</span>
      ${[['priority','Priority'],['due','Due date'],['created','Created']].map(([v,l]) =>
        `<button class="sort-chip${_kanbanSort===v?' on':''}" onclick="setKanbanSort('${v}','${p.id}')">${l}</button>`
      ).join('')}
      <button class="btn btn-ghost btn-sm" style="margin-left:auto;margin-right:4px" onclick="exportTasksPDF()" title="Export to PDF">📄 Export</button>
      <button class="btn btn-primary btn-sm" onclick="openAddTask('${p.id}','TODO')">${I.pl} Add task</button>
    </div>
    <div class="kanban">
    ${cols.map(col => {
      const ct = sortTasks(tasks.filter(t => t.status === col.k), _kanbanSort);
      return `<div class="kcol" id="kcol-${col.k}"
        ondragover="event.preventDefault();this.classList.add('drag-over')"
        ondragleave="this.classList.remove('drag-over')"
        ondrop="dropKanban(event,'${col.k}','${p.id}')">
        <div class="kch">
          <div class="klbl" style="color:${col.c}">${col.l}</div>
          <span class="kcnt">${ct.length}</span>
        </div>
        <div>
          ${ct.map(t => `<div class="tkcard ${t.status==='IN_PROGRESS'?'ip':t.status==='DONE'?'dn':''}"
            draggable="true" data-tid="${t.id}"
            ondragstart="event.dataTransfer.setData('taskId','${t.id}')"
            onclick="openTaskDetail('${t.id}')"
            role="button" tabindex="0" aria-label="${esc(t.title)}" onkeydown="if(event.key==='Enter')openTaskDetail('${t.id}')">
            <div class="tktitle">${esc(t.title)}</div>
            <div class="tkmeta">
              ${t.dueDate ? `<span style="font-size:11px;color:${isOD(t.dueDate)?'var(--err)':'var(--tx3)'}">📅 ${fmtD(t.dueDate)}</span>` : '<span></span>'}
              <span class="pri pri-${t.priority==='HIGH'?'h':t.priority==='LOW'?'l':'m'}">${(t.priority||'').charAt(0)+(t.priority||'').slice(1).toLowerCase()}</span>
            </div>
          </div>`).join('')}
        </div>
        <button class="add-tk" onclick="openAddTask('${p.id}','${col.k}')" aria-label="Add task">${I.pl} Add task</button>
      </div>`;
    }).join('')}
    </div>`;
}

window.setKanbanSort = function(sort, pid) {
  _kanbanSort = sort;
  renderKanban(document.getElementById('ws-main'), window._wsProject);
};

window.dropKanban = async function(e, status, pid) {
  e.preventDefault();
  document.querySelectorAll('.kcol').forEach(c => c.classList.remove('drag-over'));
  const taskId = e.dataTransfer.getData('taskId');
  if (!taskId) return;
  await StorageEngine.updateTask(taskId, { status });
  const p = await StorageEngine.getProject(pid);
  window._wsProject = p;
  renderKanban(document.getElementById('ws-main'), p);
  toast('Task moved', 'success');
};

/* ── Files (with Vault tagging and version display) ─────────────────── */
function renderFiles(container, p) {
  const fk = window._wsFeatureKey || '';
  const typeMap = {
    terminal_console: '.py,.js,.ts,.ipynb,.zip,.csv,.json',
    model_viewer: '.obj,.stl,.glb,.pdf,.png',
    spreadsheet_viewer: '.xlsx,.csv,.pdf,.pptx',
    visual_board: '.png,.jpg,.jpeg,.svg,.fig,.psd',
    citation_engine: '.docx,.doc,.pdf,.txt,.md,.bib',
    latex_editor: '.tex,.pdf,.md',
    lab_notebook: '.xlsx,.csv,.pdf,.png',
    survey_builder: '.pdf,.docx,.xlsx,.csv',
    case_board: '.pdf,.docx,.txt',
    case_study_editor: '.pdf,.png,.docx',
    blueprint_viewer: '.pdf,.png,.svg,.dwg',
    debate_board: '.pdf,.docx,.txt',
  };
  const types = typeMap[fk] || '*';

  // Fuzzy search for files
  let filterQuery = '';

  function renderFileList() {
    const list = document.getElementById('files-list');
    if (!list) return;
    const allFiles = (p.files || []);
    const filtered = filterQuery
      ? allFiles.filter(f => f.filename.toLowerCase().includes(filterQuery.toLowerCase()) ||
          (f.tags || []).some(t => t.toLowerCase().includes(filterQuery.toLowerCase())))
      : allFiles;

    list.innerHTML = filtered.length === 0
      ? `<div class="empty">${I.fi}<p style="margin-top:8px">${filterQuery ? 'No matching files' : 'No files yet'}</p></div>`
      : `<div style="background:var(--sur);border:1px solid var(--bor);border-radius:var(--rl);overflow:hidden">${filtered.map(f => {
          const [bg, c] = ftCol(f.fileType);
          const canDelete = f.uploadedById === S.user.id || p.members?.some(m => m.userId === S.user.id && m.role === 'LEAD');
          return `<div class="frow" style="padding:10px 14px">
            <div class="fic" style="background:${bg};color:${c}">${f.fileType.slice(0, 3).toUpperCase()}</div>
            <div style="flex:1;min-width:0">
              <div class="fname">${esc(f.filename)}</div>
              <div style="display:flex;gap:4px;flex-wrap:wrap;margin-top:2px">
                ${(f.tags || []).map(t => `<span class="fchip" style="font-size:9px;padding:1px 5px">${esc(t)}</span>`).join('')}
              </div>
              <div class="fmeta">${fmtSz(f.sizeBytes)} · v${f.version || 1} · ${fmtD(f.createdAt)}</div>
            </div>
            <div style="display:flex;gap:4px">
              ${/\.(png|jpg|jpeg|gif|webp|svg|pdf)$/i.test(f.filename || '')
                ? `<button class="btn btn-ghost btn-sm" onclick="event.stopPropagation();previewFile('${f.id}','${esc(f.filename)}','','${f.mimeType || ''}')" title="Preview">👁</button>` : ''}
              <button class="btn btn-ghost btn-sm" onclick="event.stopPropagation();addFileTag('${f.id}')" title="Tag">🏷</button>
              <button class="btn btn-ghost btn-sm" onclick="event.stopPropagation();StorageEngine.downloadFile('${f.id}')" title="Download">${I.fi}</button>
              ${canDelete ? `<button class="btn btn-ghost btn-sm" onclick="event.stopPropagation();deleteFile('${f.id}','${p.id}')" title="Delete" style="color:var(--err)">${I.tr}</button>` : ''}
            </div>
          </div>`;
        }).join('')}</div>`;
  }

  container.innerHTML = `<div style="max-width:640px">
    <div style="display:flex;gap:8px;margin-bottom:12px">
      <div class="swrap" style="flex:1">
        <span class="sico">${I.ex}</span>
        <input class="sinput" id="file-filter" placeholder="Filter files (fuzzy)..." oninput="fileFilter(this.value)" style="padding-left:36px">
      </div>
      <button class="btn btn-primary" onclick="document.getElementById('uinput').click()">${I.up} Upload</button>
    </div>
    <div class="upzone" id="upzone" ondragover="event.preventDefault();this.classList.add('drag')" ondragleave="this.classList.remove('drag')" ondrop="dropFile(event,'${p.id}')">
      <div class="upic">${I.up}</div>
      <p style="font-size:14px;font-weight:500;margin-bottom:4px">Drag & drop files</p>
      <p style="font-size:12px;color:var(--tx3)">or click the Upload button above</p>
      <div class="fchips">${types.split(',').map(t => `<span class="fchip">${t.trim()}</span>`).join('')}</div>
    </div>
    <input type="file" id="uinput" style="display:none" multiple onchange="pickFile(event,'${p.id}')">
    <div id="files-list" style="margin-top:14px"></div>
  </div>`;

  window.fileFilter = (q) => { filterQuery = q; renderFileList(); };
  renderFileList();
}

async function pickFile(e, pid) { for (const f of e.target.files) await doUpload(f, pid); }
async function dropFile(e, pid) {
  e.preventDefault();
  document.getElementById('upzone')?.classList.remove('drag');
  for (const f of e.dataTransfer.files) await doUpload(f, pid);
}
async function doUpload(file, pid) {
  if (demoGuard()) return;
  toast(`Uploading ${file.name}...`);
  await StorageEngine.uploadFile(pid, S.user.id, file);
  toast(`${file.name} uploaded`, 'success');
  reloadWs();
}

/* ── File Preview Modal ─────────────────────────────────────────────── */
async function previewFile(fileId, filename, fileUrl, mimeType) {
  // Files are stored as base64 dataUrl in the DB — load directly from there
  let url = null;
  let resolvedMimeType = mimeType;
  try {
    const fileRecord = await StorageEngine.get('files', fileId);
    if (fileRecord?.dataUrl) {
      url = fileRecord.dataUrl;
      // If mimeType was not passed, try to infer from the dataUrl header
      if (!resolvedMimeType && url.startsWith('data:')) {
        resolvedMimeType = url.split(';')[0].replace('data:', '');
      }
    }
  } catch(e) {}
  // Fallback to a plain URL if one was explicitly provided and DB fetch failed
  if (!url && fileUrl && fileUrl !== 'undefined') url = fileUrl;
  if (!url) { toast('Could not load preview', 'error'); return; }

  const isImage = /\.(png|jpg|jpeg|gif|webp|svg)$/i.test(filename) || (resolvedMimeType && resolvedMimeType.startsWith('image/'));
  const isPDF   = /\.pdf$/i.test(filename) || resolvedMimeType === 'application/pdf';

  const existing = document.getElementById('file-preview-modal');
  if (existing) existing.remove();

  const modal = document.createElement('div');
  modal.id = 'file-preview-modal';
  modal.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,0.75);z-index:500;display:flex;flex-direction:column;align-items:center;justify-content:center;padding:16px';

  const content = isImage
    ? `<img src="${url}" alt="${esc(filename)}" style="max-width:100%;max-height:80vh;border-radius:12px;object-fit:contain;box-shadow:0 8px 40px rgba(0,0,0,0.4)">`
    : isPDF
    ? `<iframe src="${url}" style="width:min(800px,95vw);height:80vh;border:none;border-radius:12px;background:#fff"></iframe>`
    : `<div style="color:#fff;font-size:14px">Preview not available for this file type.</div>`;

  modal.innerHTML = `
    <div style="display:flex;align-items:center;justify-content:space-between;width:min(800px,95vw);margin-bottom:12px">
      <div style="font-size:13px;font-weight:600;color:#fff;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;flex:1">${esc(filename)}</div>
      <button onclick="document.getElementById('file-preview-modal').remove()"
        style="background:rgba(255,255,255,0.15);border:none;color:#fff;width:32px;height:32px;border-radius:8px;cursor:pointer;font-size:16px;flex-shrink:0;margin-left:12px">✕</button>
    </div>
    ${content}`;

  modal.addEventListener('click', e => { if (e.target === modal) modal.remove(); });
  document.body.appendChild(modal);
}

async function deleteFile(fileId, pid) {
  if (demoGuard()) return;
  if (!confirm('Delete this file? This cannot be undone.')) return;
  await StorageEngine.deleteFile(fileId);
  toast('File deleted');
  reloadWs();
}

async function addFileTag(fileId) {
  const tag = prompt('Enter a tag (e.g. "draft", "final", "reference"):');
  if (!tag) return;
  const f = await StorageEngine.get('files', fileId);
  await StorageEngine.updateFileTags(fileId, [...(f.tags || []), tag.toLowerCase().trim()]);
  toast(`Tag "${tag}" added`, 'success');
  reloadWs();
}

/* ══════════════════════════════════════════════════════════════════
   REAL-TIME CHAT — Supabase channels + typing indicators + reactions
══════════════════════════════════════════════════════════════════ */

// Active real-time channel reference (cleaned up on navigation)
window._chatChannel = null;
window._typingTimer  = null;
window._typingUsers  = {};   // { userId: { name, ts } }

function renderChat(container, p) {
  const u      = S.user;
  const isLead = p.members?.some(m => m.userId === u.id && m.role === 'LEAD');

  container.innerHTML = `
  <div style="display:flex;flex-direction:column;height:calc(100vh - 190px);min-height:400px;
              background:var(--sur);border:1px solid var(--bor);border-radius:var(--rl);overflow:hidden">

    <!-- Header -->
    <div style="padding:10px 14px;border-bottom:1px solid var(--bor);background:var(--bg2);
                display:flex;align-items:center;justify-content:space-between;flex-shrink:0">
      <div id="chat-member-header" style="display:flex;align-items:center;gap:8px;font-size:13px;font-weight:600;color:var(--tx2)">
        💬 Team chat
        <div style="display:flex;gap:4px">${(p.members || []).slice(0, 6).map(m => av(m.user || m, 'sm')).join('')}</div>
      </div>
      <div id="chat-status" style="font-size:11px;color:var(--ok);font-weight:500;display:flex;align-items:center;gap:4px">
        <span style="width:6px;height:6px;border-radius:50%;background:var(--ok);display:inline-block"></span>
        Live
      </div>
    </div>

    <!-- Messages -->
    <div id="msgs" style="flex:1;overflow-y:auto;padding:16px;display:flex;flex-direction:column;
                          gap:14px;scroll-behavior:smooth">
      ${(p.messages || []).length === 0
        ? `<div style="text-align:center;padding:40px 20px;color:var(--tx3);font-size:13px">
             <div style="font-size:28px;margin-bottom:8px">💬</div>
             No messages yet — say hello!
           </div>`
        : (p.messages || []).map(msg => chatBubbleHTML(msg, u.id, isLead)).join('')}
    </div>

    <!-- Typing indicator -->
    <div id="typing-bar" style="padding:0 16px 4px;font-size:11.5px;color:var(--tx3);
                                 font-style:italic;min-height:20px;flex-shrink:0"></div>

    <!-- Input bar -->
    <div style="padding:10px 14px;border-top:1px solid var(--bor);background:var(--sur);
                display:flex;gap:8px;align-items:center;flex-shrink:0;position:relative">
      <div id="mention-dropdown" style="display:none;position:absolute;bottom:62px;left:14px;right:60px;
        background:var(--sur);border:1px solid var(--bor);border-radius:10px;
        box-shadow:0 4px 16px rgba(0,0,0,0.14);z-index:50;overflow:hidden"></div>
      <input id="chat-in" placeholder="Message the team… (@ to mention)"
        style="flex:1;padding:10px 14px;border:1.5px solid var(--bor);border-radius:22px;
               background:var(--bg2);color:var(--tx);font-size:14px;outline:none;
               font-family:inherit;transition:border-color 0.2s"
        onfocus="this.style.borderColor='var(--brand)'"
        onblur="this.style.borderColor='var(--bor)'"
        oninput="broadcastTyping('${p.id}');handleMentionInput(this)"
        onkeydown="if(event.key==='Escape'){closeMentionDropdown()}else if(event.key==='Enter'&&!event.shiftKey){event.preventDefault();sendChat('${p.id}')}">
      <button onclick="sendChat('${p.id}')"
        style="width:40px;height:40px;border-radius:50%;background:var(--brand);color:#fff;
               border:none;cursor:pointer;display:flex;align-items:center;justify-content:center;
               flex-shrink:0;transition:all 0.2s"
        onmouseover="this.style.background='var(--brand-d)';this.style.transform='scale(1.05)'"
        onmouseout="this.style.background='var(--brand)';this.style.transform=''">
        ${I.sd}
      </button>
    </div>
  </div>`;

  const msgs = document.getElementById('msgs');
  if (msgs) msgs.scrollTop = msgs.scrollHeight;
  setTimeout(() => document.getElementById('chat-in')?.focus(), 100);

  // Start real-time subscription
  startChatRealtime(p.id, u.id, isLead);
}

/* ── Real-time subscription ────────────────────────────────────────── */
function startChatRealtime(projectId, myUserId, isLead) {
  // Clean up any previous channel
  stopChatRealtime();

  const sb = StorageEngine._sb ? StorageEngine._sb() : null;
  if (!sb) return;

  window._chatChannel = sb
    .channel(`chat:${projectId}`)

    // New message inserted in DB
    .on('postgres_changes', {
      event: 'INSERT', schema: 'public', table: 'messages',
      filter: `project_id=eq.${projectId}`
    }, async (payload) => {
      const row = payload.new;
      // Skip own messages (already rendered optimistically)
      if (row.sender_id === myUserId) return;

      // Fetch sender profile
      const { data: senderRow } = await sb.from('users').select('*, departments(*)').eq('id', row.sender_id).single();
      const sender = senderRow
        ? { ...senderRow, fullName: senderRow.full_name, department: senderRow.departments }
        : null;

      const msg = {
        id: row.id, content: row.content,
        senderId: row.sender_id, sentAt: row.sent_at,
        sender,
      };

      const msgs = document.getElementById('msgs');

      // Track unread if chat tab not visible
      const chatTabActive = document.querySelector('.tab.on[data-t="chat"]');
      if (!chatTabActive) {
        window._unreadChats = window._unreadChats || {};
        window._unreadChats[projectId] = (window._unreadChats[projectId] || 0) + 1;
        updateChatBadge(projectId);
      }

      if (!msgs) return;

      // Remove empty state if present
      const empty = msgs.querySelector('[data-empty]');
      if (empty) empty.remove();

      msgs.insertAdjacentHTML('beforeend', chatBubbleHTML(msg, myUserId, isLead));
      msgs.scrollTop = msgs.scrollHeight;

      // Clear that sender from typing
      delete window._typingUsers[row.sender_id];
      updateTypingBar();

      // Push notification if tab is not visible
      PushEngine.notifyIfHidden(
        sender?.fullName || 'Team member',
        row.content,
        projectId
      );
    })

    // Message deleted
    .on('postgres_changes', {
      event: 'DELETE', schema: 'public', table: 'messages',
      filter: `project_id=eq.${projectId}`
    }, (payload) => {
      const row = document.querySelector(`.chat-msg-row[data-mid="${payload.old?.id}"]`);
      if (row) { row.style.opacity = '0'; setTimeout(() => row.remove(), 200); }
    })

    // Presence tracking
    .on('presence', { event: 'sync' }, () => {
      const state = window._chatChannel.presenceState();
      window._onlineUsers = {};
      Object.values(state).forEach(presences => {
        presences.forEach(p => { if (p.userId) window._onlineUsers[p.userId] = true; });
      });
      updatePresenceDots();
    })
    .on('presence', { event: 'join' }, ({ newPresences }) => {
      window._onlineUsers = window._onlineUsers || {};
      newPresences.forEach(p => { if (p.userId) window._onlineUsers[p.userId] = true; });
      updatePresenceDots();
    })
    .on('presence', { event: 'leave' }, ({ leftPresences }) => {
      window._onlineUsers = window._onlineUsers || {};
      leftPresences.forEach(p => { if (p.userId) delete window._onlineUsers[p.userId]; });
      updatePresenceDots();
    })

    // Typing broadcast (presence-style)
    .on('broadcast', { event: 'typing' }, (payload) => {
      const { userId, name } = payload.payload;
      if (userId === myUserId) return;
      window._typingUsers[userId] = { name, ts: Date.now() };
      updateTypingBar();
      // Auto-clear after 3 seconds of silence
      setTimeout(() => {
        if (window._typingUsers[userId] && Date.now() - window._typingUsers[userId].ts >= 2900) {
          delete window._typingUsers[userId];
          updateTypingBar();
        }
      }, 3000);
    })

    .subscribe((status) => {
      const indicator = document.getElementById('chat-status');
      if (!indicator) return;
      if (status === 'SUBSCRIBED') {
        indicator.innerHTML = '<span style="width:6px;height:6px;border-radius:50%;background:var(--ok);display:inline-block"></span> Live';
        indicator.style.color = 'var(--ok)';
        // Track own presence
        window._chatChannel.track({ userId: myUserId, ts: Date.now() });
      } else if (status === 'CHANNEL_ERROR' || status === 'TIMED_OUT') {
        indicator.innerHTML = '<span style="width:6px;height:6px;border-radius:50%;background:var(--err);display:inline-block"></span> Reconnecting…';
        indicator.style.color = 'var(--err)';
      }
    });
}

/* ── Unread chat badge ─────────────────────────────────────────────── */
function updateChatBadge(projectId) {
  const count = (window._unreadChats || {})[projectId] || 0;
  // Update Chat tab badge
  const chatTab = document.querySelector('.tab[data-t="chat"]');
  if (chatTab) {
    let badge = chatTab.querySelector('.chat-unread-badge');
    if (count > 0) {
      if (!badge) {
        badge = document.createElement('span');
        badge.className = 'chat-unread-badge';
        badge.style.cssText = 'display:inline-flex;align-items:center;justify-content:center;min-width:16px;height:16px;border-radius:8px;background:var(--err);color:#fff;font-size:9px;font-weight:700;padding:0 4px;margin-left:4px;vertical-align:middle';
        chatTab.appendChild(badge);
      }
      badge.textContent = count > 99 ? '99+' : count;
    } else if (badge) {
      badge.remove();
    }
  }
  // Update mobile nav Projects dot
  const projNavItem = document.querySelector('.mob-nav-item[data-p="projects"]');
  if (projNavItem) {
    let dot = projNavItem.querySelector('.msg-unread-dot');
    const totalUnread = Object.values(window._unreadChats || {}).reduce((a, b) => a + b, 0);
    if (totalUnread > 0) {
      if (!dot) {
        dot = document.createElement('span');
        dot.className = 'msg-unread-dot';
        dot.style.cssText = 'position:absolute;top:4px;right:10px;width:8px;height:8px;border-radius:50%;background:var(--err);border:2px solid var(--sur)';
        projNavItem.style.position = 'relative';
        projNavItem.appendChild(dot);
      }
    } else if (dot) {
      dot.remove();
    }
  }
}

function clearChatUnread(projectId) {
  if (!window._unreadChats) return;
  delete window._unreadChats[projectId];
  updateChatBadge(projectId);
}

function updatePresenceDots() {
  const online = window._onlineUsers || {};
  // Update all avatar elements that have data-uid
  document.querySelectorAll('[data-uid]').forEach(el => {
    const uid = el.getAttribute('data-uid');
    let dot = el.querySelector('.presence-dot');
    if (online[uid]) {
      if (!dot) {
        dot = document.createElement('span');
        dot.className = 'presence-dot';
        dot.style.cssText = 'position:absolute;bottom:0;right:0;width:8px;height:8px;border-radius:50%;background:var(--ok);border:2px solid var(--sur);box-sizing:content-box';
        el.style.position = 'relative';
        el.appendChild(dot);
      }
    } else if (dot) {
      dot.remove();
    }
  });
  // Update the chat member count with online count
  const memberHeader = document.getElementById('chat-member-header');
  if (memberHeader) {
    memberHeader.querySelector('.online-count')?.remove();
    const onlineCount = Object.keys(online).length;
    if (onlineCount > 0) {
      const span = document.createElement('span');
      span.className = 'online-count';
      span.style.cssText = 'font-size:11px;color:var(--ok);font-weight:600';
      span.textContent = `· ${onlineCount} online`;
      memberHeader.appendChild(span);
    }
  }
}

function stopChatRealtime() {
  if (window._chatChannel) {
    try { window._chatChannel.unsubscribe(); } catch(e) {}
    window._chatChannel = null;
  }
  window._typingUsers = {};
  clearTimeout(window._typingTimer);
}

/* ── Typing indicator ──────────────────────────────────────────────── */
function broadcastTyping(projectId) {
  const ch = window._chatChannel;
  if (!ch) return;
  ch.send({ type: 'broadcast', event: 'typing', payload: {
    userId: S.user.id,
    name: S.user.fullName,
  }});
  // Stop broadcasting after 2s of no input
  clearTimeout(window._typingTimer);
  window._typingTimer = setTimeout(() => {}, 2000);
}

function updateTypingBar() {
  const bar = document.getElementById('typing-bar');
  if (!bar) return;
  const names = Object.values(window._typingUsers).map(u => u.name.split(' ')[0]);
  if (names.length === 0) { bar.textContent = ''; return; }
  if (names.length === 1) bar.textContent = `${names[0]} is typing…`;
  else if (names.length === 2) bar.textContent = `${names[0]} and ${names[1]} are typing…`;
  else bar.textContent = `${names.length} people are typing…`;
}

/* ── @mention autocomplete ─────────────────────────────────────────── */
function handleMentionInput(input) {
  const val    = input.value;
  const caret  = input.selectionStart;
  const before = val.slice(0, caret);
  const match  = before.match(/@([A-Za-z0-9 ]*)$/);
  const dd     = document.getElementById('mention-dropdown');
  if (!match || !dd) { closeMentionDropdown(); return; }

  const query   = match[1].toLowerCase();
  const members = (window._wsProject?.members || []);
  const hits    = members
    .filter(m => m.userId !== S.user?.id)
    .filter(m => (m.user?.fullName || '').toLowerCase().includes(query))
    .slice(0, 5);

  if (hits.length === 0) { closeMentionDropdown(); return; }

  dd.style.display = 'block';
  dd.innerHTML = hits.map((m, i) => {
    const name = esc(m.user?.fullName || 'Unknown');
    const code = m.user?.department?.code || '';
    const bg   = db_(code.toUpperCase()), col = dc(code.toUpperCase());
    return `<div data-mention-idx="${i}" onclick="insertMention('${(m.user?.fullName||'').replace(/'/g,"\\'")}',this)"
      style="display:flex;align-items:center;gap:8px;padding:8px 12px;cursor:pointer;
             transition:background 0.1s;font-size:13px;color:var(--tx)"
      onmouseover="this.style.background='var(--bg2)'" onmouseout="this.style.background=''">
      <div style="width:26px;height:26px;border-radius:50%;background:${bg};color:${col};
                  font-size:10px;font-weight:700;display:flex;align-items:center;justify-content:center;flex-shrink:0">${ini(m.user?.fullName)}</div>
      <span>${name}</span>
    </div>`;
  }).join('');
}

function insertMention(fullName, el) {
  const input  = document.getElementById('chat-in');
  if (!input) return;
  const val    = input.value;
  const caret  = input.selectionStart;
  const before = val.slice(0, caret);
  const after  = val.slice(caret);
  const newBefore = before.replace(/@([A-Za-z0-9 ]*)$/, `@${fullName} `);
  input.value = newBefore + after;
  input.focus();
  input.setSelectionRange(newBefore.length, newBefore.length);
  closeMentionDropdown();
}

function closeMentionDropdown() {
  const dd = document.getElementById('mention-dropdown');
  if (dd) dd.style.display = 'none';
}

/* ── Task Comments ─────────────────────────────────────────────────── */
// We store task comments as messages with a special taskId field.
// This reuses the existing messages table — no new table needed.

async function loadTaskComments(taskId) {
  const box = document.getElementById('td-comments');
  if (!box) return;
  try {
    const sb = StorageEngine._sb();
    const { data, error } = await sb
      .from('messages')
      .select('*, users!sender_id(full_name, department_id, departments(code, color_hex))')
      .eq('task_id', taskId)
      .order('sent_at', { ascending: true });

    if (error || !data || data.length === 0) {
      box.innerHTML = `<div style="font-size:12px;color:var(--tx3);font-style:italic">No comments yet.</div>`;
      return;
    }

    box.innerHTML = data.map(c => {
      const name  = c.users?.full_name || 'Unknown';
      const code  = c.users?.departments?.code || '';
      const bg    = db_(code.toUpperCase()), col = dc(code.toUpperCase());
      const isSelf = c.sender_id === S.user?.id;
      const time  = new Date(c.sent_at).toLocaleTimeString([], {hour:'2-digit',minute:'2-digit'});
      const date  = new Date(c.sent_at).toLocaleDateString('en-US',{month:'short',day:'numeric'});
      return `<div style="display:flex;gap:8px;align-items:flex-start">
        <div style="width:24px;height:24px;border-radius:50%;background:${bg};color:${col};
                    font-size:10px;font-weight:700;display:flex;align-items:center;justify-content:center;flex-shrink:0;margin-top:2px">${ini(name)}</div>
        <div style="flex:1;min-width:0">
          <div style="font-size:11px;color:var(--tx3);margin-bottom:2px">${esc(isSelf?'You':name)} · ${date} ${time}</div>
          <div style="font-size:13px;color:var(--tx);line-height:1.45;word-break:break-word;
                      background:var(--bg2);border-radius:8px;padding:6px 10px">${esc(c.content)}</div>
        </div>
      </div>`;
    }).join('');
    box.scrollTop = box.scrollHeight;
  } catch(e) {
    const box = document.getElementById('td-comments');
    if (box) box.innerHTML = `<div style="font-size:12px;color:var(--tx3);font-style:italic">Comments unavailable.</div>`;
  }
}

async function submitTaskComment() {
  if (demoGuard()) return;
  const inp = document.getElementById('td-comment-in');
  const txt = inp?.value?.trim();
  if (!txt || !_editTaskId) return;
  inp.value = '';
  try {
    const sb = StorageEngine._sb();
    const pid = window._wsProject?.id;
    await sb.from('messages').insert({
      id: ([1e7]+-1e3+-4e3+-8e3+-1e11).replace(/[018]/g,c=>(c^crypto.getRandomValues(new Uint8Array(1))[0]&15>>c/4).toString(16)),
      project_id: pid,
      sender_id:  S.user.id,
      content:    txt,
      task_id:    _editTaskId,
      sent_at:    new Date().toISOString(),
    });
    await loadTaskComments(_editTaskId);
    toast('Comment added', 'success');
  } catch(e) {
    toast('Could not post comment', 'error');
  }
}

function chatBubbleHTML(msg, myId, isLead) {
  const isSelf = msg.senderId === myId;
  const sender = isSelf ? S.user : (msg.sender || {});
  const canDelete = isSelf || isLead;
  const code = sender?.department?.code || '';
  const bg = db_(code.toUpperCase()), col = dc(code.toUpperCase());

  // Render @mentions as highlighted spans
  const renderContent = (text) => {
    if (!text) return '';
    return esc(text).replace(/@([A-Za-z][A-Za-z0-9 ._-]{0,30})/g, (match, name) => {
      const isSelfMention = name.toLowerCase() === (S.user?.fullName || '').toLowerCase();
      return `<span style="background:${isSelfMention ? 'rgba(255,200,0,0.25)' : 'rgba(83,74,183,0.15)'};color:${isSelf ? 'rgba(255,255,255,0.9)' : 'var(--brand)'};border-radius:4px;padding:0 3px;font-weight:600">@${name}</span>`;
    });
  };

  return `<div class="chat-msg-row" data-mid="${msg.id}" style="display:flex;gap:9px;align-items:flex-end;${isSelf ? 'flex-direction:row-reverse' : ''}">
    <div style="width:30px;height:30px;border-radius:50%;background:${bg};color:${col};font-size:11px;font-weight:700;display:flex;align-items:center;justify-content:center;flex-shrink:0;margin-bottom:2px">
      ${ini(sender?.fullName)}
    </div>
    <div style="max-width:68%;${isSelf ? 'align-items:flex-end' : ''}; display:flex;flex-direction:column">
      <div style="font-size:11px;color:var(--tx3);margin-bottom:3px;${isSelf ? 'text-align:right' : ''}">
        ${esc(isSelf ? 'You' : (sender?.fullName || 'Unknown'))} · ${new Date(msg.sentAt || Date.now()).toLocaleTimeString([], {hour:'2-digit',minute:'2-digit'})}
        ${canDelete ? `<button onclick="deleteChatMsg('${msg.id}')" style="background:none;border:none;cursor:pointer;color:var(--tx3);font-size:11px;margin-left:4px;padding:0;line-height:1;opacity:0.5" onmouseover="this.style.opacity=1;this.style.color='var(--err)'" onmouseout="this.style.opacity=0.5;this.style.color='var(--tx3)'" title="Delete">✕</button>` : ''}
      </div>
      <div style="padding:9px 14px;border-radius:${isSelf ? '16px 16px 4px 16px' : '16px 16px 16px 4px'};background:${isSelf ? 'var(--brand)' : 'var(--bg2)'};color:${isSelf ? '#fff' : 'var(--tx)'};font-size:14px;line-height:1.5;word-break:break-word">
        ${renderContent(msg.content)}
      </div>
    </div>
  </div>`;
}

async function sendChat(pid) {
  if (demoGuard()) return;
  const inp = document.getElementById('chat-in');
  const txt = inp?.value?.trim();
  if (!txt) return;
  inp.value = '';

  // Optimistic render — show immediately without waiting for DB
  const p      = window._wsProject;
  const isLead = p?.members?.some(m => m.userId === S.user.id && m.role === 'LEAD');
  const tempId  = 'tmp-' + Date.now();
  const tempMsg = { id: tempId, content: txt, senderId: S.user.id, sentAt: new Date().toISOString(), sender: S.user };
  const msgs    = document.getElementById('msgs');

  if (msgs) {
    // Remove empty state
    const empty = msgs.querySelector('[data-empty]');
    if (empty) empty.remove();
    msgs.insertAdjacentHTML('beforeend', chatBubbleHTML(tempMsg, S.user.id, isLead));
    msgs.scrollTop = msgs.scrollHeight;
  }

  try {
    const saved = await StorageEngine.sendMsg(pid, S.user.id, txt);
    // Update temp element with real ID
    const tempEl = msgs?.querySelector(`[data-mid="${tempId}"]`);
    if (tempEl) tempEl.setAttribute('data-mid', saved.id);
  } catch(e) {
    // Roll back on failure
    const tempEl = msgs?.querySelector(`[data-mid="${tempId}"]`);
    if (tempEl) {
      tempEl.style.opacity = '0.4';
      tempEl.title = 'Failed to send';
    }
    toast('Failed to send message', 'error');
  }
}

async function deleteChatMsg(msgId) {
  if (demoGuard()) return;
  if (!confirm('Delete this message?')) return;
  await StorageEngine.deleteMsg(msgId);
  const row = document.querySelector(`.chat-msg-row[data-mid="${msgId}"]`);
  if (row) {
    row.style.transition = 'all 0.2s';
    row.style.opacity = '0';
    row.style.transform = 'scale(0.9)';
    setTimeout(() => row.remove(), 200);
  }
  toast('Message deleted');
}

/* ── Quiz Module ────────────────────────────────────────────────────── */
function renderQuiz(container, p) {
  const quizzes = p.quizzes || [];

  function renderQuizList() {
    const ql = document.getElementById('quiz-list');
    if (!ql) return;
    ql.innerHTML = quizzes.length === 0
      ? `<div class="empty"><div class="emico">${I.qu}</div><p style="margin-top:8px">No quizzes yet</p><button class="btn btn-primary btn-sm" style="margin-top:10px" onclick="showQuizCreator('${p.id}')">${I.pl} Create Quiz</button></div>`
      : `<div style="margin-bottom:16px"><button class="btn btn-primary btn-sm" onclick="showQuizCreator('${p.id}')">${I.pl} Create Quiz</button></div>
         ${quizzes.map(q => `<div class="quiz-card card-c" onclick="takeQuiz('${q.id}')">
           <div style="display:flex;justify-content:space-between;align-items:center">
             <div><div style="font-weight:600">${esc(q.title)}</div><div style="font-size:12px;color:var(--tx3);margin-top:2px">${(q.questions || []).length} questions · ${esc(q.description || '')}</div></div>
             <span class="badge b-blue">Take</span>
           </div>
         </div>`).join('')}`;
  }

  container.innerHTML = `<div class="quiz-wrap">
    <h3 style="margin-bottom:12px">Peer Quizzes</h3>
    <div id="quiz-list"></div>
    <div id="quiz-area"></div>
  </div>`;

  window.showQuizCreator = (pid) => {
    const area = document.getElementById('quiz-area');
    area.innerHTML = `<div class="quiz-create" style="background:var(--sur);border:1px solid var(--bor);border-radius:var(--rl);padding:20px;margin-top:12px">
      <h3 style="margin-bottom:12px">Create Quiz</h3>
      <div class="fg"><label class="fl" for="qc-title">Title</label><input class="fi" id="qc-title" placeholder="e.g. UI Design Principles"></div>
      <div class="fg"><label class="fl" for="qc-desc">Description</label><input class="fi" id="qc-desc" placeholder="Brief description..."></div>
      <div id="qc-questions"></div>
      <button class="btn btn-sm" onclick="addQCQuestion()" style="margin-bottom:12px">${I.pl} Add Question</button>
      <div style="display:flex;gap:8px">
        <button class="btn btn-primary" onclick="saveQuiz('${pid}')">Save Quiz</button>
        <button class="btn" onclick="renderQuiz(document.getElementById('ws-main'),window._wsProject)">Cancel</button>
      </div>
    </div>`;
    addQCQuestion();
  };

  window.addQCQuestion = () => {
    const qs = document.getElementById('qc-questions');
    const i = qs.children.length;
    const div = document.createElement('div');
    div.style.cssText = 'border:1px solid var(--bor);border-radius:var(--r);padding:12px;margin-bottom:8px';
    div.innerHTML = `
      <div class="fg"><label class="fl" for="qc-q-${i}">Question ${i + 1}</label><input class="fi qc-q" id="qc-q-${i}" placeholder="Question text..."></div>
      ${[0,1,2,3].map(j => `<div class="fg"><input class="fi qc-o" placeholder="Option ${j+1}${j===0?' (correct)':''}" data-correct="${j===0}"></div>`).join('')}
      <span style="font-size:10px;color:var(--tx3)">First option = correct answer</span>
    `;
    qs.appendChild(div);
  };

  window.saveQuiz = async (pid) => {
    if (demoGuard()) return;
    const title = document.getElementById('qc-title')?.value?.trim();
    if (!title) { toast('Title required', 'error'); return; }
    const desc = document.getElementById('qc-desc')?.value?.trim() || '';
    const questionDivs = document.querySelectorAll('#qc-questions > div');
    const questions = [];
    questionDivs.forEach(div => {
      const qText = div.querySelector('.qc-q')?.value?.trim();
      const opts = [...div.querySelectorAll('.qc-o')].map(inp => inp.value.trim()).filter(Boolean);
      if (qText && opts.length >= 2) questions.push({ q: qText, options: opts, correctIndex: 0 });
    });
    if (questions.length === 0) { toast('Add at least one question', 'error'); return; }
    await StorageEngine.createQuiz({ projectId: pid, title, description: desc, questions, createdBy: S.user.id });
    toast('Quiz created!', 'success');
    reloadWs();
  };

  window.takeQuiz = async (quizId) => {
    const quiz = await StorageEngine.getQuiz(quizId);
    if (!quiz) return;
    const area = document.getElementById('quiz-area');
    let answers = new Array(quiz.questions.length).fill(-1);
    let submitted = false;

    function renderTake() {
      area.innerHTML = `<div style="background:var(--sur);border:1px solid var(--bor);border-radius:var(--rl);padding:20px;margin-top:12px">
        <h3>${esc(quiz.title)}</h3>
        <p style="font-size:12px;color:var(--tx2);margin-bottom:16px">${esc(quiz.description)}</p>
        ${quiz.questions.map((q, i) => `<div class="quiz-card ${submitted ? (answers[i] === q.correctIndex ? 'correct' : 'wrong') : ''}">
          <div style="font-weight:500;margin-bottom:10px">${i+1}. ${esc(q.q)}</div>
          ${q.options.map((opt, j) => `<div class="quiz-opt ${answers[i]===j?'selected':''} ${submitted&&j===q.correctIndex?'correct':''} ${submitted&&answers[i]===j&&j!==q.correctIndex?'wrong':''}"
            onclick="${submitted?'':`setAnswer(${i},${j})`}">${esc(opt)}</div>`).join('')}
        </div>`).join('')}
        ${!submitted
          ? `<button class="btn btn-primary btn-block" onclick="submitQuiz('${quizId}')" id="quiz-submit-btn">Submit Answers</button>`
          : `<div class="quiz-score">
              <div class="quiz-score-val">${answers.filter((a,i)=>a===quiz.questions[i].correctIndex).length}/${quiz.questions.length}</div>
              <p style="color:var(--tx2);margin-top:4px">${answers.filter((a,i)=>a===quiz.questions[i].correctIndex).length===quiz.questions.length?'🎉 Perfect score!':'Keep learning!'}</p>
              <button class="btn btn-sm" style="margin-top:12px" onclick="renderQuiz(document.getElementById('ws-main'),window._wsProject)">Back to quizzes</button>
            </div>`}
      </div>`;
    }

    window.setAnswer = (i, j) => { answers[i] = j; renderTake(); };
    window.submitQuiz = async (qid) => {
      if (demoGuard()) return;
      submitted = true;
      const score = answers.filter((a, i) => a === quiz.questions[i].correctIndex).length;
      await StorageEngine.submitQuizAttempt({ quizId: qid, userId: S.user.id, answers, score, total: quiz.questions.length });
      renderTake();
      toast(`Score: ${score}/${quiz.questions.length}`, score === quiz.questions.length ? 'success' : 'info');
    };
    renderTake();
  };

  renderQuizList();
}

/* ── Dependency Graph ──────────────────────────────────────────────── */
function renderDependencyGraph(container, p) {
  container.innerHTML = `<div class="graph-wrap">
    <div class="graph-legend">
      <div style="font-size:11px;font-weight:600;margin-bottom:4px">Legend</div>
      <div style="display:flex;align-items:center;gap:6px;margin-bottom:2px"><div style="width:10px;height:10px;border-radius:2px;background:var(--brand)"></div> This project</div>
      <div style="display:flex;align-items:center;gap:6px;margin-bottom:2px"><div style="width:10px;height:10px;border-radius:2px;background:var(--ok)"></div> Completed</div>
      <div style="display:flex;align-items:center;gap:6px;margin-bottom:2px"><div style="width:10px;height:10px;border-radius:2px;background:var(--warn)"></div> In progress</div>
      <div style="display:flex;align-items:center;gap:6px"><div style="width:10px;height:10px;border-radius:2px;background:var(--tx3)"></div> Todo</div>
    </div>
    <canvas class="graph-canvas" id="graph-canvas"></canvas>
  </div>`;

  setTimeout(() => drawGraph(p), 200);
}

function drawGraph(p) {
  const canvas = document.getElementById('graph-canvas');
  if (!canvas) return;
  const w = canvas.offsetWidth || 600;
  const h = 500;
  canvas.width = w;
  canvas.height = h;
  const ctx = canvas.getContext('2d');

  // Background
  ctx.fillStyle = getComputedStyle(document.documentElement).getPropertyValue('--sur').trim() || '#fff';
  ctx.fillRect(0, 0, w, h);

  const tasks = p.tasks || [];
  if (tasks.length === 0) {
    ctx.fillStyle = '#8E8BAD';
    ctx.font = '14px Inter, sans-serif';
    ctx.textAlign = 'center';
    ctx.fillText('Add tasks to see the dependency graph', w/2, h/2);
    return;
  }

  // Arrange nodes in a radial layout
  const cx = w / 2, cy = h / 2;
  const radius = Math.min(w, h) * 0.35;
  const nodes = tasks.map((t, i) => {
    const angle = (i / tasks.length) * Math.PI * 2 - Math.PI / 2;
    return {
      x: cx + Math.cos(angle) * radius,
      y: cy + Math.sin(angle) * radius,
      id: t.id,
      title: t.title,
      status: t.status,
      priority: t.priority,
      color: t.status === 'DONE' ? '#1D9E75' : t.status === 'IN_PROGRESS' ? '#BA7517' : '#8E8BAD',
      radius: t.priority === 'HIGH' ? 28 : t.priority === 'MEDIUM' ? 22 : 18,
    };
  });

  // Draw edges (dependencies — simulated as sequential for demo)
  ctx.strokeStyle = getComputedStyle(document.documentElement).getPropertyValue('--bor').trim() || '#E4E3F0';
  ctx.lineWidth = 2;
  for (let i = 0; i < nodes.length - 1; i++) {
    ctx.beginPath();
    ctx.moveTo(nodes[i].x, nodes[i].y);
    ctx.lineTo(nodes[i + 1].x, nodes[i + 1].y);
    ctx.stroke();
  }

  // Draw nodes
  nodes.forEach(n => {
    // Circle
    ctx.beginPath();
    ctx.arc(n.x, n.y, n.radius, 0, Math.PI * 2);
    ctx.fillStyle = n.color + '22';
    ctx.fill();
    ctx.strokeStyle = n.color;
    ctx.lineWidth = 2.5;
    ctx.stroke();

    // Label
    ctx.fillStyle = getComputedStyle(document.documentElement).getPropertyValue('--tx').trim() || '#0F0E1A';
    ctx.font = '10px Inter, sans-serif';
    ctx.textAlign = 'center';
    const words = n.title.split(' ');
    const line1 = words.slice(0, 2).join(' ');
    const line2 = words.slice(2, 4).join(' ');
    ctx.fillText(line1, n.x, n.y - 3);
    if (line2) ctx.fillText(line2, n.x, n.y + 11);
  });

  // Center label
  ctx.fillStyle = getComputedStyle(document.documentElement).getPropertyValue('--brand').trim() || '#534AB7';
  ctx.font = 'bold 14px Inter, sans-serif';
  ctx.textAlign = 'center';
  ctx.fillText(p.title, cx, cy);
}

/* ── Activity Feed ─────────────────────────────────────────────────── */
function renderActivity(container, p) {
  const evts = [
    { ic: '✓', tx: `<strong>Jamie D.</strong> completed "Initial project brief"`, tm: '2h ago' },
    { ic: '📎', tx: `<strong>Alex M.</strong> uploaded <em>wireframes_v3.fig</em>`, tm: '4h ago' },
    { ic: '👤', tx: `<strong>Kim L.</strong> joined the project`, tm: 'Yesterday' },
    { ic: '✏️', tx: `<strong>Jamie D.</strong> updated the project description`, tm: '2 days ago' },
    { ic: '🔑', tx: `<strong>Jamie D.</strong> created project and generated invite key`, tm: '3 days ago' },
  ];
  container.innerHTML = `<div style="max-width:560px" class="stagger">
    <div style="background:var(--sur);border:1px solid var(--bor);border-radius:var(--rl);overflow:hidden">
      ${evts.map(e => `<div style="display:flex;gap:12px;padding:12px 16px;border-bottom:1px solid var(--bor)">
        <span style="font-size:16px;width:24px;flex-shrink:0">${e.ic}</span>
        <div><div style="font-size:13px">${e.tx}</div><div style="font-size:11px;color:var(--tx3);margin-top:2px">${e.tm}</div></div>
      </div>`).join('')}
    </div>
  </div>`;
}

/* ── Department Workstation Router ──────────────────────────────────── */
function renderWS(container, p, fk) {
  if (fk === 'terminal_console') wsTerminal(container, p);
  else if (fk === 'model_viewer') wsModel(container, p);
  else if (fk === 'spreadsheet_viewer') wsSheet(container, p);
  else if (fk === 'visual_board') wsVisual(container, p);
  else if (fk === 'citation_engine') wsCitation(container, p);
  else if (fk === 'latex_editor') wsLatex(container, p);
  else if (fk === 'lab_notebook') wsLab(container, p);
  else if (fk === 'survey_builder') wsSurvey(container, p);
  else if (fk === 'case_board') wsCase(container, p);
  else if (fk === 'case_study_editor') wsCaseStudy(container, p);
  else if (fk === 'blueprint_viewer') wsBlueprint(container, p);
  else if (fk === 'debate_board') wsDebate(container, p);
  else container.innerHTML = `<div class="empty"><p>Workstation coming soon</p></div>`;
}

/* ── Terminal Console (Computer Science) ────────────────────────────── */
let _termHistory = ['Welcome to the uni-co Terminal Console.', 'Type "help" for available commands.', ''];

function wsTerminal(c, p) {
  c.innerHTML = `<div class="term-wrap">
    <div class="term-bar">
      <div class="cdots"><div class="cdot" style="background:#FF5F57"></div><div class="cdot" style="background:#FFBD2E"></div><div class="cdot" style="background:#28C840"></div></div>
      <span style="font-size:11px;color:#666;font-family:var(--mono)">terminal — ${esc(p.title)}</span>
      <button class="cbtn" style="margin-left:auto;background:transparent;color:#aaa" onclick="_termHistory=[];reloadWs()">clear</button>
    </div>
    <div class="term-body" id="term-body">
      ${_termHistory.map(l => `<div class="term-line ${l.startsWith('$ ')?'term-prompt':l.startsWith('Error')?'term-error':'term-output'}">${esc(l)}</div>`).join('')}
    </div>
    <div class="term-input-row">
      <span style="color:#00FF88;font-family:var(--mono);font-size:12px">$</span>
      <input class="term-input" id="term-input" placeholder="Type a command..." onkeydown="if(event.key==='Enter')runTermCmd()" autofocus>
    </div>
  </div>`;

  const body = document.getElementById('term-body');
  if (body) body.scrollTop = body.scrollHeight;
  setTimeout(() => document.getElementById('term-input')?.focus(), 100);
}

function runTermCmd() {
  const inp = document.getElementById('term-input');
  if (!inp) return;
  const cmd = inp.value.trim();
  inp.value = '';
  if (!cmd) return;

  _termHistory.push(`$ ${cmd}`);

  const parts = cmd.split(' ');
  const main = parts[0].toLowerCase();
  const args = parts.slice(1);

  const tasks = (window._wsProject?.tasks || []);
  const todoCount = tasks.filter(t => t.status === 'TODO').length;
  const ipCount = tasks.filter(t => t.status === 'IN_PROGRESS').length;
  const doneCount = tasks.filter(t => t.status === 'DONE').length;

  const commands = {
    help: () => [
      'Available commands:',
      '  help          — Show this message',
      '  status        — Project task summary',
      '  tasks         — List all tasks',
      '  files         — Show file count',
      '  members       — List team members',
      '  key           — Show invite key',
      '  echo [text]   — Print text',
      '  date          — Current date/time',
      '  whoami        — Your username',
      '  clear         — Clear terminal (refresh)',
      '  math [expr]   — Evaluate simple math (e.g. math 2+3*4)',
    ],
    status: () => [`📊 ${esc(window._wsProject?.title)} — ${todoCount} todo, ${ipCount} in progress, ${doneCount} done`],
    tasks: () => tasks.map(t => `  [${t.status === 'DONE' ? '✓' : t.status === 'IN_PROGRESS' ? '▶' : '○'}] ${t.title} (${t.priority})`),
    files: () => [`📁 ${(window._wsProject?.files || []).length} files uploaded`],
    members: () => (window._wsProject?.members || []).map(m => `  ${m.user?.fullName || 'Unknown'} — ${m.role}`),
    key: () => [`🔑 ${window._wsProject?.inviteKey?.keyCode || 'No active key'}`],
    echo: () => [args.join(' ')],
    date: () => [new Date().toString()],
    whoami: () => [S.user?.fullName || 'unknown'],
    math: () => {
      try {
        const expr = args.join('');
        // Safe eval: only allow numbers, operators, parens, and spaces
        if (!/^[\d\s+\-*/().]+$/.test(expr)) return ['Error: invalid expression'];
        const result = Function(`"use strict"; return (${expr})`)();
        return [`= ${result}`];
      } catch (e) { return [`Error: ${e.message}`]; }
    },
  };

  const output = commands[main] ? commands[main]() : [`Command not found: ${main}. Type "help" for commands.`];
  _termHistory.push(...output.map(l => String(l)));
  _termHistory.push('');

  // Re-render terminal body
  const body = document.getElementById('term-body');
  if (body) {
    body.innerHTML = _termHistory.map(l =>
      `<div class="term-line ${l.startsWith('$ ') ? 'term-prompt' : l.startsWith('Error') || l.startsWith('Command not found') ? 'term-error' : 'term-output'}">${esc(l)}</div>`
    ).join('');
    body.scrollTop = body.scrollHeight;
  }
}

/* ── Citation Engine (English & Literature) ─────────────────────────── */
let _citations = [];

function wsCitation(c, p) {
  function renderCitations() {
    const list = document.getElementById('cite-list');
    if (!list) return;
    list.innerHTML = _citations.length === 0
      ? `<p style="color:var(--tx3);font-size:13px">No citations yet. Add one using the form.</p>`
      : _citations.map((cit, i) => `<div class="cite-item" onclick="copyCitation(${i})">
          <div style="font-size:12px;line-height:1.6">${cit.formatted}</div>
          <div style="font-size:10px;color:var(--tx3);margin-top:3px">${cit.style} · Click to copy</div>
        </div>`).join('');
  }

  c.innerHTML = `<div class="cite-wrap">
    <div class="cite-input">
      <h3 style="margin-bottom:12px">Add Citation</h3>
      <div class="fg"><label class="fl" for="cite-style">Style</label><select class="fi fi-select" id="cite-style"><option value="APA">APA 7th</option><option value="MLA">MLA 9th</option></select></div>
      <div class="frow">
        <div class="fg"><label class="fl" for="cite-author">Author(s)</label><input class="fi" id="cite-author" placeholder="e.g. Smith, J."></div>
        <div class="fg"><label class="fl" for="cite-year">Year</label><input class="fi" id="cite-year" placeholder="2024"></div>
      </div>
      <div class="fg"><label class="fl" for="cite-title">Title</label><input class="fi" id="cite-title" placeholder="Article or book title"></div>
      <div class="fg"><label class="fl" for="cite-source">Source / Journal</label><input class="fi" id="cite-source" placeholder="Journal name or publisher"></div>
      <div class="frow">
        <div class="fg"><label class="fl" for="cite-vol">Volume</label><input class="fi" id="cite-vol" placeholder="e.g. 12"></div>
        <div class="fg"><label class="fl" for="cite-pages">Issue / Pages</label><input class="fi" id="cite-pages" placeholder="e.g. 45-67"></div>
      </div>
      <div class="fg"><label class="fl" for="cite-doi">DOI or URL</label><input class="fi" id="cite-doi" placeholder="https://doi.org/..."></div>
      <button class="btn btn-primary" onclick="addCitation()">Generate Citation</button>
    </div>
    <div class="cite-output">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px">
        <h3>Bibliography</h3>
        <button class="btn btn-sm" onclick="exportCitations()">Export .bib</button>
      </div>
      <div id="cite-list"></div>
    </div>
  </div>`;

  window.addCitation = () => {
    const style = document.getElementById('cite-style')?.value || 'APA';
    const author = document.getElementById('cite-author')?.value?.trim();
    const year = document.getElementById('cite-year')?.value?.trim();
    const title = document.getElementById('cite-title')?.value?.trim();
    const source = document.getElementById('cite-source')?.value?.trim();
    const vol = document.getElementById('cite-vol')?.value?.trim();
    const pages = document.getElementById('cite-pages')?.value?.trim();
    const doi = document.getElementById('cite-doi')?.value?.trim();

    if (!author || !title) { toast('Author and title required', 'error'); return; }

    let formatted = '';
    if (style === 'APA') {
      formatted = `${author} (${year || 'n.d.'}). ${title}. `;
      if (source) formatted += `<em>${source}</em>`;
      if (vol) formatted += `, <em>${vol}</em>`;
      if (pages) formatted += `(${pages})`;
      formatted += '.';
      if (doi) formatted += ` https://doi.org/${doi.replace('https://doi.org/', '')}`;
    } else { // MLA
      formatted = `${author}. "${title}." `;
      if (source) formatted += `<em>${source}</em>`;
      if (vol) formatted += `, vol. ${vol}`;
      if (year) formatted += `, ${year}`;
      if (pages) formatted += `, pp. ${pages}`;
      formatted += '.';
      if (doi) formatted += ` ${doi}`;
    }

    _citations.push({ style, formatted, raw: { author, year, title, source, vol, pages, doi } });
    toast('Citation added!', 'success');
    ['cite-author', 'cite-year', 'cite-title', 'cite-source', 'cite-vol', 'cite-pages', 'cite-doi'].forEach(id => {
      const el = document.getElementById(id); if (el) el.value = '';
    });
    renderCitations();
  };

  window.copyCitation = (i) => {
    const text = _citations[i]?.formatted?.replace(/<[^>]*>/g, '') || '';
    navigator.clipboard.writeText(text).then(() => toast('Citation copied!', 'success'));
  };

  window.exportCitations = () => {
    const bib = _citations.map(c => c.formatted.replace(/<[^>]*>/g, '')).join('\n\n');
    const blob = new Blob([bib], { type: 'text/plain' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'bibliography.txt';
    a.click();
    toast('Bibliography exported', 'success');
  };

  renderCitations();
}

/* ═══════════════════════════════════════════════════════════════════
   SECTION 3 (continued) — Department Workstations 3-12
═══════════════════════════════════════════════════════════════════ */

/* ── Model Viewer (Engineering) ──────────────────────────────────────── */
let _modelAngle = 0, _modelDragging = false, _modelLastX = 0;

function wsModel(c, p) {
  c.innerHTML = `<div>
    <div class="mview">
      <div class="mcanvas" id="mcanvas"><canvas id="mc" style="width:100%;height:100%"></canvas>
        <div style="position:absolute;top:10px;right:10px;display:flex;flex-direction:column;gap:4px">
          <button class="mbtn" onclick="zoomModel(1.1)">+</button>
          <button class="mbtn" onclick="zoomModel(0.9)">−</button>
          <button class="mbtn" onclick="_modelAngle=0;initModel()">⟳</button>
        </div>
        <div style="position:absolute;bottom:10px;left:12px;font-size:11px;color:#666">Drag to rotate · Scroll to zoom</div>
      </div>
      <div class="mctrl">
        <button class="mbtn on" id="mv-persp" onclick="setView('persp')">Perspective</button>
        <button class="mbtn" id="mv-top" onclick="setView('top')">Top</button>
        <button class="mbtn" id="mv-front" onclick="setView('front')">Front</button>
        <div style="margin-left:auto;display:flex;gap:4px">
          <button class="mbtn" onclick="toast('Wireframe mode')">Wireframe</button>
          <button class="mbtn" onclick="toast('Solid mode')">Solid</button>
          <button class="mbtn" onclick="toast('Rendered mode')">Render</button>
        </div>
      </div>
    </div>
    <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:10px;margin-top:12px">
      ${[['Vertices','12,480'],['Faces','24,960'],['Materials','3']].map(([l,v]) => `<div class="stat"><div style="font-size:11px;color:var(--tx3);margin-bottom:4px">${l}</div><div style="font-size:18px;font-weight:700">${v}</div></div>`).join('')}
    </div>
    <div style="background:var(--sur);border:1px solid var(--bor);border-radius:var(--rl);padding:14px;margin-top:12px">
      <div style="font-size:12px;font-weight:600;margin-bottom:10px">Annotations</div>
      ${['Bearing load point — max 450 kN','Structural joint — welded connection','Foundation anchor — M24 bolts ×8'].map((a,i) => `<div style="display:flex;align-items:center;gap:8px;padding:6px 0;border-bottom:1px solid var(--bor);font-size:12px"><span style="width:18px;height:18px;border-radius:50%;background:var(--brand-l);color:var(--brand);font-size:10px;font-weight:700;display:flex;align-items:center;justify-content:center;flex-shrink:0">${i+1}</span>${a}</div>`).join('')}
      <button class="btn btn-sm" style="margin-top:8px" onclick="toast('Annotation added','success')">${I.pl} Add annotation</button>
    </div>
  </div>`;
  initModel();
}

let _modelZoom = 1;
function initModel() {
  const canvas = document.getElementById('mc');
  if (!canvas) return;
  const w = canvas.offsetWidth || 600;
  const h = 340;
  canvas.width = w; canvas.height = h;
  const ctx = canvas.getContext('2d');
  if (!ctx) return;

  const cx = w / 2, cy = h / 2, sz = Math.min(w, h) * 0.22 * _modelZoom;

  canvas.onmousedown = e => { _modelDragging = true; _modelLastX = e.clientX; };
  canvas.onmousemove = e => {
    if (_modelDragging) { _modelAngle += (e.clientX - _modelLastX) * 0.006; _modelLastX = e.clientX; }
  };
  canvas.onmouseup = () => _modelDragging = false;
  canvas.onmouseleave = () => _modelDragging = false;
  canvas.onwheel = e => { e.preventDefault(); zoomModel(e.deltaY < 0 ? 1.1 : 0.9); };

  function draw() {
    ctx.fillStyle = '#1a1a2e';
    ctx.fillRect(0, 0, w, h);
    ctx.strokeStyle = 'rgba(0,80,180,0.12)';
    ctx.lineWidth = 0.5;
    for (let x = 0; x < w; x += 30) { ctx.beginPath(); ctx.moveTo(x, 0); ctx.lineTo(x, h); ctx.stroke(); }
    for (let y = 0; y < h; y += 30) { ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(w, y); ctx.stroke(); }

    const cos = Math.cos(_modelAngle), sin = Math.sin(_modelAngle);
    const proj = ([x, y, z]) => [cx + (x * cos - z * sin) * 0.8, cy + (y - (x * sin + z * cos) * 0.4)];
    const v = [[-1,-1,-1],[1,-1,-1],[1,1,-1],[-1,1,-1],[-1,-1,1],[1,-1,1],[1,1,1],[-1,1,1]].map(a => proj([a[0]*sz, a[1]*sz, a[2]*sz]));
    const faces = [[0,1,2,3,'rgba(83,74,183,0.55)'],[4,5,6,7,'rgba(83,74,183,0.35)'],[0,1,5,4,'rgba(100,95,200,0.45)'],[2,3,7,6,'rgba(60,52,137,0.45)'],[0,3,7,4,'rgba(70,65,180,0.45)'],[1,2,6,5,'rgba(90,82,200,0.45)']];
    faces.forEach(([a,b_,c_,d,fill]) => {
      ctx.beginPath(); ctx.moveTo(...v[a]); ctx.lineTo(...v[b_]); ctx.lineTo(...v[c_]); ctx.lineTo(...v[d]); ctx.closePath();
      ctx.fillStyle = fill; ctx.fill();
      ctx.strokeStyle = 'rgba(180,180,255,0.3)'; ctx.lineWidth = 1; ctx.stroke();
    });
    if (!_modelDragging) _modelAngle += 0.006;
    requestAnimationFrame(draw);
  }
  draw();
}
function zoomModel(factor) { _modelZoom = Math.max(0.3, Math.min(3, _modelZoom * factor)); initModel(); }
function setView(v) {
  if (v === 'top') _modelAngle = 0;
  else if (v === 'front') _modelAngle = Math.PI / 2;
  else _modelAngle = 0.6;
  document.querySelectorAll('#mv-persp, #mv-top, #mv-front').forEach(b => b.classList.remove('on'));
  document.getElementById('mv-' + v)?.classList.add('on');
  initModel();
}

/* ── Spreadsheet (Business & Economics) ─────────────────────────────── */
function wsSheet(c, p) {
  const rows = [
    ['Quarter','Revenue ($K)','Expenses ($K)','Net ($K)','Growth %'],
    ['Q1 2025','1,240','890','350','—'],
    ['Q2 2025','1,580','1,020','560','60%'],
    ['Q3 2025','1,920','1,180','740','32%'],
    ['Q4 2025','2,340','1,350','990','34%'],
    ['Total','7,080','4,440','2,640','—']
  ];
  c.innerHTML = `<div>
    <div style="background:var(--sur);border:1px solid var(--bor);border-radius:var(--rl);overflow:hidden">
      <div style="padding:8px 12px;border-bottom:1px solid var(--bor);background:var(--bg2);display:flex;gap:4px;flex-wrap:wrap">
        ${['Bold','Italic','|','Align L','Align R','|','$ Format','% Format','|','Sum','Avg'].map(t => t==='|'?`<div style="width:1px;height:18px;background:var(--bor);margin:0 2px"></div>`:`<button class="btn btn-ghost btn-sm" onclick="toast('${t} applied')">${t}</button>`).join('')}
        <button class="btn btn-primary btn-sm" style="margin-left:auto" onclick="exportCSV()">Export CSV</button>
      </div>
      <div style="overflow-x:auto"><table class="sheet">
        <tr><th style="width:32px"></th>${['A','B','C','D','E'].map(c_ => `<th style="min-width:120px">${c_}</th>`).join('')}</tr>
        ${rows.map((row,ri) => `<tr><td style="background:var(--bg2);font-weight:600;color:var(--tx2);text-align:center">${ri+1}</td>${row.map(cell => `<td contenteditable="true" style="${ri===0||ri===rows.length-1?'font-weight:600;background:var(--bg2)':''}">${cell}</td>`).join('')}</tr>`).join('')}
      </table></div>
    </div>
    <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin-top:12px">
      ${[['Revenue','$7,080K','var(--ok-bg)','var(--ok)'],['Expenses','$4,440K','var(--err-bg)','var(--err)'],['Net Profit','$2,640K','var(--info-bg)','var(--info)'],['Avg Growth','42%','var(--warn-bg)','var(--warn)']].map(([l,v,bg1,col]) => `<div style="background:${bg1};border-radius:var(--rl);padding:14px"><div style="font-size:11px;color:${col};font-weight:600;margin-bottom:4px">${l}</div><div style="font-size:22px;font-weight:700;color:${col}">${v}</div></div>`).join('')}
    </div>
  </div>`;
}
function exportCSV() {
  const blob = new Blob(['Quarter,Revenue,Expenses,Net,Growth\n'], { type: 'text/csv' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'data.csv';
  a.click();
  toast('Exported as CSV', 'success');
}

/* ── Visual Board (Arts & Design) ───────────────────────────────────── */
function wsVisual(c, p) {
  const swatches = [['#534AB7','Brand Purple'],['#1D9E75','Brand Teal'],['#F5C4B3','Soft Coral'],['#E6F1FB','Sky Blue'],['#FAEEDA','Warm Amber'],['#EAF3DE','Sage Green']];
  c.innerHTML = `<div style="display:grid;grid-template-columns:1fr 200px;gap:14px">
    <div>
      <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:10px"><h3>Mood board</h3><button class="btn btn-sm" onclick="toast('Image added','success')">${I.pl} Add image</button></div>
      <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(130px,1fr));gap:8px">
        ${swatches.map(([bg,lbl]) => `<div style="background:${bg};border-radius:var(--r);aspect-ratio:1;display:flex;align-items:flex-end;padding:8px;cursor:pointer;transition:transform .2s;border:1px solid var(--bor)" onclick="toast('${lbl} selected')" onmouseover="this.style.transform='scale(1.02)'" onmouseout="this.style.transform=''"><span style="font-size:10px;font-weight:600;color:rgba(0,0,0,.5)">${lbl}</span></div>`).join('')}
        ${[1,2].map(() => `<div style="border:2px dashed var(--bor);border-radius:var(--r);aspect-ratio:1;display:flex;align-items:center;justify-content:center;cursor:pointer;color:var(--tx3)" onclick="toast('Click + Add image to upload')"><span style="font-size:24px">+</span></div>`).join('')}
      </div>
      <textarea class="fi fi-ta" style="margin-top:12px" rows="3" placeholder="Visual direction notes...">Minimalist approach — clean geometric forms. Primary palette: purple anchor with warm neutral accents.</textarea>
    </div>
    <div>
      <div class="ssec"><div class="sslbl">Colour palette</div>
        ${swatches.map(([bg,lbl]) => `<div style="display:flex;align-items:center;gap:8px;padding:5px 0;border-bottom:1px solid var(--bor)">
          <div style="width:22px;height:22px;border-radius:4px;background:${bg};border:1px solid var(--bor);flex-shrink:0"></div>
          <div style="flex:1"><div style="font-size:12px;font-weight:500">${lbl}</div><div style="font-size:10px;color:var(--tx3)">${bg}</div></div>
          <button class="btn btn-ghost btn-sm" onclick="navigator.clipboard.writeText('${bg}').then(()=>toast('Hex copied!','success'))">${I.cp}</button>
        </div>`).join('')}
      </div>
    </div>
  </div>`;
}

/* ── LaTeX Editor (Mathematics) ──────────────────────────────────────── */
function wsLatex(c, p) {
  c.innerHTML = `<div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;height:calc(100vh - 180px)">
    <div style="display:flex;flex-direction:column">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px"><h3>LaTeX source</h3><button class="btn btn-primary btn-sm" onclick="toast('Compiled!','success')">Compile</button></div>
      <textarea class="fi fi-ta" rows="20" style="flex:1;font-family:var(--mono);font-size:12px;background:#1e1e2e;color:#cdd6f4;border-color:var(--bor)">\\documentclass{article}\n\\usepackage{amsmath}\n\\title{Convergence of Fourier Series}\n\\author{Research Group}\n\\begin{document}\n\\maketitle\n\\section{Introduction}\nLet $f: [-\\pi, \\pi] \\to \\mathbb{R}$ be square-integrable.\nThe Fourier series is:\n\\begin{equation}\n  f(x) = \\frac{a_0}{2} + \\sum_{n=1}^{\\infty}(a_n \\cos nx + b_n \\sin nx)\n\\end{equation}\n\\end{document}</textarea>
    </div>
    <div style="display:flex;flex-direction:column">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px"><h3>Preview</h3><button class="btn btn-sm" onclick="toast('Export PDF — connect LaTeX backend','info')">Export PDF</button></div>
      <div style="background:var(--sur);border:1px solid var(--bor);border-radius:var(--rl);padding:24px;font-size:14px;line-height:1.8;flex:1;overflow-y:auto">
        <div style="text-align:center;margin-bottom:16px;padding-bottom:14px;border-bottom:1px solid var(--bor)"><div style="font-size:18px;font-weight:700">Convergence of Fourier Series</div><div style="font-size:13px;color:var(--tx2);margin-top:4px">Research Group</div></div>
        <div style="font-size:14px;font-weight:700;margin-bottom:8px">1. Introduction</div>
        <p style="margin-bottom:12px">Let <em>f</em> : [−π, π] → ℝ be square-integrable. The Fourier series is defined as:</p>
        <div style="text-align:center;padding:12px;background:var(--bg2);border-radius:var(--r);font-size:15px;margin-bottom:12px"><em>f</em>(x) = a₀/2 + Σ(aₙcos(nx) + bₙsin(nx))</div>
        <div style="padding:10px 14px;background:var(--bg2);border-radius:var(--r)"><div>aₙ = (1/π) ∫₋π^π f(x)cos(nx) dx</div><div style="margin-top:6px">bₙ = (1/π) ∫₋π^π f(x)sin(nx) dx</div></div>
      </div>
    </div>
  </div>`;
}

/* ── Lab Notebook (Biology & Life Sciences) ──────────────────────────── */
function wsLab(c, p) {
  c.innerHTML = `<div style="max-width:700px">
    <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:12px"><h3>Lab notebook</h3><button class="btn btn-primary btn-sm" onclick="addLabEntry()">${I.pl} New entry</button></div>
    <div id="lab-entries">
      <div class="lab-entry">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;padding-bottom:10px;border-bottom:1px solid var(--bor)">
          <div><div style="font-size:14px;font-weight:600">Experiment 3 — Gene expression analysis</div><div style="font-size:11px;color:var(--tx3)">Apr 17, 2026 · Jamie Davis</div></div>
          <span class="badge b-teal">In progress</span>
        </div>
        ${[['Hypothesis','Elevated CO₂ will upregulate stress-response genes in E. coli by ≥40%.'],['Materials','E. coli K-12, LB broth, CO₂ incubator, qRT-PCR reagents, RNA extraction kit'],['Procedure','1. Culture at 37°C, 5% CO₂ for 4h. 2. Extract RNA. 3. Run qRT-PCR for rpoS, katG, oxyR. 4. Analyse ΔΔCt values.']].map(([l,v]) => `<div class="lab-field"><div class="lab-lbl">${l}</div><div style="font-size:13px">${v}</div></div>`).join('')}
        <div class="lab-field"><div class="lab-lbl">Results</div><textarea class="fi fi-ta" rows="2" style="font-size:12px">Preliminary: rpoS upregulated 2.3×. katG 1.8×. Awaiting replicate confirmation.</textarea></div>
        <div class="lab-field"><div class="lab-lbl">Conclusion</div><textarea class="fi fi-ta" rows="2" style="font-size:12px">Partial confirmation of hypothesis. Full statistical analysis pending n=3 replicates.</textarea></div>
      </div>
    </div>
  </div>`;
}
function addLabEntry() {
  const c = document.getElementById('lab-entries');
  const el = document.createElement('div');
  el.className = 'lab-entry';
  el.style.marginBottom = '10px';
  el.innerHTML = `<div style="font-size:14px;font-weight:600;margin-bottom:12px">New experiment · ${new Date().toLocaleDateString()}</div>${['Hypothesis','Materials','Procedure','Results','Conclusion'].map(f => `<div class="lab-field"><div class="lab-lbl">${f}</div><textarea class="fi fi-ta" rows="2" style="font-size:12px" placeholder="${f}..."></textarea></div>`).join('')}`;
  c.prepend(el);
  toast('New lab entry created', 'success');
}

/* ── Survey Builder (Psychology) ────────────────────────────────────── */
function wsSurvey(c, p) {
  c.innerHTML = `<div style="display:grid;grid-template-columns:1fr 190px;gap:12px">
    <div>
      <div style="display:flex;justify-content:space-between;margin-bottom:10px">
        <div><h3>Academic Stress Questionnaire</h3><div style="font-size:12px;color:var(--tx2)">4 questions · Anonymous</div></div>
        <div style="display:flex;gap:6px"><button class="btn btn-sm" onclick="toast('Preview opened')">Preview</button><button class="btn btn-primary btn-sm" onclick="navigator.clipboard.writeText(location.href).then(()=>toast('Link copied!','success'))">Share link</button></div>
      </div>
      <div class="sqst"><div style="font-size:10px;font-weight:600;text-transform:uppercase;letter-spacing:.5px;color:var(--tx3);margin-bottom:6px">Q1 · Multiple choice</div>
        <div style="font-size:14px;font-weight:500;margin-bottom:10px">How often do you feel overwhelmed by your academic workload?</div>
        ${['Never','Rarely (once a month)','Sometimes (once a week)','Often (most days)'].map(o => `<label style="display:flex;align-items:center;gap:8px;padding:5px 0;font-size:13px;cursor:pointer"><input type="radio" name="q1" style="accent-color:var(--brand)"> ${o}</label>`).join('')}
      </div>
      <div class="sqst"><div style="font-size:10px;font-weight:600;text-transform:uppercase;letter-spacing:.5px;color:var(--tx3);margin-bottom:6px">Q2 · Likert scale</div>
        <div style="font-size:14px;font-weight:500;margin-bottom:10px">I feel confident managing my deadlines this semester.</div>
        <div class="likert"><span style="font-size:11px;color:var(--tx3)">Strongly disagree</span>
          ${[1,2,3,4,5].map(i => `<div class="lbtn" onclick="this.classList.toggle('on')">${i}</div>`).join('')}
          <span style="font-size:11px;color:var(--tx3)">Strongly agree</span>
        </div>
      </div>
      <div class="sqst"><div style="font-size:10px;font-weight:600;text-transform:uppercase;letter-spacing:.5px;color:var(--tx3);margin-bottom:6px">Q3 · Open text</div>
        <div style="font-size:14px;font-weight:500;margin-bottom:8px">Describe a recent situation where academic pressure affected your wellbeing.</div>
        <textarea class="fi fi-ta" rows="3" placeholder="Respondents type here..."></textarea>
      </div>
      <button class="btn btn-sm" onclick="toast('Question added','success')">${I.pl} Add question</button>
    </div>
    <div>
      <div class="ssec"><div class="sslbl">Responses</div>
        <div class="stat" style="margin-bottom:8px"><div class="stat-lbl">Total</div><div class="stat-val">24</div></div>
        <div class="stat"><div class="stat-lbl">Completion</div><div class="stat-val">87%</div></div>
        <button class="btn btn-sm btn-block" style="margin-top:8px" onclick="toast('Results exported','success')">Export results</button>
      </div>
      <div class="ssec"><div class="sslbl">Question types</div>
        ${[['Multiple choice','purple'],['Likert scale','amber'],['Open text','teal'],['Yes / No','blue'],['Rating','green']].map(([t,col]) => `<div style="margin-bottom:4px"><span class="badge b-${col}">${t}</span></div>`).join('')}
      </div>
    </div>
  </div>`;
}

/* ── Case Board (Law) ───────────────────────────────────────────────── */
function wsCase(c, p) {
  c.innerHTML = `<div>
    <div style="background:var(--sur);border:2px solid var(--brand);border-radius:var(--rl);padding:14px;margin-bottom:14px;text-align:center">
      <div style="font-size:10px;font-weight:600;color:var(--brand);text-transform:uppercase;letter-spacing:.6px;margin-bottom:6px">Matter</div>
      <div style="font-size:15px;font-weight:600">Constitutional challenge to emergency ministerial powers under s.33 Charter Act</div>
    </div>
    <div style="background:var(--sur);border:1px solid var(--bor);border-radius:var(--rl);padding:14px;margin-bottom:10px">
      <div style="font-size:12px;font-weight:600;margin-bottom:10px">Issue statement</div>
      <textarea class="fi fi-ta" rows="3">Whether the Minister's use of emergency powers constitutes a disproportionate restriction on freedom of expression under s.2(b) of the Charter.</textarea>
    </div>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:10px">
      <div class="dside" style="border-top:3px solid var(--ok)">
        <div style="display:flex;justify-content:space-between;margin-bottom:10px"><div style="font-weight:600;color:var(--ok)">Applicant</div><span class="badge b-teal">Prosecution</span></div>
        <div id="ap-args">${['The restriction was not prescribed by law as required.','Government failed to demonstrate pressing and substantial objective.','Less restrictive alternatives were available — means not proportional.'].map(a => `<div class="darg" onclick="upvoteArg(this)">${a}<div style="font-size:10px;color:var(--tx3);margin-top:3px">0 upvotes</div></div>`).join('')}</div>
        <button class="btn btn-sm btn-block" style="margin-top:6px" onclick="addArg('ap-args')">${I.pl} Add argument</button>
      </div>
      <div class="dside" style="border-top:3px solid var(--err)">
        <div style="display:flex;justify-content:space-between;margin-bottom:10px"><div style="font-weight:600;color:var(--err)">Respondent</div><span class="badge b-coral">Defence</span></div>
        <div id="re-args">${['Order is prescribed by law through enabling legislation.','National security constitutes pressing and substantial objective.','The Oakes test is satisfied — rights limitation is minimal.'].map(a => `<div class="darg" onclick="upvoteArg(this)">${a}<div style="font-size:10px;color:var(--tx3);margin-top:3px">0 upvotes</div></div>`).join('')}</div>
        <button class="btn btn-sm btn-block" style="margin-top:6px" onclick="addArg('re-args')">${I.pl} Add argument</button>
      </div>
    </div>
    <div style="background:var(--sur);border:1px solid var(--bor);border-radius:var(--rl);padding:14px">
      <div style="font-size:12px;font-weight:600;margin-bottom:10px">Citations</div>
      ${[['R v Oakes [1986] 1 SCR 103','Oakes test for s.1 justification'],['Irwin Toy Ltd v Quebec [1989]','Breadth of expression protection']].map(([cn,note]) => `<div style="display:flex;justify-content:space-between;align-items:center;padding:7px 0;border-bottom:1px solid var(--bor);font-size:12px"><div><div style="font-weight:500">${cn}</div><div style="font-size:11px;color:var(--tx3)">${note}</div></div><button class="btn btn-ghost btn-sm" onclick="navigator.clipboard.writeText('${cn}').then(()=>toast('Copied!','success'))">${I.cp}</button></div>`).join('')}
      <button class="btn btn-sm" style="margin-top:8px" onclick="toast('Citation added','success')">${I.pl} Add citation</button>
    </div>
  </div>`;
}
function upvoteArg(el) {
  const s = el.querySelector('div');
  if (s) { const n = parseInt(s.textContent) || 0; s.textContent = (n + 1) + ' upvotes'; s.style.color = 'var(--brand)'; }
}
function addArg(id) {
  const t = prompt('Enter argument:');
  if (!t) return;
  const el = document.createElement('div');
  el.className = 'darg';
  el.setAttribute('onclick', 'upvoteArg(this)');
  el.innerHTML = esc(t) + `<div style="font-size:10px;color:var(--tx3);margin-top:3px">0 upvotes</div>`;
  document.getElementById(id)?.appendChild(el);
  toast('Argument added', 'success');
}

/* ── Case Study Editor (Medicine & Health) ──────────────────────────── */
function wsCaseStudy(c, p) {
  c.innerHTML = `<div style="max-width:720px">
    <div style="display:flex;justify-content:space-between;margin-bottom:12px"><h3>Clinical case study</h3><button class="btn btn-sm" onclick="exportCaseStudy()">Export</button></div>
    ${[['Patient presentation','63-year-old male, 3-day progressive dyspnoea, orthopnoea, peripheral oedema. PMH: Hypertension ×15y, T2DM ×8y, MI 2019. Rx: Ramipril 10mg, Metformin 1g BD, Aspirin 75mg.'],['Examination findings','HR 98 bpm (irregular), BP 148/92, RR 22/min, SpO₂ 91%. JVP elevated. Bilateral basal crackles. Pitting oedema to knees. S3 gallop.'],['Investigations','ECG: AF rate 98, LBBB. CXR: Cardiomegaly, bilateral pleural effusions. BNP 1,840 pg/mL, Troponin-T 42 ng/L (↑), eGFR 52.'],['Diagnosis','Acute decompensated heart failure (HFrEF) — precipitated by new-onset atrial fibrillation. Background ischaemic cardiomyopathy.'],['Management','1. IV furosemide 80mg stat + infusion. 2. Rate control: digoxin 0.5mg IV. 3. Continue ACEi if tolerated. 4. Anticoagulation: LMWH to warfarin. 5. Cardiology referral.']].map(([t,v]) => `<div class="case-sec"><div style="display:flex;justify-content:space-between;margin-bottom:8px"><h3>${t}</h3><button class="btn btn-ghost btn-sm">${I.ed}</button></div><textarea class="fi fi-ta" rows="3" style="font-size:13px">${v}</textarea></div>`).join('')}
  </div>`;
}
function exportCaseStudy() {
  const sections = [...document.querySelectorAll('.case-sec')].map(s => {
    const h = s.querySelector('h3')?.textContent || '';
    const t = s.querySelector('textarea')?.value || '';
    return `=== ${h} ===\n${t}`;
  }).join('\n\n');
  const blob = new Blob([sections], { type: 'text/plain' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'case-study.txt';
  a.click();
  toast('Case study exported', 'success');
}

/* ── Blueprint Viewer (Architecture) ─────────────────────────────────── */
function wsBlueprint(c, p) {
  c.innerHTML = `<div>
    <div class="bpview">
      <canvas class="bpcanvas" id="bpc"></canvas>
      <div class="mctrl">
        <button class="mbtn on" onclick="toast('Floor plan')">Floor plan</button>
        <button class="mbtn" onclick="toast('Elevation')">Elevation</button>
        <button class="mbtn" onclick="toast('Section')">Section</button>
        <div style="margin-left:auto;display:flex;gap:4px">
          <button class="mbtn" onclick="toast('DWG exported','success')">Export DWG</button>
          <button class="mbtn" onclick="toast('PDF exported','success')">Export PDF</button>
        </div>
      </div>
    </div>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-top:12px">
      <div style="background:var(--sur);border:1px solid var(--bor);border-radius:var(--rl);padding:14px">
        <div style="font-size:12px;font-weight:600;margin-bottom:8px">Room schedule</div>
        <table style="width:100%;border-collapse:collapse;font-size:12px">
          <tr style="border-bottom:1px solid var(--bor)"><th style="text-align:left;padding:4px 0;color:var(--tx2)">Room</th><th style="padding:4px;color:var(--tx2)">m²</th><th style="padding:4px;color:var(--tx2)">Occ.</th></tr>
          ${[['Living room',32,6],['Kitchen',18,4],['Master bed',22,2],['Bedroom 2',16,2],['Bathroom',8,1],['Hall',12,0]].map(([n,a,o]) => `<tr style="border-bottom:1px solid var(--bor)"><td style="padding:4px 0">${n}</td><td style="text-align:center">${a}</td><td style="text-align:center">${o}</td></tr>`).join('')}
          <tr><td style="padding:6px 0;font-weight:600">Total</td><td style="text-align:center;font-weight:600">108</td><td></td></tr>
        </table>
      </div>
      <div style="background:var(--sur);border:1px solid var(--bor);border-radius:var(--rl);padding:14px">
        <div style="font-size:12px;font-weight:600;margin-bottom:8px">Annotations</div>
        ${['N-facing glazing — solar gain analysis required','Load-bearing wall — structural sign-off needed','Accessibility route — 1800mm clear width'].map((a,i) => `<div style="display:flex;gap:8px;padding:5px 0;border-bottom:1px solid var(--bor);font-size:12px"><span style="width:18px;height:18px;border-radius:50%;background:#1a3654;color:#4ab8ff;font-size:10px;font-weight:700;display:flex;align-items:center;justify-content:center;flex-shrink:0">${i+1}</span>${a}</div>`).join('')}
        <button class="btn btn-sm" style="margin-top:8px" onclick="toast('Annotation added','success')">${I.pl} Add</button>
      </div>
    </div>
  </div>`;
  drawBP();
}
function drawBP() {
  const canvas = document.getElementById('bpc');
  if (!canvas) return;
  const w = canvas.offsetWidth || 600, h = 320;
  canvas.width = w; canvas.height = h;
  const ctx = canvas.getContext('2d');
  if (!ctx) return;
  ctx.fillStyle = '#0f1f33';
  ctx.fillRect(0, 0, w, h);
  ctx.strokeStyle = 'rgba(0,80,180,0.18)';
  ctx.lineWidth = 0.5;
  for (let x = 0; x < w; x += 25) { ctx.beginPath(); ctx.moveTo(x, 0); ctx.lineTo(x, h); ctx.stroke(); }
  for (let y = 0; y < h; y += 25) { ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(w, y); ctx.stroke(); }
  ctx.strokeStyle = '#4db8ff';
  ctx.lineWidth = 2;
  ctx.font = '11px Inter, sans-serif';
  ctx.fillStyle = '#4db8ff';
  ctx.textAlign = 'center';
  const rooms = [[50, 40, 200, 130, 'Living Room'], [50, 180, 200, 100, 'Kitchen'], [270, 40, 160, 120, 'Master Bed'], [270, 170, 160, 110, 'Bed 2'], [450, 40, 100, 90, 'Bath'], [50, 10, 400, 20, '']];
  rooms.forEach(([x, y, rw, rh, lbl]) => {
    ctx.strokeRect(x, y, rw, rh);
    if (lbl) { ctx.fillStyle = 'rgba(0,80,180,0.12)'; ctx.fillRect(x+1, y+1, rw-2, rh-2); ctx.fillStyle = '#4db8ff'; ctx.fillText(lbl, x+rw/2, y+rh/2+4); }
  });
}

/* ── Debate Board (Political Science) ───────────────────────────────── */
function wsDebate(c, p) {
  c.innerHTML = `<div>
    <div style="background:var(--sur);border:2px solid var(--brand);border-radius:var(--rl);padding:14px;margin-bottom:14px;text-align:center">
      <div style="font-size:10px;font-weight:600;color:var(--brand);text-transform:uppercase;letter-spacing:.6px;margin-bottom:5px">Motion</div>
      <div style="font-size:15px;font-weight:600;line-height:1.4">This House Believes that social media algorithms should be regulated as public utilities.</div>
    </div>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:12px">
      <div class="dside" style="border-top:3px solid var(--ok)">
        <div style="display:flex;justify-content:space-between;margin-bottom:10px"><div style="font-weight:600;color:var(--ok)">Proposition</div><span class="badge b-teal">Jamie, Alex</span></div>
        <div id="pro-args">${['Algorithmic amplification of harmful content requires regulatory oversight.','Network effects grant platforms monopolistic power — utility regulation justified.','Transparency requirements enable democratic accountability.','Precedent: telecoms carriers are regulated public utilities.'].map(a => `<div class="darg" onclick="upvoteArg(this)">${a}<div style="font-size:10px;color:var(--tx3);margin-top:3px">0 upvotes</div></div>`).join('')}</div>
        <button class="btn btn-sm btn-block" style="margin-top:8px" onclick="addArg('pro-args')">${I.pl} Add argument</button>
      </div>
      <div class="dside" style="border-top:3px solid var(--err)">
        <div style="display:flex;justify-content:space-between;margin-bottom:10px"><div style="font-weight:600;color:var(--err)">Opposition</div><span class="badge b-coral">Kim, Sara</span></div>
        <div id="opp-args">${['Utility regulation chills innovation and harms new entrants.','First Amendment concerns — state-compelled editorial decisions.','Market competition more effective than regulatory intervention.','Technical complexity makes algorithmic regulation unenforceable.'].map(a => `<div class="darg" onclick="upvoteArg(this)">${a}<div style="font-size:10px;color:var(--tx3);margin-top:3px">0 upvotes</div></div>`).join('')}</div>
        <button class="btn btn-sm btn-block" style="margin-top:8px" onclick="addArg('opp-args')">${I.pl} Add argument</button>
      </div>
    </div>
    <div style="background:var(--sur);border:1px solid var(--bor);border-radius:var(--rl);padding:14px">
      <div style="font-size:12px;font-weight:600;margin-bottom:8px">Evidence & citations</div>
      ${[['Zuboff, S. (2019) The Age of Surveillance Capitalism','Academic — supports regulation argument'],['EU Digital Services Act (2022)','Regulatory precedent for large platform obligations']].map(([ci, n]) => `<div style="padding:7px 0;border-bottom:1px solid var(--bor)"><div style="font-size:12px;font-weight:500">${ci}</div><div style="font-size:11px;color:var(--tx3)">${n}</div></div>`).join('')}
      <button class="btn btn-sm" style="margin-top:8px" onclick="toast('Citation added','success')">${I.pl} Add citation</button>
    </div>
  </div>`;
}

/* ═══════════════════════════════════════════════════════════════════
   SECTION 4 — Permissions Auditor + Boot/Init
═══════════════════════════════════════════════════════════════════ */

/* ── Permissions Auditor ────────────────────────────────────────────── */
async function showPermissionsAuditor(projectId) {
  const perms = await StorageEngine.getPermissions(projectId);
  const members = await StorageEngine.getAll('members', 'projectId', projectId);
  const allUsers = await StorageEngine.getAll('users');
  const um = Object.fromEntries(allUsers.map(u => [u.id, u]));

  const modal = document.createElement('div');
  modal.className = 'ov on';
  modal.id = 'm-permissions';
  modal.innerHTML = `<div class="modal" style="width:560px">
    <div class="mh">
      <div class="mtitle">Permissions Auditor</div>
      <button class="mclose" onclick="document.getElementById('m-permissions').remove()">${I.cl}</button>
    </div>
    <div class="mb">
      <p style="font-size:12px;color:var(--tx2);margin-bottom:14px">Manage who can invite, edit, and delete in this project.</p>
      <div style="overflow-x:auto">
        <table class="sheet">
          <tr><th>Member</th><th style="text-align:center">Can Invite</th><th style="text-align:center">Can Edit</th><th style="text-align:center">Can Delete</th></tr>
          ${members.map(m => {
            const p = perms.find(x => x.userId === m.userId) || { canInvite: false, canEdit: false, canDelete: false };
            const name = um[m.userId]?.fullName || 'Unknown';
            return `<tr>
              <td style="display:flex;align-items:center;gap:8px">${av(um[m.userId], 'sm')} ${esc(name)}</td>
              <td style="text-align:center"><input type="checkbox" ${p.canInvite ? 'checked' : ''} onchange="togglePerm('${p.id || 'new'}','${m.userId}','canInvite',this.checked)"></td>
              <td style="text-align:center"><input type="checkbox" ${p.canEdit ? 'checked' : ''} onchange="togglePerm('${p.id || 'new'}','${m.userId}','canEdit',this.checked)"></td>
              <td style="text-align:center"><input type="checkbox" ${p.canDelete ? 'checked' : ''} onchange="togglePerm('${p.id || 'new'}','${m.userId}','canDelete',this.checked)"></td>
            </tr>`;
          }).join('')}
        </table>
      </div>
    </div>
    <div class="mf">
      <button class="btn" onclick="document.getElementById('m-permissions').remove()">Close</button>
    </div>
  </div>`;

  document.body.appendChild(modal);

  window.togglePerm = async (permId, userId, field, value) => {
    if (demoGuard()) return;
    if (permId === 'new') {
      await StorageEngine.put('permissions', {
        id: StorageEngine.uid(),
        projectId,
        userId,
        canInvite: field === 'canInvite' ? value : false,
        canEdit: field === 'canEdit' ? value : false,
        canDelete: field === 'canDelete' ? value : false,
      });
    } else {
      const p = await StorageEngine.get('permissions', permId);
      if (p) await StorageEngine.updatePermission(permId, { [field]: value });
    }
    toast(`Permission updated for ${field}`, 'success');
  };
}

/* ── Permissions link in workspace sidebar ──────────────────────────── */
// (Augments renderSide to include an auditor button for leads)
const _originalRenderSide = renderSide;
renderSide = function(p, isLead) {
  let html = _originalRenderSide(p, isLead);
  if (isLead) {
    html += `<div class="ssec"><div class="sslbl">Admin</div>
      <button class="btn btn-ghost btn-sm btn-block" onclick="showPermissionsAuditor('${p.id}')">🔐 Permissions Auditor</button>
    </div>`;
  }
  return html;
};

/* ═══════════════════════════════════════════════════════════════════
   SECTION 5 — Boot & Initialization
═══════════════════════════════════════════════════════════════════ */

/* ═══════════════════════════════════════════════════════════════════
   SECURITY LAYER
   Countermeasures: XSS prevention, rate limiting, session integrity,
   input sanitisation, clickjacking guard, data isolation.
═══════════════════════════════════════════════════════════════════ */
const Security = (() => {
  // Rate limiting map: action -> { count, firstAt }
  const _limits = new Map();
  const RULES = {
    login:   { max: 5,  windowMs: 5 * 60 * 1000, msg: 'Too many login attempts. Wait 5 minutes.' },
    signup:  { max: 3,  windowMs: 10 * 60 * 1000, msg: 'Too many sign-up attempts. Wait 10 minutes.' },
    message: { max: 20, windowMs: 60 * 1000, msg: 'Sending too fast. Slow down.' },
    upload:  { max: 10, windowMs: 60 * 1000, msg: 'Too many uploads. Wait a minute.' },
  };

  function rateLimit(action) {
    const rule = RULES[action]; if (!rule) return null;
    const now = Date.now();
    const entry = _limits.get(action) || { count: 0, firstAt: now };
    if (now - entry.firstAt > rule.windowMs) {
      _limits.set(action, { count: 1, firstAt: now });
      return null; // reset window, allow
    }
    entry.count++;
    _limits.set(action, entry);
    if (entry.count > rule.max) return rule.msg;
    return null;
  }

  // Strip any HTML from user input (belt-and-suspenders on top of esc())
  function sanitizeInput(str, maxLen = 2000) {
    if (typeof str !== 'string') return '';
    return str
      .replace(/<[^>]*>/g, '')           // strip HTML tags
      .replace(/javascript:/gi, '')       // strip JS protocol
      .replace(/on\w+\s*=/gi, '')         // strip event handlers
      .replace(/data:/gi, '')             // strip data URIs in text
      .slice(0, maxLen)
      .trim();
  }

  // Validate email format
  function isValidEmail(email) {
    return /^[^\s@]{1,64}@[^\s@]{1,253}\.[^\s@]{2,}$/.test(email);
  }

  // Validate password strength: min 8 chars
  function isValidPassword(pw) {
    return typeof pw === 'string' && pw.length >= 8 && pw.length <= 128;
  }

  // Session token integrity check: session must match IndexedDB
  async function verifySession() {
    try {
      const session = await StorageEngine.getSession();
      if (!session?.userId) return false;
      const user = await StorageEngine.get('users', session.userId);
      return !!user;
    } catch { return false; }
  }

  // Detect suspicious environment signals
  function detectThreats() {
    const threats = [];
    // Clickjacking: if framed, warn
    if (window !== window.top) threats.push('framed');
    // DevTools open in prod could indicate tampering (soft signal only)
    // Prototype pollution guard
    if (Object.prototype.hasOwnProperty.call(Object.prototype, 'constructor') === false) {
      try {
        Object.freeze(Object.prototype);
      } catch {}
    }
    return threats;
  }

  // Periodic session re-validation every 5 min
  function startSessionWatcher(onInvalid) {
    setInterval(async () => {
      const valid = await verifySession();
      if (!valid && S.user) {
        toast('Your session expired. Please sign in again.', 'error');
        S.user = null;
        await StorageEngine.logout();
        onInvalid();
      }
    }, 5 * 60 * 1000);
  }

  return { rateLimit, sanitizeInput, isValidEmail, isValidPassword, verifySession, detectThreats, startSessionWatcher };
})();

/* ── Patch login/signup/sendMsg to use security layer ─────────────── */
const _origLogin = StorageEngine.login.bind(StorageEngine);
StorageEngine.login = async (creds) => {
  const block = Security.rateLimit('login');
  if (block) throw new Error(block);
  if (creds.email && !Security.isValidEmail(creds.email)) throw new Error('Invalid email format.');
  if (!Security.isValidPassword(creds.password)) throw new Error('Password must be 8–128 characters.');
  return _origLogin(creds);
};

const _origSignup = StorageEngine.signup.bind(StorageEngine);
StorageEngine.signup = async (data) => {
  const block = Security.rateLimit('signup');
  if (block) throw new Error(block);
  if (data.email && !Security.isValidEmail(data.email)) throw new Error('Invalid email format.');
  if (!Security.isValidPassword(data.password)) throw new Error('Password must be 8–128 characters.');
  data.fullName = Security.sanitizeInput(data.fullName, 100);
  return _origSignup(data);
};

const _origSendMsg = StorageEngine.sendMsg.bind(StorageEngine);
StorageEngine.sendMsg = async (projectId, senderId, content) => {
  const block = Security.rateLimit('message');
  if (block) throw new Error(block);
  const clean = Security.sanitizeInput(content, 2000);
  if (!clean) throw new Error('Message cannot be empty.');
  return _origSendMsg(projectId, senderId, clean);
};

const _origUpload = StorageEngine.uploadFile.bind(StorageEngine);
StorageEngine.uploadFile = async (projectId, userId, file) => {
  const block = Security.rateLimit('upload');
  if (block) throw new Error(block);
  if (file.size > 50 * 1024 * 1024) throw new Error('File exceeds 50 MB limit.');
  // Validate file name
  const cleanName = Security.sanitizeInput(file.name, 255).replace(/[<>:"/\\|?*]/g, '_');
  const safeFile = new File([file], cleanName, { type: file.type });
  return _origUpload(projectId, userId, safeFile);
};

/* ════════════════════════════════════════════════════════════════════
   BOOT
════════════════════════════════════════════════════════════════════ */
(async () => {
  // Security: detect environmental threats
  const threats = Security.detectThreats();
  if (threats.includes('framed')) {
    document.body.innerHTML = '<div style="display:flex;align-items:center;justify-content:center;height:100vh;font-family:sans-serif;color:#c0392b;flex-direction:column;gap:12px"><strong style="font-size:18px">⚠ Embedded access blocked</strong><p style="font-size:13px">uni-co cannot run inside an iframe. Open it directly.</p></div>';
    return;
  }

  // ── Connect to Supabase ────────────────────────────────────────────
  try {
    await StorageEngine.init();
  } catch (err) {
    document.getElementById('root').innerHTML = `
      <div style="display:flex;align-items:center;justify-content:center;height:100vh;flex-direction:column;gap:14px;padding:24px;text-align:center">
        <div style="font-size:26px;font-weight:700"><span style="color:#534AB7">uni</span>-co</div>
        <div style="color:#C0392B;font-size:14px;max-width:420px;line-height:1.6">
          <strong>Could not connect to the database.</strong><br><br>
          ${err.message}<br><br>
          <strong>Fix:</strong> Open <code>config.js</code> and set your Supabase URL and anon key. See <code>SETUP.md</code> for instructions.
        </div>
        <button onclick="location.reload()" style="padding:9px 22px;background:#534AB7;color:#fff;border:none;border-radius:8px;cursor:pointer;font-size:14px;font-weight:500">Retry</button>
      </div>`;
    return;
  }

  // ── Restore session ───────────────────────────────────────────────
  try {
    const valid = await Security.verifySession();
    if (!valid) { await StorageEngine.logout(); showLogin(); return; }
    const user = await StorageEngine.getCurrentUser();
    if (!user) { await StorageEngine.logout(); showLogin(); return; }
    S.user = user;
    renderShell();
    await go('dashboard');

    // Start session watcher — only for real users, not demo sessions
    if (!S.user.isDemo) Security.startSessionWatcher(() => showLogin());
  } catch (err) {
    console.error('[uni-co] Boot error:', err);
    showLogin();
  }

  console.log('[uni-co] Boot complete —', StorageEngine.mode(), 'mode, theme:', S.theme);

  // Initialise push notifications
  PushEngine.init();

  // Handle navigation messages from service worker (notification click)
  if ('serviceWorker' in navigator) {
    navigator.serviceWorker.addEventListener('message', e => {
      if (e.data?.type === 'NAVIGATE' && e.data.url) {
        const url = new URL(e.data.url, location.origin);
        const ws  = url.searchParams.get('ws');
        if (ws) go('ws', { id: ws });
        else go('dashboard');
      }
    });
  }

})();

/* ══════════════════════════════════════════════════════════════════
   PUSH NOTIFICATION ENGINE
   Uses the Web Push API + service worker to deliver notifications
   even when the tab is in the background or the app is closed.
══════════════════════════════════════════════════════════════════ */
const PushEngine = (() => {

  // ── Public VAPID key — generate yours at https://vapidkeys.com
  // Replace this with your own public key after generating a VAPID pair.
  const PUBLIC_VAPID_KEY = 'BFsbeLbrlU2UMZxaeEtOnhkRbYd2OYtzF4TqBNeLkUs7oP8fEZOgRf-ONY0VqT4wCCJlbyW9lZErERlf5w8z_mA';

  function urlBase64ToUint8Array(base64String) {
    const padding = '='.repeat((4 - base64String.length % 4) % 4);
    const base64 = (base64String + padding).replace(/-/g, '+').replace(/_/g, '/');
    const raw = atob(base64);
    return Uint8Array.from([...raw].map(c => c.charCodeAt(0)));
  }

  async function init() {
    if (!('serviceWorker' in navigator) || !('PushManager' in window)) return;
    if (PUBLIC_VAPID_KEY === 'YOUR_VAPID_PUBLIC_KEY_HERE') return; // not configured yet
    try {
      const reg = await navigator.serviceWorker.ready;
      const existing = await reg.pushManager.getSubscription();
      if (existing) {
        await saveSubscription(existing);
        return;
      }
      const permission = await Notification.requestPermission();
      if (permission !== 'granted') return;
      const sub = await reg.pushManager.subscribe({
        userVisibleOnly: true,
        applicationServerKey: urlBase64ToUint8Array(PUBLIC_VAPID_KEY),
      });
      await saveSubscription(sub);
    } catch (e) {
      console.warn('[uni-co] Push init failed:', e);
    }
  }

  async function saveSubscription(sub) {
    // Store in Supabase push_subscriptions table (create via SQL editor):
    // CREATE TABLE push_subscriptions (
    //   id uuid primary key default gen_random_uuid(),
    //   user_id uuid references users(id) on delete cascade,
    //   subscription jsonb not null,
    //   created_at timestamptz default now()
    // );
    try {
      const sb = StorageEngine._sb();
      await sb.from('push_subscriptions').upsert({
        user_id: S.user?.id,
        subscription: sub.toJSON(),
      }, { onConflict: 'user_id' });
    } catch (e) {
      console.warn('[uni-co] Could not save push subscription:', e);
    }
  }

  // Show a local notification if the document is hidden (tab in background)
  function notifyIfHidden(senderName, content, projectId) {
    if (!document.hidden) return; // user is looking at the tab, no need
    if (Notification.permission !== 'granted') return;
    try {
      navigator.serviceWorker.ready.then(reg => {
        reg.showNotification(`${senderName} — uni-co`, {
          body: content.length > 80 ? content.slice(0, 80) + '…' : content,
          icon: '/icons/icon-192x192.png',
          badge: '/icons/icon-72x72.png',
          tag: `chat-${projectId}`,     // replaces previous notification for same project
          renotify: true,
          data: { url: `/?ws=${projectId}` },
          actions: [
            { action: 'open',   title: 'Open chat' },
            { action: 'dismiss',title: 'Dismiss'   },
          ],
        });
      });
    } catch(e) {}
  }

  // Ask for permission (call this from settings or first message send)
  async function requestPermission() {
    if (!('Notification' in window)) {
      toast('Notifications not supported in this browser', 'error');
      return false;
    }
    if (Notification.permission === 'granted') return true;
    const result = await Notification.requestPermission();
    if (result === 'granted') {
      toast('Notifications enabled ✓', 'success');
      await init();
      return true;
    }
    toast('Notification permission denied', 'error');
    return false;
  }

  return { init, notifyIfHidden, requestPermission };
})();
