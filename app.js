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

   //SECTION 2 — UI Framework
   //State, Icons, Theme Engine, Toast System, FLIP Morphing Modals,
   //Skeleton Loaders, Staggered Animations, Router, Shell, Auth,
   //Dashboard, Projects, Explore, Notifications, Settings + Data Vault


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
  return `<div class="av av-${sz}" style="background:${bg};color:${col}">${ini(user?.fullName)}</div>`;
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

  if (page === 'dashboard') await showDashboard();
  else if (page === 'projects') await showProjects();
  else if (page === 'explore') await showExplore();
  else if (page === 'notifs') await showNotifs();
  else if (page === 'settings') await showSettings();
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
  m.innerHTML = `<d
