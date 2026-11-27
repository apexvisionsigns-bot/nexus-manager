const crypto = require('crypto');
const { createClient } = require('@supabase/supabase-js');

// Keep only the origin of the URL, so extra parts like /rest/v1 or a trailing slash don't break requests
const SB_URL = (() => {
  try {
    return new URL((process.env.SUPABASE_URL || process.env.NEXT_PUBLIC_SUPABASE_URL || '').trim()).origin;
  } catch (e) {
    return '';
  }
})();
const SB_KEY = (process.env.SUPABASE_SERVICE_ROLE_KEY || '').trim();
const SECRET = process.env.AUTH_SECRET || '';
const ADMIN_EMAIL = (process.env.ADMIN_EMAIL || '').trim().toLowerCase();
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || '';
const TOKEN_TTL = 1000 * 60 * 60 * 24 * 30; // 30 days
const PAGE = 200;
const STAFF_KINDS = ['shop', 'eq'];

let sb;
const db = () => sb || (sb = createClient(SB_URL, SB_KEY, { auth: { persistSession: false, autoRefreshToken: false } }));

class HttpError extends Error {
  constructor(status, msg) {
    super(msg);
    this.status = status;
  }
}
const ck = ({ data, error }) => {
  if (error) throw new Error(error.message || 'Database error');
  return data;
};

const hashPw = (pw, salt) => crypto.scryptSync(pw, salt, 32).toString('hex');
const safeEq = (a, b) => {
  const x = Buffer.from(String(a));
  const y = Buffer.from(String(b));
  return x.length === y.length && crypto.timingSafeEqual(x, y);
};
function sign(payload) {
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  return body + '.' + crypto.createHmac('sha256', SECRET).update(body).digest('base64url');
}
function verify(token) {
  const [body, sig] = String(token || '').split('.');
  if (!body || !sig) return null;
  const good = crypto.createHmac('sha256', SECRET).update(body).digest('base64url');
  if (!safeEq(sig, good)) return null;
  try {
    const p = JSON.parse(Buffer.from(body, 'base64url').toString());
    return p.exp > Date.now() ? p : null;
  } catch (e) {
    return null;
  }
}

async function authUser(req) {
  const p = verify((req.headers.authorization || '').replace(/^Bearer\s+/i, ''));
  if (!p) throw new HttpError(401, 'Unauthorized');
  const u = ck(await db().from('nx_users').select('email,name,role').eq('email', p.email).maybeSingle());
  if (!u) throw new HttpError(401, 'Unauthorized');
  return u;
}
const needAdmin = (u) => {
  if (u.role !== 'admin') throw new HttpError(403, 'Admin only');
};

async function login(b) {
  const email = String(b.email || '').trim().toLowerCase();
  const password = String(b.password || '');
  if (!email || !password) throw new HttpError(401, 'Invalid credentials');

  // Admin account comes from the environment variables
  if (ADMIN_EMAIL && ADMIN_PASSWORD && email === ADMIN_EMAIL && safeEq(password, ADMIN_PASSWORD)) {
    const salt = crypto.randomBytes(16).toString('hex');
    ck(await db().from('nx_users').upsert(
      { email, name: 'Admin', role: 'admin', salt, hash: hashPw(password, salt) },
      { onConflict: 'email' }
    ));
  }

  const u = ck(await db().from('nx_users').select('email,name,role,salt,hash').eq('email', email).maybeSingle());
  if (!u || !safeEq(hashPw(password, u.salt), u.hash)) throw new HttpError(401, 'Invalid credentials');
  return {
    token: sign({ email: u.email, exp: Date.now() + TOKEN_TTL }),
    user: { email: u.email, name: u.name, role: u.role },
  };
}

async function push(u, b) {
  const up = Array.isArray(b.up) ? b.up : [];
  const rows = up.map((x) => {
    const id = String(x.id || '');
    const kind = String(x.kind || '');
    if (!id || !kind || id.split(':')[0] !== kind) throw new HttpError(400, 'Bad record');
    if (u.role !== 'admin' && !STAFF_KINDS.includes(kind)) throw new HttpError(403, 'Not allowed');
    return { id, kind, data: x.data || {}, deleted: !!x.deleted };
  });
  if (rows.length) ck(await db().from('nx_records').upsert(rows, { onConflict: 'id' }));
  return { ok: true };
}

async function pull(u, b) {
  const data = ck(await db().rpc('nx_pull', {
    p_since: b.since || '1970-01-01T00:00:00Z',
    p_after: b.after || '',
    p_kinds: u.role === 'admin' ? null : STAFF_KINDS,
    p_limit: PAGE + 1,
  })) || [];
  const more = data.length > PAGE;
  return { rows: more ? data.slice(0, PAGE) : data, more };
}

async function staffList() {
  return { rows: ck(await db().from('nx_users').select('email,name,role').order('created_at')) || [] };
}
async function staffAdd(b) {
  const email = String(b.email || '').trim().toLowerCase();
  const pw = String(b.password || '');
  if (!email || pw.length < 6) throw new HttpError(400, 'Email and a password of 6+ characters required');
  const ex = ck(await db().from('nx_users').select('email').eq('email', email).maybeSingle());
  if (ex) throw new HttpError(409, 'User already exists');
  const salt = crypto.randomBytes(16).toString('hex');
  ck(await db().from('nx_users').insert({
    email,
    name: String(b.name || '').trim(),
    role: b.role === 'admin' ? 'admin' : 'staff',
    salt,
    hash: hashPw(pw, salt),
  }));
  return { ok: true };
}
async function staffRole(u, b) {
  const email = String(b.email || '').trim().toLowerCase();
  if (email === u.email) throw new HttpError(400, "You can't change your own role");
  ck(await db().from('nx_users').update({ role: b.role === 'admin' ? 'admin' : 'staff' }).eq('email', email));
  return { ok: true };
}
async function staffDel(u, b) {
  const email = String(b.email || '').trim().toLowerCase();
  if (email === u.email) throw new HttpError(400, "You can't delete yourself");
  ck(await db().from('nx_users').delete().eq('email', email));
  return { ok: true };
}
async function password(u, b) {
  const pw = String(b.password || '');
  if (pw.length < 6) throw new HttpError(400, 'Password must be 6+ characters');
  const salt = crypto.randomBytes(16).toString('hex');
  ck(await db().from('nx_users').update({ salt, hash: hashPw(pw, salt) }).eq('email', u.email));
  return { ok: true };
}

module.exports = async (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  try {
    if (req.method !== 'POST') throw new HttpError(405, 'POST only');
    if (/(^|\.)supabase\.com$/.test(new URL(SB_URL || 'http://x').hostname)) throw new HttpError(500, 'SUPABASE_URL is wrong: it must look like https://<project-id>.supabase.co (not the dashboard link)');
    if (!SB_URL || !SB_KEY) throw new HttpError(500, 'Supabase is not configured (SUPABASE_URL / SUPABASE_SERVICE_ROLE_KEY missing)');
    if (SECRET.length < 16) throw new HttpError(500, 'AUTH_SECRET is missing or too short');

    let b = req.body;
    if (typeof b === 'string') b = JSON.parse(b || '{}');
    b = b || {};

    if (b.a === 'login') return res.status(200).json(await login(b));

    const u = await authUser(req);
    switch (b.a) {
      case 'push': return res.status(200).json(await push(u, b));
      case 'pull': return res.status(200).json(await pull(u, b));
      case 'password': return res.status(200).json(await password(u, b));
      case 'staffList': needAdmin(u); return res.status(200).json(await staffList());
      case 'staffAdd': needAdmin(u); return res.status(200).json(await staffAdd(b));
      case 'staffRole': needAdmin(u); return res.status(200).json(await staffRole(u, b));
      case 'staffDel': needAdmin(u); return res.status(200).json(await staffDel(u, b));
      default: throw new HttpError(400, 'Unknown action');
    }
  } catch (e) {
    const status = e.status || 500;
    if (status === 500) console.error(e);
    res.status(status).json({ error: e instanceof HttpError ? e.message : 'Server error: ' + e.message });
  }
};
