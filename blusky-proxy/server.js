// --- sessions via cookie (first-party) ---
const cookieSession = require("cookie-session");
const multer = require('multer');
const mysql = require('mysql2/promise');
const argon2 = require('argon2');
// Si tu es derrière un reverse-proxy HTTPS (Apache/Nginx), indispensable
const helmet = require('helmet');
const fs = require("fs");
const path = require("path");
const { BskyAgent } = require("@atproto/api");

const IS_PROD = process.env.NODE_ENV === 'dev';
let port = Number(process.env.PORT);
if (!Number.isFinite(port)) {
  if (IS_PROD) {
    throw new Error('[BOOT] PORT must be set in environment (Cloud Web provides it).');
  } else {
    port = 3001; // fallback DEV si tu oublies PORT dans .env
    console.warn(`[BOOT] No PORT in .env, using dev fallback ${port}`);
  }
}
const express = require("express");
const app = express();
const { rateLimit, ipKeyGenerator } = require('express-rate-limit');
const { slowDown } = require('express-slow-down');




require('dotenv').config({
  path: path.resolve(__dirname, 'etc', '.env')
});

const dev = process.env.NODE_ENV !== "development";


app.set('trust proxy', true); // pour que req.ip prenne X-Forwarded-For s’il est présent

app.use(helmet({ contentSecurityPolicy: false }));
// --- Limiteurs ---
// npm i express-rate-limit express-slow-down



// Clé: IP normalisée (IPv4/IPv6) + DID (si présent) => évite de mutualiser tout le monde


function keyByIpAndDid(req) {
  // Normalise IPv4/IPv6 et respecte app.set('trust proxy', true)
  const baseIp = ipKeyGenerator(req);

  const did = req.session?.did || req.session?.user?.did || req.query?.did || '';
  return did ? `${baseIp}|${String(did).trim()}` : baseIp;
}

// Limiteur léger pour la saisie (évite 429 trop tôt)
const suggestLimiter = rateLimit({
  windowMs: 30_000,
  limit: 120,                // 120 req / 30s / IP
  standardHeaders: true,
  legacyHeaders: false,
});

// --- Helper DB safe (fonctionne si tu utilises db ou pool avec mysql2/promise)
// --- Helper DB simple, branché sur dbPool
async function dbQuery(sql, params = []) {
  try {
    const [rows] = await dbPool.query(sql, params);
    return rows;
  } catch (e) {
    console.error('[DB] query error:', e);
    return [];
  }
}

// Petit normaliseur pour fusionner DB + Bluesky
function normHandle(h) {
  if (!h) return '';
  return h.startsWith('@') ? h.slice(1).toLowerCase() : h.toLowerCase();
}
// près de tes autres const multer…

function requireMultipart(req, res, next) {
  // si le proxy a cassé le CT, on le verra de suite
  if (!req.is('multipart/form-data')) {
    return res.status(415).json({ error: 'EXPECTED_MULTIPART' });
  }
  next();
}

function attachAbortLog(req, _res, next) {
  req.on('aborted', () => {
    console.warn('[/post/images] requête ABORTED (client/proxy a coupé le flux)');
  });
  next();
}

// --- Helpers expiration & marquage ---
/*
function jwtExpMs(token) {
  try {
    const p = token.split('.')[1];
    const payload = JSON.parse(Buffer.from(p, 'base64url').toString('utf8'));
    return (typeof payload.exp === 'number') ? payload.exp * 1000 : null;
  } catch { return null; }
}
*/
/*
function isSessionAliveRecord(s) {
  if (!s || s.dead) return false;
  // Tu stockes le JWT sous s.jwt
  const exp = s.jwt ? jwtExpMs(s.jwt) : null;
  // ⚠️ clé du bug: sans exp décodable → on considère NON authentifié
  if (!exp) return false;
  const skew = 30_000; // marge 30s
  return Date.now() + skew < exp;
}
*/
function markSessionDead(did, reason = 'EXPIRED') {
  if (!did || !sessions[did]) return;
  sessions[did].dead = true;
  sessions[did].deadReason = reason;
  try { fs.writeFileSync(sessionsPath, JSON.stringify(sessions, null, 2)); } catch {}
}

// 429 JSON propre (avec Retry-After)
function rateLimitHandler(req, res, _next, options) {
  res.set('Retry-After', String(Math.ceil(options.windowMs / 1000)));
  res.status(options.statusCode).json({
    ok: false,
    error: 'RATE_LIMIT',
    message: 'Too many requests',
  });
}

// 🔒 Limiteur strict seulement pour les écritures
const writeLimiter = rateLimit({
  windowMs: 60_000,
  max: 60,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: keyByIpAndDid,
  handler: rateLimitHandler,
});

// 🐢 Ralentisseur pour les lectures (pas de 429 brutal)
const readSlowdown = slowDown({
  windowMs: 10_000,
  delayAfter: 20,
  // "ancien" comportement : +250 ms par requête au-delà du seuil
  delayMs: (used, req) => Math.max(0, used - req.slowDown.limit) * 250,
  maxDelayMs: 2000,
  keyGenerator: keyByIpAndDid,
});

// ❌ supprime ceci si tu l’as encore : app.use(limiter);
// ✅ applique finement :
const WRITE_PATHS = [
  '/login','/logout',
  '/post','/post/images','/post/video','/post/edit','/post/delete',
  '/comment','/comment/delete',
  '/like','/unlike',
  '/video/upload','/post/video-from-job'
];
app.use(WRITE_PATHS, writeLimiter);

const READ_PATHS = ['/feed','/feed/page','/thread'];
app.use(READ_PATHS, readSlowdown);

// ⛔️ surtout PAS de limiter sur /me




// Ping simple (pratique pour tester /bsky/)





app.use(cookieSession({
  name: "bsky.sid",
  keys: [process.env.SESSION_SECRET || "dev-change-me"],
  httpOnly: true,
  secure: dev ? false : true,    // prod: true (HTTPS), dev HTTP: false
  sameSite: "lax",               // même-origine: Lax suffit
  maxAge: 30 * 24 * 60 * 60 * 1000
}));
app.get("/", (_req, res) => res.json({ ok: true, name: "Bluesky Proxy API" }));
function didFromReq(req){
  return req.session?.did || req.session?.user?.did || null;
}
function hasServerSession(did){
  return !!(did && sessions && sessions[did] && !sessions[did].dead);
}
app.use((req, res, next) => {
  const did = didFromReq(req);
  if (did && !hasServerSession(did)) {
    // Cookie orphelin : on le supprime et on informe le front
    if (req.session) req.session = null;
    res.set('x-auth-expired', '1');
  }
  next();
});


function setSession(req, { did, handle }) {
  req.session = { did, handle, at: Date.now() };
}
function clearSession(req) {
  req.session = null;
}
/*
function didFromReq(req) {
  return req.session?.did || null;
}
*/
app.use((req, _res, next) => {
  if (req.path === "/post/images") {
    console.log("[Node sees] CT=%s Len=%s", req.headers['content-type'], req.headers['content-length']);
  }
  next();
});

// ---- Helpers session ----
function jwtExpMs(jwt) {
  try {
    const part = jwt.split('.')[1];
    const json = Buffer.from(part, 'base64url').toString('utf8');
    const payload = JSON.parse(json);
    if (payload && typeof payload.exp === 'number') return payload.exp * 1000;
  } catch {}
  return null;
}

function isSessionAliveRecord(s) {
  if (!s || s.dead) return false;
  // essaie d'abord l'accessJwt (ATProto renvoie des JWT)
  const exp = s.accessJwt ? jwtExpMs(s.accessJwt) : (s.tokenExpiresAt || null);
  if (!exp) return true; // pas d'info: on ne déclare pas mort par défaut
  const skew = 30 * 1000; // marge de 30s
  return Date.now() + skew < exp;
}

function isSessionAlive(did) {
  const s = did && sessions ? sessions[did] : null;
  return isSessionAliveRecord(s);
}


// --- [EN-HAUT DE FICHIER] imports ---


// ex: server.js
const VIDEO_LIMITS_TTL_MS = 5 * 60 * 1000;
let _videoLimitsCache = { data: null, ts: 0 };
// limite dédiée vidéo (≤ ~100 Mo côté Bluesky – on laisse un peu de marge)
const uploadVideo = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 110 * 1024 * 1024, files: 1 }, // 110 Mo, 1 fichier
});
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024, files: 4 }, // 5 Mo, max 4 images
});
const BSKY_MAX_BYTES = 950 * 1024; // ~0,95 Mo (marge sous 1 Mo Bluesky)
const BSKY_MAX_SIDE  = 2000;       // côté max si on compresse
// Middleware Multer qui capte tout, puis on filtrera strictement par nom de champ
function runMulterAnyStrict() {
  const mw = upload.any();
  return (req, res, next) => {
    mw(req, res, (err) => {
      if (!err) return next();
      console.error("[Upload] Multer error:", err.code || err.name, "-", err.message);
      res.status(400).json({ error: "UPLOAD_INVALID", code: err.code || "MULTER", detail: err.message });
    });
  };
}
app.get("/video/limits", async (req, res) => {
  try {
    if (!_videoLimitsCache.data || (Date.now() - _videoLimitsCache.ts) > VIDEO_LIMITS_TTL_MS) {
      const r = await technicalAgent.api.app.bsky.video.getUploadLimits({});
      _videoLimitsCache = { data: r.data, ts: Date.now() };
    }
    res.json({ success: true, limits: _videoLimitsCache.data });
  } catch (e) {
    res.status(500).json({ error: "get_limits_failed", detail: String(e?.message || e) });
  }
});
// 1) démarrer l’upload (via l’utilisateur connecté)
app.post("/video/upload", upload.single("video"), async (req, res) => {
  try {
    const did = didFromReq(req);
    const agent = await getAgentFromDid(did);
    if (!agent) return res.status(401).json({ error: "session_invalid" });

    const buf = req.file.buffer;
    const mime = req.file.mimetype;

    // upload initial → renvoie un job
    const r = await agent.api.app.bsky.video.uploadVideo(buf, { encoding: mime });
    const jobId = r?.data?.jobId || r?.data?.jobid;
    if (!jobId) return res.status(500).json({ error: "no_job_id" });

    res.json({ success: true, jobId });
  } catch (e) {
    res.status(500).json({ error: "upload_failed", detail: String(e?.message || e) });
  }
});

// 2) polling du job (même user agent que l’upload)
app.get("/video/job", async (req, res) => {
  try {
    const did = didFromReq(req);
    const agent = await getAgentFromDid(did);
    if (!agent) return res.status(401).json({ error: "session_invalid" });

    const jobId = String(req.query.id || "");
    const r = await agent.api.app.bsky.video.getJobStatus({ jobId });
    res.json({ success: true, data: r.data });
  } catch (e) {
    res.status(500).json({ error: "job_failed", detail: String(e?.message || e) });
  }
});

// 3) créer le post à partir du job prêt (BlobRef)
app.post("/post/video-from-job", async (req, res) => {
  try {
    const did = didFromReq(req);
    const agent = await getAgentFromDid(did);
    if (!agent) return res.status(401).json({ error: "session_invalid" });

    const { text = "" , jobId } = req.body || {};
    if (!jobId) return res.status(400).json({ error: "jobId_required" });

    const st = await agent.api.app.bsky.video.getJobStatus({ jobId });
    if (st?.data?.state !== "ready") {
      return res.status(409).json({ error: "not_ready_yet", state: st?.data?.state });
    }

    const videoBlob = st.data.blob;              // BlobRef
    const ar        = st.data.aspectRatio || {}; // { width, height }

    const record = {
      $type: "app.bsky.feed.post",
      text: text.trim() || "\u200B",
      createdAt: new Date().toISOString(),
      embed: {
        $type: "app.bsky.embed.video",
        video: videoBlob,
        aspectRatio: ar,
        // thumbnail: { ... } si st.data.thumbnail disponible
      },
      langs: ["fr"],
    };

    const resp = await agent.com.atproto.repo.createRecord({
      repo: agent.session?.did || did,
      collection: "app.bsky.feed.post",
      record,
    });

    res.json({
      success: true,
      uri: resp?.data?.uri || resp?.uri,
      cid: resp?.data?.cid || resp?.cid
    });
  } catch (e) {
    res.status(500).json({ error: "create_post_failed", detail: String(e?.message || e) });
  }
});

const ALLOWED_MIME = new Set(['image/jpeg','image/png','image/webp','image/gif', 'image/heic', 'image/avif']);
const ALLOWED_VIDEO_MIME = new Set([
  'video/mp4',        // mp4
  'video/quicktime',  // mov
  'video/webm',       // webm
  'video/mpeg'        // mpeg
]);



// --- pool MySQL ---
// 1) Charger .env AVANT de créer le pool

// (facultatif) log de la cible DB
console.log('[DB] Target =>',
  `host=${process.env.DB_HOST || 'localhost'}`,
  `db=${process.env.DB_NAME || '(unset)'}`,
  `user=${process.env.DB_USER || '(unset)'}`
);

// 2) Pool MySQL (assure-toi que DB_NAME est bien défini)
const dbPool = mysql.createPool({
  host: process.env.DB_HOST,
  port: Number(process.env.DB_PORT || 3306),
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD || '',
  database: process.env.DB_NAME,
  charset: 'utf8mb4',
  waitForConnections: true,
  connectionLimit: 5,
  // Si tu actives TLS côté WCD, décommente au besoin (avec le CA si fourni) :
  // ssl: { minVersion: 'TLSv1.2', rejectUnauthorized: true /*, ca: fs.readFileSync('/path/ca.pem')*/ },
});


// 3) Utilitaire: où suis-je connecté ?
async function logDbWhere() {
  const conn = await dbPool.getConnection();
  try {
    const [rows] = await conn.query('SELECT DATABASE() AS db, @@hostname AS host, @@port AS port');
    const r = rows[0] || {};
    console.log(`[DB] Connected to db="${r.db}" on ${r.host}:${r.port}`);
  } finally {
    conn.release();
  }
}

// 4) Création table
async function ensureUsersSchema() {
  const conn = await dbPool.getConnection();
  try {
    // 1) Table
    await conn.query(`
      CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        did VARCHAR(128) NOT NULL UNIQUE,
        handle VARCHAR(191) NOT NULL UNIQUE,
        password_hash VARCHAR(191) NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    `);

    // 2) Colonnes existantes
    const [cols] = await conn.query(
      `SELECT COLUMN_NAME FROM information_schema.COLUMNS
       WHERE TABLE_SCHEMA = ? AND TABLE_NAME = 'users'`,
      [process.env.DB_NAME]
    );
    const have = new Set(cols.map(r => r.COLUMN_NAME.toLowerCase()));

    // 3) ALTER si manquantes
    const alters = [];
    if (!have.has('password_hash')) alters.push(`ADD COLUMN password_hash VARCHAR(191) NULL AFTER handle`);
    if (!have.has('created_at'))    alters.push(`ADD COLUMN created_at DATETIME DEFAULT CURRENT_TIMESTAMP`);
    if (!have.has('updated_at'))    alters.push(`ADD COLUMN updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP`);
	if (!have.has('displayName'.toLowerCase())) alters.push(`ADD COLUMN displayName VARCHAR(191) NULL`);
	if (!have.has('avatar'.toLowerCase()))      alters.push(`ADD COLUMN avatar TEXT NULL`);
	if (!have.has('last_seen'.toLowerCase()))   alters.push(`ADD COLUMN last_seen DATETIME NULL`);


    if (alters.length) {
      await conn.query(`ALTER TABLE users ${alters.join(', ')}`);
      console.log(`[DB] 🔧 users migrated: ${alters.join(', ')}`);
    } else {
      console.log('[DB] ✅ users schema OK');
    }
  } finally {
    conn.release();
  }
}

// 5) Boot (⚠️ À L’EXTÉRIEUR des fonctions !)
(async () => {
  try {
    await logDbWhere();       // affiche où on est connecté
    await ensureUsersSchema(); // crée la table si besoin
  } catch (e) {
    console.warn('[DB] ⚠️ Init DB:', e.message);
  }
})();

app.get('/debug/db-info', async (req, res) => {
  try {
    const conn = await dbPool.getConnection();
    try {
      const [info] = await conn.query('SELECT DATABASE() AS db, @@hostname AS host, @@port AS port');
      res.json({ ok: true, info: info[0], env: { DB_HOST: process.env.DB_HOST, DB_NAME: process.env.DB_NAME, DB_USER: process.env.DB_USER } });
    } finally {
      conn.release();
    }
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});
app.get('/debug/record', async (req, res) => {
  const uri = String(req.query.uri || '');
  const m = uri.match(/^at:\/\/([^/]+)\/app\.bsky\.feed\.post\/([^/]+)$/);
  if (!m) return res.status(400).json({ ok:false, error:'BAD_URI' });
  const [_, repo, rkey] = m;
  try {
    // agent technique suffit en lecture
    const r = await technicalAgent.com.atproto.repo.getRecord({
      repo, collection: 'app.bsky.feed.post', rkey
    });
    res.json({ ok:true, cid: r?.data?.cid, value: r?.data?.value });
  } catch (e) {
    res.status(500).json({ ok:false, error:String(e?.message||e) });
  }
});

app.get('/debug/users', async (req, res) => {
  try {
    const conn = await dbPool.getConnection();
    try {
      const [rows] = await conn.query('SELECT id, did, handle, created_at FROM users ORDER BY id DESC LIMIT 50');
      res.json({ ok: true, count: rows.length, users: rows });
    } finally {
      conn.release();
    }
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});


app.use(express.json());

const technicalAgent = new BskyAgent({ service: "https://bsky.social" });
const sessionsPath = path.join(__dirname, "sessions.json");
let sessions = {};

// Charger les sessions depuis le fichier
if (fs.existsSync(sessionsPath)) {
	sessions = JSON.parse(fs.readFileSync(sessionsPath, "utf-8"));
	console.log(`[Proxy] 🔁 Sessions chargées : ${Object.keys(sessions).length}`);
}

// Enregistrer une session sur disque
function saveSession(did, sessionData) {
	sessions[did] = sessionData;
	fs.writeFileSync(sessionsPath, JSON.stringify(sessions, null, 2));
}

// Restaurer un agent à partir du did
async function getAgentFromDid(did) {
  const s = sessions[did];
  if (!isSessionAliveRecord(s)) return null;

  try {
    const agent = new BskyAgent({ service: "https://bsky.social" });
    await agent.resumeSession({ did, accessJwt: s.accessJwt || s.jwt, refreshJwt: s.refreshJwt });
    return agent;
  } catch (err) {
    const msg = String(err?.message || err);
    console.error(`[Proxy] resumeSession(${did}) failed:`, msg);
    if (/expired/i.test(msg)) markSessionDead(did, 'EXPIRED');
    return null;
  }
}


// Cache des index de flux: clé = `${actor}::${perPage}`
// valeur = { cursors: [null, c1, c2, ...], exhausted: boolean, updatedAt: ISO }
// Cache global
const feedIndexCache = new Map();

// utilise TOUJOURS technicalAgent ici
async function ensureFeedIndex(actor, perPage, targetPage, { computeUntilEnd = false } = {}) {
  const key = `${actor}::${perPage}`;
  let entry = feedIndexCache.get(key);
  if (!entry) {
    entry = { cursors: [null], exhausted: false, updatedAt: new Date().toISOString() };
    feedIndexCache.set(key, entry);
  }

  // Si déjà épuisé (plus de page) ou on a déjà au moins targetPage, rien à faire
  if (!computeUntilEnd && (entry.exhausted || entry.cursors.length > targetPage)) {
    return entry;
  }


  while (!entry.exhausted && entry.cursors.length <= (computeUntilEnd ? 1e9 : targetPage)) {
    const cursor = entry.cursors[entry.cursors.length - 1] || undefined;
    let resp;
    try {
      resp = await technicalAgent.api.app.bsky.feed.getAuthorFeed({
        actor,
        limit: perPage,
        cursor,
      });
    } catch (e) {
      console.error("[Proxy] ensureFeedIndex getAuthorFeed error:", e.message);
      // on arrête proprement
      entry.exhausted = true;
      break;
    }

    const nextCursor = resp?.data?.cursor;
    if (nextCursor) {
      entry.cursors.push(nextCursor);
    } else {
      entry.exhausted = true;
      break;
    }
  }

  entry.updatedAt = new Date().toISOString();
  feedIndexCache.set(key, entry);
  return entry;
}
async function recordUserOnFirstLogin({ did, handle, plainPassword }) {
  if (!did || !handle) return;

  const conn = await dbPool.getConnection();
  try {
    // pour être sûr de la DB courante et de l'autocommit
    const [info] = await conn.query('SELECT DATABASE() AS db, @@autocommit AS autocommit');
    console.log('[DB] recordUserOnFirstLogin → db=%s autocommit=%s', info?.[0]?.db, info?.[0]?.autocommit);

    await conn.beginTransaction();

    // Existe déjà ?
    const [rows] = await conn.query(
      'SELECT id, did, handle FROM users WHERE did = ? OR handle = ? LIMIT 1',
      [did, handle]
    );

    if (rows.length) {
      const row = rows[0];
      console.log('[DB] user déjà présent id=%s did=%s handle=%s', row.id, row.did, row.handle);
      // Mise à jour douce si besoin
      if (row.did !== did || row.handle !== handle) {
        const [uRes] = await conn.query(
  'UPDATE users SET handle=?, last_seen=NOW(), updated_at=NOW() WHERE did=?',
  [handle, did]
);
        console.log('[DB] UPDATE users affectedRows=%s', uRes?.affectedRows);
      }
      await conn.commit();
      return;
    }

    // Hash (facultatif)
    let passwordHash = null;
    if (plainPassword) {
      try {
        passwordHash = await argon2.hash(plainPassword, {
          type: argon2.argon2id,
          timeCost: 3,
          memoryCost: 2 ** 16,
          parallelism: 1,
        });
      } catch (e) {
        console.warn('[DB] ⚠️ Argon2 hash fail:', e.message);
      }
    }

    // INSERT
    const [ins] = await conn.query(
      'INSERT INTO users (did, handle, password_hash) VALUES (?, ?, ?)',
      [did, handle, passwordHash]
    );
    console.log('[DB] INSERT users affectedRows=%s insertId=%s', ins?.affectedRows, ins?.insertId);

    // Read-back immédiat pour confirmer
    const [chk] = await conn.query('SELECT id, did, handle FROM users WHERE id = ?', [ins.insertId]);
    console.log('[DB] Readback row =', chk?.[0]);

    await conn.commit();
    console.log('[DB] 🆕 User ajouté:', handle, did);
  } catch (e) {
    try { await conn.rollback(); } catch {}
    console.error('[DB] ❌ recordUserOnFirstLogin error:', e.message);
  } finally {
    conn.release();
  }
}


// Connexion du compte technique
(async () => {
	try {
		await technicalAgent.login({
			identifier: process.env.FEED_BSKY_HANDLE,
			password: process.env.FEED_BSKY_PASSWORD
		});
		console.log("[Proxy] ✅ Compte technique connecté avec succès");
	} catch (err) {
		console.error("[Proxy] ❌ Échec de connexion du compte technique :", err.message);
	}
})();

// LOGIN utilisateur
app.post("/login", async (req, res) => {
  let { handle, password } = req.body || {};
  if (!handle || !password) {
    return res.status(400).json({ error: "Identifiants manquants" });
  }

  // 🔧 normalisation robuste
  handle = String(handle).trim();
  if (handle.startsWith("@")) handle = handle.slice(1);

  if (handle.startsWith("did:")) {
    // c'est un DID ⇒ on NE TOUCHE PAS
  } else if (!handle.includes(".")) {
    // c'est un handle court ⇒ on complète
    handle = handle.toLowerCase() + ".bsky.social";
  }

  const agent = new BskyAgent({ service: "https://bsky.social" });

  try {
    // ⚠️ utiliser un **App Password**, pas le mot de passe principal
    await agent.login({ identifier: handle, password });
const { did, accessJwt, refreshJwt } = agent.session;

saveSession(did, {
  handle,
  accessJwt,
  refreshJwt,
  createdAt: sessions[did]?.createdAt || new Date().toISOString(),
  updatedAt: new Date().toISOString(),
});

    setSession(req, { did, handle });            // ← pose le cookie bsky.sid
    recordUserOnFirstLogin({ did, handle, plainPassword: null }).catch(() => {});
    return res.json({ success: true, did, handle });
  } catch (err) {
    console.error("[Proxy] login 401:", { identifier: handle }, err.message);
    return res.status(401).json({ error: "Échec de connexion" });
  }
});

// Déconnexion (efface le cookie)
app.post('/logout', (req, res) => {
  const did = req.session?.did || req.session?.user?.did;
  // 1) purge côté serveur
  if (did && sessions && sessions[did]) {
    delete sessions[did];
    try { fs.writeFileSync(sessionsPath, JSON.stringify(sessions, null, 2)); } catch {}
  }
  // 2) vide le cookie de session
  if (req.session) req.session = null;

  // 3) petit indicateur pour débogage / proxy
  res.set('x-from-node', 'logout');
  res.set('x-auth-expired', '1');

  return res.json({ ok: true });
});


// Qui suis-je ? (lit la session cookie)
app.get("/me", (req, res) => {
  res.set('Cache-Control', 'no-store');
  res.set('Vary', 'Cookie');

  const did = didFromReq(req);
  const s   = did ? sessions[did] : null;
  const alive = isSessionAliveRecord(s);
  const exp = s?.accessJwt ? jwtExpMs(s.accessJwt) : null;

  // log utile (temporaire)
  console.log('[ME]', {
    did, alive, dead: !!s?.dead,
    hasJwt: !!s?.jwt,
    expISO: exp ? new Date(exp).toISOString() : null
  });

  if (!did || !alive) {
    clearSession(req);              // coupe le cookie
    res.set('x-auth-expired', '1'); // aide le front
    return res.json({ authenticated: false, reason: 'EXPIRED_OR_UNKNOWN' });
  }

  const handle = s?.handle || null;
  return res.json({ authenticated: true, did, handle });
});




// Validation légère (utilisée par le front avant action)
app.get("/session/validate", async (req, res) => {
  const did = didFromReq(req);
  if (!did) return res.json({ valid: false, reason: "NO_SESSION" });

  try {
    const agent = await getAgentFromDid(did);
    await agent.getProfile({ actor: did });
    return res.json({ valid: true, did, handle: sessions[did]?.handle || null });
  } catch {
    return res.json({ valid: false, reason: "SESSION_EXPIRED" });
  }
});

//fin login/logout

// FEED
app.get("/feed", async (req, res) => {
  try {
    const actor = String(req.query.actor || "").trim();
    if (!actor) return res.status(400).json({ error: "actor manquant" });

    // borne les paramètres pour éviter les abus
    const limitQ = parseInt(String(req.query.limit ?? "50"), 10);
    const pagesQ = parseInt(String(req.query.pages ?? "1"), 10);
    const limit = Math.min(Math.max(limitQ || 50, 1), 100);   // 1..100 par page
    const pages = Math.min(Math.max(pagesQ || 1, 1), 10);     // 1..10 pages max
    const cursor = req.query.cursor ? String(req.query.cursor) : undefined;

    const did = didFromReq(req);                 // ✅ cookie si connecté
	let agent = did ? (await getAgentFromDid(did)) : technicalAgent;


    console.log(`[Proxy] /feed actor=${actor} limit=${limit} pages=${pages} cursor=${cursor ?? "-"} did=${did ?? "-"}`);

    if (!agent) agent = technicalAgent;

    const { feed, cursor: nextCursor } = await fetchAuthorFeedDeep(agent, {
      actor,
      limit,
      cursor,
      pages,
    });

    // on renvoie le même shape que l’API Bluesky pour rester compatible avec ton front
    res.json({
      success: true,
      data: { feed, cursor: nextCursor },
    });
  } catch (err) {
  const did = didFromReq(req);
  const msg = String(err?.message || err);
  if (/token has expired/i.test(msg)) {
    markSessionDead(did, 'EXPIRED');
    clearSession(req);
    return res.status(401).set('x-auth-expired', '1')
      .json({ ok:false, error:'AUTH_EXPIRED' });
  }
  return res.status(500).json({ ok:false, error: msg });
}

});

app.get("/feed/page", async (req, res) => {
  try {
    const actor = String(req.query.actor || "").trim();
    if (!actor) return res.status(400).json({ error: "actor manquant" });

    let page = parseInt(String(req.query.page ?? "1"), 10);
    if (!Number.isInteger(page) || page < 1) page = 1;

    let perPage = parseInt(String(req.query.perPage ?? "50"), 10);
    perPage = Math.min(Math.max(perPage, 1), 100);

    const did = req.query.did ? String(req.query.did) : undefined;
    const computeTotal = String(req.query.computeTotal || "0") === "1";

    // Agent pour la page (viewer si dispo, sinon technique)
    let viewerAgent = null;
    if (did) {
      try {
        viewerAgent = await getAgentFromDid(did);
      } catch (e) {
        console.warn("[Proxy] getAgentFromDid a échoué, fallback technique:", e.message);
      }
    }
    if (!viewerAgent) viewerAgent = technicalAgent;

    console.log(`[Proxy] /feed/page actor=${actor} page=${page} perPage=${perPage} did=${did ?? "-"} (viewer=${viewerAgent === technicalAgent ? "tech" : "user"})`);

    // construit/complète l’index avec l’agent technique (ne jette pas si user non connecté)
    const idx = await ensureFeedIndex(actor, perPage, page, { computeUntilEnd: computeTotal });

    if (!idx.exhausted && idx.cursors.length < page) {
      await ensureFeedIndex(actor, perPage, page, { computeUntilEnd: false });
    }

    const startCursor = idx.cursors[page - 1] || undefined;

    // Récupère *la page demandée* avec l’agent viewer si possible (pour champs viewer.like)
    const resp = await viewerAgent.api.app.bsky.feed.getAuthorFeed({
      actor,
      limit: perPage,
      cursor: startCursor,
    });

    const feed = resp?.data?.feed || [];
    const nextCursor = resp?.data?.cursor || null;

    const hasPrev = page > 1;
    const hasNext = !!nextCursor || (!idx.exhausted);

    let totalPages = null;
    if (computeTotal || idx.exhausted) {
      totalPages = idx.cursors.length; // cursors[0]=null => pages = length
    }

    res.json({
      success: true,
      data: { feed, page, perPage, hasPrev, hasNext, totalPages },
    });
  } catch (err) {
  const did = didFromReq(req);
  const msg = String(err?.message || err);
  if (/token has expired/i.test(msg)) {
    markSessionDead(did, 'EXPIRED');
    clearSession(req);
    return res.status(401).set('x-auth-expired', '1')
      .json({ ok:false, error:'AUTH_EXPIRED' });
  }
  return res.status(500).json({ ok:false, error: msg });
}

});

// THREAD
app.get("/thread", async (req, res) => {
	const { uri, did } = req.query;
	if (!uri) return res.status(400).json({ error: "Paramètre 'uri' manquant" });

	let agent = technicalAgent;
	if (did && sessions[did]) {
		const userAgent = await getAgentFromDid(did);
		if (userAgent) agent = userAgent;
	}

	try {
		const result = await agent.getPostThread({ uri });
		res.json({ success: true, thread: result.data.thread });
	} catch (err) {
  const did = didFromReq(req);
  const msg = String(err?.message || err);
  if (/token has expired/i.test(msg)) {
    markSessionDead(did, 'EXPIRED');
    clearSession(req);
    return res.status(401).set('x-auth-expired', '1')
      .json({ ok:false, error:'AUTH_EXPIRED' });
  }
  return res.status(500).json({ ok:false, error: msg });
}

});

// LIKE
// --- LIKE ---
app.post("/like", async (req, res) => {
  const did = didFromReq(req);
  if (!did) return res.status(401).json({ error: "Utilisateur non connecté" });

  const agent = await getAgentFromDid(did);
  if (!agent) return res.status(401).json({ error: "Session invalide" });

  const { uri, cid } = req.body || {};
  if (!uri || !cid) return res.status(400).json({ error: "Paramètres manquants (uri,cid)" });

  try {
    const repoDid = agent.session?.did;
    if (!repoDid) return res.status(401).json({ error: "Session invalide (repoDid)" });

    const createdAt = new Date().toISOString();
    const result = await agent.api.app.bsky.feed.like.create(
      { repo: repoDid },
      { subject: { uri: String(uri), cid: String(cid) }, createdAt }
    );

    const likeUri = result?.uri || result?.data?.uri || null;
    return res.json({ success: true, uri: likeUri });
  } catch (err) {
  const did = didFromReq(req);
  const msg = String(err?.message || err);
  if (/token has expired/i.test(msg)) {
    markSessionDead(did, 'EXPIRED');
    clearSession(req);
    return res.status(401).set('x-auth-expired', '1')
      .json({ ok:false, error:'AUTH_EXPIRED' });
  }
  return res.status(500).json({ ok:false, error: msg });
}

});
/*
// --- UNLIKE ---
app.post("/unlike", async (req, res) => {
  const did = didFromReq(req);
  if (!did) return res.status(401).json({ error: "Utilisateur non connecté" });

  const agent = await getAgentFromDid(did);
  if (!agent) return res.status(401).json({ error: "Session invalide" });

  const { likeUri } = req.body || {};
  if (!likeUri) return res.status(400).json({ error: "Paramètre manquant (likeUri)" });

  try {
    const repoDid = agent.session?.did;
    if (!repoDid) return res.status(401).json({ error: "Session invalide (repoDid)" });

    const rkey = String(likeUri).split("/").pop();
    await agent.api.com.atproto.repo.deleteRecord({
      repo: repoDid,
      collection: "app.bsky.feed.like",
      rkey
    });

    return res.json({ success: true });
  } catch (err) {
  const did = didFromReq(req);
  const msg = String(err?.message || err);
  if (/token has expired/i.test(msg)) {
    markSessionDead(did, 'EXPIRED');
    clearSession(req);
    return res.status(401).set('x-auth-expired', '1')
      .json({ ok:false, error:'AUTH_EXPIRED' });
  }
  return res.status(500).json({ ok:false, error: msg });
}

});
*/
app.post("/unlike", async (req, res) => {
  try {
    // 1) session via cookie
    const did = didFromReq(req);
    if (!did) return res.status(401).json({ error: "Utilisateur non connecté" });

    // 2) entrée : on accepte soit likeUri, soit le sujet (uri/cid)
    const likeUri    = (req.body?.likeUri || "").toString().trim();
    const subjectUri = (req.body?.uri || req.body?.subjectUri || "").toString().trim();
    const subjectCid = (req.body?.cid || req.body?.subjectCid || "").toString().trim();

    if (!likeUri && !subjectUri) {
      return res.status(400).json({ error: "Paramètres manquants: 'likeUri' OU 'uri' (subjectUri)" });
    }

    // 3) agent utilisateur
    const agent = await getAgentFromDid(did);
    if (!agent) return res.status(401).json({ error: "Session invalide" });

    const repoDid = agent.session?.did;
    if (!repoDid) return res.status(403).json({ error: "Session utilisateur invalide (pas de DID)" });

    // 4) récupérer l'rkey
    let rkey = null;

    if (likeUri) {
      // likeUri ex: at://did:.../app.bsky.feed.like/3k4abcxyz
      const parts = likeUri.split("/");
      rkey = parts[parts.length - 1] || null;
    } else {
      // Fallback: on va chercher le like de l'utilisateur sur le post sujet
      try {
        const likesResp = await agent.api.app.bsky.feed.getLikes({
          uri: subjectUri,
          limit: 100
        });
        const list = likesResp?.data?.likes || [];
        const mine = list.find(l => l.actor?.did === repoDid);
        if (mine?.uri) {
          const parts = String(mine.uri).split("/");
          rkey = parts[parts.length - 1] || null;
        }
      } catch (e) {
        console.warn("[Proxy] getLikes fallback failed:", e?.message);
      }
    }

    if (!rkey) {
      return res.status(404).json({ error: "LIKE_NOT_FOUND_FOR_USER" });
    }

    // 5) suppression du record
    let del;
    try {
      del = await agent.api.com.atproto.repo.deleteRecord({
        repo: repoDid,
        collection: "app.bsky.feed.like",
        rkey
      });
    } catch (e) {
      console.error("[Proxy] ❌ unlike deleteRecord error:", e?.message, e?.response?.data || "");
      return res.status(500).json({ error: "UNLIKE_FAILED", detail: e?.message || "unknown" });
    }

    return res.json({ success: true, uri: del?.uri || likeUri || `at://${repoDid}/app.bsky.feed.like/${rkey}` });
 } catch (err) {
  const did = didFromReq(req);
  const msg = String(err?.message || err);
  if (/token has expired/i.test(msg)) {
    markSessionDead(did, 'EXPIRED');
    clearSession(req);
    return res.status(401).set('x-auth-expired', '1')
      .json({ ok:false, error:'AUTH_EXPIRED' });
  }
  return res.status(500).json({ ok:false, error: msg });
}

});



// POST /post  → publier un nouveau post (top-level)
app.post("/post", async (req, res) => {
  try {
    const payload = req.body || {};
    console.log("[Proxy] /post payload:", payload);

    const did = didFromReq(req);
	if (!did) return res.status(401).json({ error: "Utilisateur non connecté" });

	const agent = await getAgentFromDid(did);
	if (!agent) return res.status(401).json({ error: "Session invalide" });

    
	const text = typeof payload.text === "string" ? payload.text : "";
    const lang = payload.lang;

    if (!did)  return res.status(400).json({ error: "Paramètre did manquant" });
    if (!text) return res.status(400).json({ error: "Texte vide" });

    const body = text.trim();
    if (!body) return res.status(400).json({ error: "Texte vide (après trim)" });
    if (body.length > 300) return res.status(400).json({ error: "Texte trop long (max 300)" });

    const record = {
      $type: "app.bsky.feed.post",
      text: body,
      createdAt: new Date().toISOString(),
    };
    if (lang) record.langs = Array.isArray(lang) ? lang : [lang];

    console.log("[Proxy] /post record:", record);

    // Utilise l’API canonique
    const resp = await agent.com.atproto.repo.createRecord({
      repo: agent.session?.did || did,
      collection: "app.bsky.feed.post",
      record,
    });

    // Selon la version du client, c'est resp.data.{uri,cid}
    const uri = resp?.data?.uri || resp?.uri;
    const cid = resp?.data?.cid || resp?.cid;

    console.log("[Proxy] ✅ /post ok:", { uri, cid });

    return res.json({ success: true, uri, cid });
  } catch (e) {
    console.error("[Proxy] ❌ /post error:", e.message || e);
    return res.status(500).json({ error: "Erreur lors de la publication" });
  }
});
// juste au-dessus : garde bien ton "upload = multer({ storage:..., limits:{ fileSize: 5*1024*1024, files: 4 } })"

// petit logger pour vérifier ce que Node reçoit

const uploadImages = multer({
  storage: multer.memoryStorage(),
  limits: { files: 4, fileSize: 5 * 1024 * 1024 },
});
const LOG_LEVEL = (process.env.LOG_LEVEL || 'warn').toLowerCase();
const DEBUG = LOG_LEVEL === 'debug' || LOG_LEVEL === 'trace';
app.use((req, _res, next) => {
  if (DEBUG && req.path === "/post/images") {
    console.log("[Node sees] CT=%s Len=%s", req.headers['content-type'], req.headers['content-length']);
  }
  next();
});
app.post(
  '/post/images',
  requireMultipart,
  attachAbortLog,
  uploadImages.any(),                                  // 👈 capture tout, on filtrera
  async (req, res) => {
    try {
      const did = didFromReq(req);
      if (!did) return res.status(401).json({ error: 'Utilisateur non connecté' });
      const agent = await getAgentFromDid(did);
      if (!agent) return res.status(401).json({ error: 'Session invalide' });

      const text = typeof req.body?.text === 'string' ? req.body.text : '';
      const body = text.trim() || '\u200B';

      const all = Array.isArray(req.files) ? req.files : [];
      // 🔎 garde seulement images[0], images[1], ... (ou "images" si jamais)
      const files = all
        .filter(f => /^images(\[\d+\])?$/.test(f.fieldname))
        .sort((a, b) => {
          const ai = parseInt((a.fieldname.match(/\[(\d+)\]/) || [])[1] || '0', 10);
          const bi = parseInt((b.fieldname.match(/\[(\d+)\]/) || [])[1] || '0', 10);
          return ai - bi;
        });

      console.log('[Upload] fields:', all.map(f => f.fieldname));
      console.log('[Upload] kept:', files.map(f => ({ name: f.originalname, size: f.size, type: f.mimetype })));

      if (!files.length)     return res.status(400).json({ error: 'Aucune image reçue' });
      if (files.length > 4)  return res.status(400).json({ error: 'TOO_MANY_FILES' });
      if (body.length > 300) return res.status(400).json({ error: 'Texte trop long (max 300)' });

      for (const f of files) {
        if (!ALLOWED_MIME.has(f.mimetype)) {
          return res.status(415).json({ error: `Type non supporté: ${f.mimetype}` });
        }
      }

      const blobs = [];
      for (const f of files) {
        let up;
        try {
          up = await agent.com.atproto.repo.uploadBlob(f.buffer, { encoding: f.mimetype });
        } catch (e) {
          if (typeof agent.uploadBlob === 'function') {
            up = await agent.uploadBlob(f.buffer, { encoding: f.mimetype });
          } else {
            throw e;
          }
        }
        const blob = up?.data?.blob || up?.blob;
        if (!blob) return res.status(500).json({ error: 'Blob manquant après upload' });
        blobs.push({ image: blob, alt: '' });
      }

      const record = {
        $type: 'app.bsky.feed.post',
        text: body,
        createdAt: new Date().toISOString(),
        embed: { $type: 'app.bsky.embed.images', images: blobs },
        langs: ['fr'],
      };

      const resp = await agent.com.atproto.repo.createRecord({
        repo: agent.session?.did || did,
        collection: 'app.bsky.feed.post',
        record,
      });

      const uri = resp?.data?.uri || resp?.uri;
      const cid = resp?.data?.cid || resp?.cid;
      return res.json({ success: true, uri, cid });
    } catch (e) {
      console.error('[Proxy] ❌ /post/images error:', e?.message || e);
      return res.status(500).json({ error: 'Erreur lors de la publication' });
    }
  }
);

app.post("/post/video", uploadVideo.single("video"), async (req, res) => {
  try {
    const did = didFromReq(req);
    if (!did) return res.status(401).json({ error: "Utilisateur non connecté" });
    const agent = await getAgentFromDid(did);
    if (!agent) return res.status(401).json({ error: "Session invalide" });

    const f = req.file;
    const text = typeof req.body?.text === "string" ? req.body.text : "";
    let body = text.trim();
    if (!f) return res.status(400).json({ error: "Aucune vidéo reçue" });
    if (!body) body = "\u200B";
    if (body.length > 300) return res.status(400).json({ error: "Texte trop long (max 300)" });

    if (!ALLOWED_VIDEO_MIME.has(f.mimetype)) {
      return res.status(415).json({ error: `Type non supporté: ${f.mimetype}` });
    }

    // Upload du blob vidéo
    let up;
    try {
      up = await agent.com.atproto.repo.uploadBlob(f.buffer, { encoding: f.mimetype });
    } catch (e) {
      console.error("[Proxy] ❌ uploadBlob(video):", e.message || e);
      return res.status(500).json({ error: "Erreur upload vidéo" });
    }
    const blob = up?.data?.blob || up?.blob;
    if (!blob) return res.status(500).json({ error: "Blob manquant après upload" });

    // aspect ratio (optionnel, fourni par le front)
    const aspectW = parseInt(req.body?.aspectW || "", 10);
    const aspectH = parseInt(req.body?.aspectH || "", 10);
    const embed = { $type: "app.bsky.embed.video", video: blob };
    if (Number.isFinite(aspectW) && Number.isFinite(aspectH) && aspectW > 0 && aspectH > 0) {
      embed.aspectRatio = { width: aspectW, height: aspectH };
    }

    const record = {
      $type: "app.bsky.feed.post",
      text: body,
      createdAt: new Date().toISOString(),
      embed,
      langs: ["fr"],
    };

    const resp = await agent.com.atproto.repo.createRecord({
      repo: agent.session?.did || did,
      collection: "app.bsky.feed.post",
      record,
    });

    const uri = resp?.data?.uri || resp?.uri;
    const cid = resp?.data?.cid || resp?.cid;
    return res.json({ success: true, uri, cid });
  } catch (e) {
    console.error("[Proxy] ❌ /post/video error:", e.message || e);
    return res.status(500).json({ error: "Erreur lors de la publication" });
  }
});

// DELETE un post (ou un repost) de l'utilisateur connecté
// Supprimer un post (record app.bsky.feed.post)
app.post("/post/delete", async (req, res) => {
  try {
    const did = didFromReq(req);
    if (!did) return res.status(401).json({ error: "Utilisateur non connecté" });

    const uri = String(req.body?.uri || "").trim();
    if (!uri.startsWith("at://")) {
      return res.status(400).json({ error: "URI invalide" });
    }

    // at://did:xxx/app.bsky.feed.post/<rkey>
    const parts = uri.split("/");
    // parts: ["at:", "", "did:plc:...", "app.bsky.feed.post", "<rkey>"]
    const authorDid = parts[2] || "";
    const collection = parts[3] || "";
    const rkey = parts[4] || "";

    if (collection !== "app.bsky.feed.post" || !rkey) {
      return res.status(400).json({ error: "URI de post invalide" });
    }

    const agent = await getAgentFromDid(did);
    if (!agent) return res.status(401).json({ error: "Session invalide" });

    const repoDid = agent.session?.did;
    if (!repoDid) return res.status(403).json({ error: "Session utilisateur invalide" });

    // Sécurité : on ne peut supprimer QUE ses propres posts
    if (authorDid !== repoDid) {
      return res.status(403).json({ error: "FORBIDDEN_NOT_OWNER" });
    }

    const del = await agent.api.com.atproto.repo.deleteRecord({
      repo: repoDid,
      collection: "app.bsky.feed.post",
      rkey,
    });

    return res.json({ success: true, uri: del?.uri || uri });
  } catch (err) {
    console.error("[Proxy] ❌ /post/delete error:", err?.message || err);
    return res.status(500).json({ error: "DELETE_FAILED" });
  }
});



// COMMENT
// POST /comment — répondre à un post (ou à une réponse)
app.post("/comment", async (req, res) => {
  try {
    // 1) session via cookie
    const did = didFromReq(req);
    if (!did) return res.status(401).json({ error: "Utilisateur non connecté" });

    // 2) inputs
    const parentUri = (req.body?.parentUri || "").toString().trim();
    const textRaw   = (req.body?.text || "").toString();
    const lang      = req.body?.lang;

    const text = textRaw.trim();
    if (!parentUri) return res.status(400).json({ error: "Paramètre parentUri manquant" });
    if (!text)      return res.status(400).json({ error: "Texte vide" });
    if (text.length > 300) return res.status(400).json({ error: "Texte trop long (max 300)" });

    // 3) agent utilisateur
    const agent = await getAgentFromDid(did);
    if (!agent) return res.status(401).json({ error: "Session invalide" });

    // 4) récupérer parent + root
    let thr;
    try {
      thr = await agent.getPostThread({ uri: parentUri });
    } catch (e) {
      console.error("[Proxy] getPostThread error:", e?.message);
      return res.status(404).json({ error: "Post parent introuvable" });
    }

    const node = thr?.data?.thread;
    if (!node || node.notFound) return res.status(404).json({ error: "Post parent introuvable" });

    // parent = le post ciblé ; root = le premier ancêtre du thread
    const parentPost = node.post || node?.record || null;
    let rootNode = node;
    while (rootNode?.parent?.post) rootNode = rootNode.parent;
    const rootPost = rootNode?.post || parentPost;

    const parentCid = parentPost?.cid;
    const rootCid   = rootPost?.cid || parentCid;
    const rootUri   = rootPost?.uri || parentUri;

    if (!parentCid || !rootCid) {
      return res.status(400).json({ error: "CID du post parent introuvable" });
    }

    // 5) créer le record de reply
    const record = {
      $type: "app.bsky.feed.post",
      text,
      createdAt: new Date().toISOString(),
      reply: {
        root:   { uri: rootUri,   cid: rootCid   },
        parent: { uri: parentUri, cid: parentCid },
      },
    };
    if (lang) record.langs = Array.isArray(lang) ? lang : [lang];

    const resp = await agent.com.atproto.repo.createRecord({
      repo: agent.session?.did || did,
      collection: "app.bsky.feed.post",
      record,
    });

    const uri = resp?.data?.uri || resp?.uri;
    const cid = resp?.data?.cid || resp?.cid;
    return res.json({ success: true, uri, cid });
  } catch (err) {
    console.error("[Proxy] ❌ /comment error:", err?.message, err?.response?.data || "");
    return res.status(500).json({ error: "Erreur lors de l'envoi du commentaire" });
  }
});



// Éditer un post (implémentation "delete & re-post" côté Bluesky)
app.post('/post/edit', express.json(), async (req, res) => {
  res.set('Cache-Control', 'no-store');

  const viewerDid = req.session?.did || req.session?.user?.did || null;
  if (!viewerDid) return res.status(401).json({ ok:false, error:'NOT_AUTH' });

  const uri  = String(req.body?.uri || '').trim();
  const text = String(req.body?.text || '').trim();
  // facultatif : forcer la date d'origine au lieu de "maintenant"
  const preserveCreatedAt = !!req.body?.preserveCreatedAt;

  if (!uri || !text) return res.status(400).json({ ok:false, error:'BAD_INPUT' });

  const m = uri.match(/^at:\/\/([^/]+)\/app\.bsky\.feed\.post\/([^/]+)$/);
  if (!m) return res.status(400).json({ ok:false, error:'BAD_URI' });
  const postDid = m[1];
  const rkey    = m[2];
  if (postDid !== viewerDid) return res.status(403).json({ ok:false, error:'NOT_OWNER' });

  const agent = await getAgentFromDid(viewerDid);
  if (!agent) {
    res.set('x-auth-expired','1');
    return res.status(401).json({ ok:false, error:'AUTH_EXPIRED' });
  }

  try {
    // 1) lire l’ancien record pour récupérer médias/contexte
    const rec = await agent.com.atproto.repo.getRecord({
      repo: viewerDid,
      collection: 'app.bsky.feed.post',
      rkey
    });
    const prev = rec?.data?.value || {};

    // 2) nouveau record : texte remplacé, médias/contexte conservés
    const nextRecord = {
      $type: 'app.bsky.feed.post',
      text,
      // createdAt : soit on garde, soit on remet "maintenant" (par défaut)
      createdAt: preserveCreatedAt ? (prev.createdAt || new Date().toISOString())
                                   : new Date().toISOString(),
      ...(prev.langs ? { langs: prev.langs } : {}),
      ...(prev.embed ? { embed: prev.embed } : {}),
      ...(prev.reply ? { reply: prev.reply } : {}),
      // ⚠️ on NE reprend PAS prev.facets (offsets invalides avec le nouveau texte)
    };

    // 3) créer le nouveau post
    const cr = await agent.com.atproto.repo.createRecord({
      repo: viewerDid,
      collection: 'app.bsky.feed.post',
      record: nextRecord
    });
    const newUri = cr?.data?.uri || cr?.uri;
    const newCid = cr?.data?.cid || cr?.cid;

    // 4) supprimer l’ancien
    await agent.com.atproto.repo.deleteRecord({
      repo: viewerDid,
      collection: 'app.bsky.feed.post',
      rkey
    });

    // 5) (optionnel) purger un éventuel cache de pagination serveur
    try {
      // si tu caches des pages par acteur → supprime les clés liées au handle/DID
      // feedIndexCache.clear(); // ou ciblé si tu préfères
    } catch {}

    return res.json({ ok:true, success:true, old: uri, uri: newUri, cid: newCid });
  } catch (err) {
    const msg = String(err?.message || err);
    console.error('[EditPost:repost]', msg);

    if (/token has expired/i.test(msg)) {
      markSessionDead?.(viewerDid, 'EXPIRED');
      clearSession?.(req);
      return res.status(401).set('x-auth-expired','1').json({ ok:false, error:'AUTH_EXPIRED' });
    }
    if (/Unauthorized|Forbidden/.test(msg)) {
      return res.status(403).json({ ok:false, error:'NOT_ALLOWED' });
    }
    if (/Record not found/i.test(msg)) {
      return res.status(404).json({ ok:false, error:'NOT_FOUND' });
    }
    return res.status(500).json({ ok:false, error:'SERVER_ERROR' });
  }
});




// DELETE COMMENT (supprime un app.bsky.feed.post qui est une reply)
app.post('/comment/delete', express.json(), async (req, res) => {
  res.set('Cache-Control', 'no-store');

  const viewerDid = req.session?.did || req.session?.user?.did || null;
  if (!viewerDid) return res.status(401).json({ ok: false, error: 'NOT_AUTH' });

  // On attend { uri: "at://did:.../app.bsky.feed.post/<rkey>" }
  const uri = (req.body?.uri || '').trim();
  const m = uri.match(/^at:\/\/([^/]+)\/app\.bsky\.feed\.post\/([^/]+)$/);
  if (!m) return res.status(400).json({ ok: false, error: 'BAD_URI' });

  const commentAuthorDid = m[1];
  const rkey = m[2];

  // Sécurité: on n’autorise la suppression que des commentaires du viewer
  if (commentAuthorDid !== viewerDid) {
    return res.status(403).json({ ok: false, error: 'NOT_OWNER' });
  }

  const agent = await getAgentFromDid(viewerDid);
  if (!agent) {
    res.set('x-auth-expired', '1');
    return res.status(401).json({ ok: false, error: 'AUTH_EXPIRED' });
  }

  try {
    await agent.com.atproto.repo.deleteRecord({
      repo: viewerDid,
      collection: 'app.bsky.feed.post',
      rkey
    });
    return res.json({ ok: true, uri });
  } catch (err) {
    const msg = String(err?.message || err);
    console.error('[DeleteComment]', msg);

    if (/token has expired/i.test(msg)) {
      markSessionDead?.(viewerDid, 'EXPIRED');
      clearSession?.(req);
      return res.status(401).set('x-auth-expired', '1').json({ ok: false, error: 'AUTH_EXPIRED' });
    }
    if (/Record not found/i.test(msg)) {
      return res.status(404).json({ ok: false, error: 'NOT_FOUND' });
    }
    if (/Unauthorized|Forbidden|cannot/i.test(msg)) {
      return res.status(403).json({ ok: false, error: 'NOT_ALLOWED' });
    }
    return res.status(500).json({ ok: false, error: 'SERVER_ERROR' });
  }
});

// --- Fallback d'agent technique pour la recherche ---
let __TECH_AGENT = null;

async function ensureTechAgent() {
  // Réutilise un agent déjà initialisé si présent
  if (global.techAgent) return global.techAgent;
  if (__TECH_AGENT) return __TECH_AGENT;

  // Lis la conf depuis l'env (adapte si besoin à tes variables)
  const service  = process.env.BSKY_SERVICE || process.env.BLUESKY_SERVICE || 'https://bsky.social';
  const handle   = process.env.FEED_BSKY_HANDLE;
  const password = process.env.FEED_BSKY_PASSWORD;

  if (!handle || !password) {
    console.warn('[Suggest] Aucun identifiant technique (handle/password) trouvé dans les variables d’environnement.');
    return null;
  }

  // ⚠️ suppose que BskyAgent est déjà importé plus haut dans ton fichier.
  const agent = new BskyAgent({ service });
  await agent.login({ identifier: handle, password });

  __TECH_AGENT = agent;
  global.techAgent = agent; // pour réutilisation ailleurs si tu veux
  console.log('[Suggest] Agent technique prêt pour la recherche.');
  return agent;
}

app.get('/search/suggest', suggestLimiter, async (req, res) => {
  res.set('Cache-Control', 'no-store');

  const qRaw = (req.query.q || '').trim();
  const q = qRaw.replace(/\s+/g, ' ');
  const limit = Math.min(parseInt(req.query.limit || '10', 10) || 10, 25);
  if (q.length < 2) return res.json({ ok: true, suggestions: [] });

  const viewerDid = req.session?.did || req.session?.user?.did || null;

  // 1) DB d’abord (mise en avant)
  const like = `%${q}%`;
  const dbRows = await dbQuery(
    `SELECT did, handle, displayName, avatar
     FROM users
     WHERE handle LIKE ? OR displayName LIKE ?
     ORDER BY last_seen DESC
     LIMIT ?`,
    [like, like, limit * 2]
  );

  const dbMap = new Map();
  for (const r of dbRows) {
    const key = r.did || normHandle(r.handle);
    if (!key) continue;
    dbMap.set(key, {
      source: 'db',
      inDb: true,
      did: r.did || null,
      handle: r.handle ? (r.handle.startsWith('@') ? r.handle : '@' + r.handle) : null,
      displayName: r.displayName || null,
      avatar: r.avatar || null,
      score: 1000, // gros boost DB
    });
  }

  // 2) Bluesky API (via agent “viewer” si possible, sinon compte technique)
  // 2) Bluesky API (via agent “viewer” si possible, sinon compte technique)
let bskyActors = [];
try {
  let agent = null;

  // d'abord l'agent de l'utilisateur connecté (si possible)
  if (viewerDid) {
    agent = await getAgentFromDid(viewerDid); // ta fonction existante
  }

  // sinon bascule sur l'agent technique
  if (!agent) {
    agent = await ensureTechAgent();          // ⬅️ NOUVEAU fallback
  }

  if (!agent) {
    console.warn('[Suggest] Pas d’agent disponible pour la recherche Bluesky.');
  } else {
    // API officielle: app.bsky.actor.searchActors (query + limit)
    const r = await agent.api.app.bsky.actor.searchActors({ q, limit: 30 });
    bskyActors = r?.data?.actors || [];
  }
} catch (e) {
  console.warn('[Suggest] Bluesky search error:', e?.message || e);
}


  // 3) Fusion avec dédoublonnage (DB prioritaire)
  const seen = new Set();
  const out = [];

  // Helper de score simple: begins-with > contains
  function rankScore(handle, displayName) {
    const h = normHandle(handle);
    const qq = normHandle(q);
    if (h.startsWith(qq)) return 200;
    if ((displayName || '').toLowerCase().startsWith(q.toLowerCase())) return 180;
    if (h.includes(qq)) return 120;
    return 80;
  }

  // 3a) DB en premier
  for (const v of dbMap.values()) {
    const key = v.did || normHandle(v.handle);
    if (!key) continue;
    seen.add(key);
    out.push(v);
  }

  // 3b) Bluesky ensuite
  for (const a of bskyActors) {
    const key = a.did || normHandle(a.handle);
    if (!key || seen.has(key)) continue;
    const item = {
      source: 'bsky',
      inDb: !!dbMap.get(key),
      did: a.did || null,
      handle: a.handle ? (a.handle.startsWith('@') ? a.handle : '@' + a.handle) : null,
      displayName: a.displayName || null,
      avatar: a.avatar || null,
      score: rankScore(a.handle, a.displayName),
    };
    seen.add(key);
    out.push(item);
  }

  // 4) Tri final: score desc, DB devant à score égal
  out.sort((a, b) => (b.score - a.score) || ((b.inDb === true) - (a.inDb === true)));

  // 5) Coupe à “limit”
  const suggestions = out.slice(0, limit);

  return res.json({ ok: true, suggestions });
});


async function fetchAuthorFeedDeep(agent, { actor, limit = 50, cursor, pages = 1 }) {
  const all = [];
  let cur = cursor || undefined;

  for (let i = 0; i < pages; i++) {
    const resp = await agent.api.app.bsky.feed.getAuthorFeed({
      actor,
      limit,
      cursor: cur,
    });

    const feed = resp?.data?.feed || [];
    all.push(...feed);

    cur = resp?.data?.cursor;
    if (!cur) break; // plus de page
  }

  return { feed: all, cursor: cur };
}
// START
app.listen(port, () => {
	console.log(`[Proxy] 🚀 Bluesky Proxy API running on http://localhost:${port}`);
});
