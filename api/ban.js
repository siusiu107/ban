const admin = require('firebase-admin');

function getEnv(name, fallback = '') {
  const v = process.env[name];
  return v && v.trim() ? v : fallback;
}

const sa = getEnv('FIREBASE_SERVICE_ACCOUNT'); // 서비스계정 JSON 문자열(필수)
const rtdbUrl = getEnv('FIREBASE_RTDB_URL');   // 선택
const allowed = (getEnv('ALLOWED_ORIGINS') || '')
  .split(',').map(s => s.trim()).filter(Boolean);

if (!admin.apps.length) {
  admin.initializeApp({
    credential: admin.credential.cert(JSON.parse(sa || '{}')),
    databaseURL: rtdbUrl || undefined,
  });
}

function isOriginAllowed(origin) {
  if (!allowed.length) return true;       // 환경변수 안 넣으면 전체 허용(간편)
  try {
    const u = new URL(origin);
    const full = `${u.protocol}//${u.host}`;
    return allowed.includes(full);
  } catch { return false; }
}

module.exports = async (req, res) => {
  // CORS preflight
  if (req.method === 'OPTIONS') {
    res.setHeader('Access-Control-Allow-Origin', req.headers.origin || '*');
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    return res.status(200).end();
  }

  if (!isOriginAllowed(req.headers.origin)) {
    return res.status(403).json({ error: 'forbidden-origin' });
  }
  res.setHeader('Access-Control-Allow-Origin', req.headers.origin || '*');
  res.setHeader('Vary', 'Origin');

  if (req.method !== 'POST') return res.status(405).json({ error: 'method-not-allowed' });

  try {
    const { idToken, reason, suspicion } = (req.body || {});
    if (!idToken) return res.status(400).json({ error: 'missing-idToken' });

    const decoded = await admin.auth().verifyIdToken(String(idToken), true);
    const uid = decoded.uid;

    await admin.auth().updateUser(uid, { disabled: true });
    await admin.auth().revokeRefreshTokens(uid);

    try {
      await admin.database().ref(`bans/${uid}`).set({
        disabled: true,
        by: 'auto-ban',
        reason: reason || 'auto-ban',
        suspicion: suspicion ?? null,
        at: Date.now()
      });
    } catch {}

    return res.status(200).json({ ok: true });
  } catch (e) {
    return res.status(500).json({ error: e?.message || 'ban-failed' });
  }
};
