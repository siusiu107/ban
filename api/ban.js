// Vercel Serverless Function: POST /api/ban
// Body: { idToken: string, reason?: string, suspicion?: number }

const admin = require("firebase-admin");

function initAdmin() {
  if (admin.apps.length) return admin;

  const projectId   = process.env.FIREBASE_PROJECT_ID;
  const clientEmail = process.env.FIREBASE_CLIENT_EMAIL;
  // 줄바꿈이 \n 문자로 저장된 경우를 모두 실제 개행으로 치환
  const privateKeyRaw = process.env.FIREBASE_PRIVATE_KEY || "";
  const privateKey = privateKeyRaw.includes("\\n")
    ? privateKeyRaw.replace(/\\n/g, "\n")
    : privateKeyRaw;

  admin.initializeApp({
    credential: admin.credential.cert({ projectId, clientEmail, privateKey }),
    databaseURL: process.env.FIREBASE_DATABASE_URL
  });
  return admin;
}

function allowCors(req, res) {
  const allow = (process.env.CORS_ALLOW_ORIGIN || "*")
    .split(",")
    .map(s => s.trim())
    .filter(Boolean);

  const origin = req.headers.origin || "";
  const ok =
    allow.includes("*") ||
    allow.includes(origin) ||
    allow.some(a => a && origin.endsWith(a.replace(/^\*?https?:\/\//, "")));

  if (ok && origin) res.setHeader("Access-Control-Allow-Origin", origin);
  else if (allow.includes("*")) res.setHeader("Access-Control-Allow-Origin", "*");

  res.setHeader("Vary", "Origin");
  res.setHeader("Access-Control-Allow-Methods", "POST,OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
}

module.exports = async function handler(req, res) {
  allowCors(req, res);
  if (req.method === "OPTIONS") return res.status(204).end();
  if (req.method !== "POST") return res.status(405).json({ error: "Method Not Allowed" });

  try {
    const { idToken, reason = "auto-ban", suspicion = null } = req.body || {};
    if (!idToken) return res.status(400).json({ error: "Missing idToken" });

    const app = initAdmin();

    // 1) 토큰 검증
    let decoded;
    try {
      decoded = await app.auth().verifyIdToken(idToken, true);
    } catch (e) {
      return res.status(401).json({ error: "Invalid idToken" });
    }

    const uid = decoded.uid;

    // 2) 계정 정지
    await app.auth().updateUser(uid, { disabled: true });

    // 3) (선택) RTDB에 로그 남기기
    try {
      const ts = Date.now();
      await app.database().ref(`banLogs/${uid}/${ts}`).set({
        reason,
        suspicion,
        by: "vercel-api",
        at: ts
      });
    } catch {}

    return res.status(200).json({ ok: true, uid, disabled: true });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Server error" });
  }
};
