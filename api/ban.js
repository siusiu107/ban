// Vercel Serverless Function: POST /api/ban
// Body(JSON): { idToken?: string, reason?: string, suspicion?: number }
// Header: Authorization: Bearer <idToken>  도 허용

const admin = require("firebase-admin");

// ---------- CORS ----------
function allowCors(req, res) {
  const allow = (process.env.CORS_ALLOW_ORIGIN || "*")
    .split(",")
    .map(s => s.trim())
    .filter(Boolean);

  const origin = req.headers.origin || "";
  const ok =
    allow.includes("*") ||
    allow.includes(origin) ||
    allow.some(a => {
      // *.example.com 같은 값도 대충 처리
      const norm = a.replace(/^\*?https?:\/\//, "");
      return norm && origin.endsWith(norm);
    });

  if (ok && origin) res.setHeader("Access-Control-Allow-Origin", origin);
  else if (allow.includes("*")) res.setHeader("Access-Control-Allow-Origin", "*");

  res.setHeader("Vary", "Origin");
  res.setHeader("Access-Control-Allow-Methods", "POST,OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
  res.setHeader("Access-Control-Max-Age", "86400"); // 24h
}

// ---------- ENV & ADMIN INIT ----------
function readPrivateKeyFromEnv() {
  const base64 = process.env.FIREBASE_PRIVATE_KEY_BASE64;
  if (base64) {
    try {
      return Buffer.from(base64, "base64").toString("utf8");
    } catch (_) {
      // fall through to plain key
    }
  }
  const raw = process.env.FIREBASE_PRIVATE_KEY || "";
  return raw.includes("\\n") ? raw.replace(/\\n/g, "\n") : raw;
}

function validateEnv() {
  const reqs = [
    "FIREBASE_PROJECT_ID",
    "FIREBASE_CLIENT_EMAIL",
    // PRIVATE KEY는 둘 중 하나면 충분
    // "FIREBASE_PRIVATE_KEY" or "FIREBASE_PRIVATE_KEY_BASE64",
    "FIREBASE_DATABASE_URL",
  ];
  const missing = reqs.filter(k => !process.env[k]);
  const priv = readPrivateKeyFromEnv();
  if (!priv) missing.push("FIREBASE_PRIVATE_KEY or FIREBASE_PRIVATE_KEY_BASE64");

  return { ok: missing.length === 0, missing, privateKey: priv };
}

function initAdmin() {
  if (globalThis.__admin) return globalThis.__admin;
  if (admin.apps.length) {
    globalThis.__admin = admin;
    return admin;
  }

  const { ok, missing, privateKey } = validateEnv();
  if (!ok) {
    const err = new Error("Environment misconfigured: " + missing.join(", "));
    err.code = "env_misconfigured";
    throw err;
  }

  const projectId   = process.env.FIREBASE_PROJECT_ID;
  const clientEmail = process.env.FIREBASE_CLIENT_EMAIL;
  const databaseURL = process.env.FIREBASE_DATABASE_URL;

  admin.initializeApp({
    credential: admin.credential.cert({ projectId, clientEmail, privateKey }),
    databaseURL
  });

  globalThis.__admin = admin;
  return admin;
}

// ---------- Helpers ----------
function json(res, status, payload) {
  res.status(status);
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.setHeader("Cache-Control", "no-store");
  return res.end(JSON.stringify(payload));
}

function getIdTokenFromReq(req) {
  // 1) Authorization header
  const authz = req.headers.authorization || req.headers.Authorization;
  if (typeof authz === "string" && authz.toLowerCase().startsWith("bearer ")) {
    return authz.slice(7).trim();
  }
  // 2) body.idToken
  const b = req.body;
  if (!b) return null;
  if (typeof b === "string") {
    try { const o = JSON.parse(b); return o.idToken || null; }
    catch { return null; }
  }
  if (typeof b === "object") {
    return b.idToken || null;
  }
  return null;
}

function parseBody(req) {
  // Vercel가 JSON으로 파싱해주지만 혹시 모를 케이스 대비
  let body = req.body;
  if (typeof body === "string") {
    try { body = JSON.parse(body); } catch { body = {}; }
  }
  if (!body || typeof body !== "object") body = {};
  return body;
}

function mapAuthError(e) {
  const code = e?.errorInfo?.code || e?.code || "";
  const msg  = e?.message || String(e);

  // verifyIdToken 관련
  if (code.includes("auth/invalid-id-token")) return { status: 401, code: "invalid_id_token", message: "Invalid ID token." };
  if (code.includes("auth/id-token-expired")) return { status: 401, code: "id_token_expired", message: "ID token expired." };
  if (code.includes("auth/id-token-revoked")) return { status: 401, code: "id_token_revoked", message: "ID token revoked." };
  if (code.includes("auth/argument-error"))   return { status: 400, code: "argument_error", message: "Bad token format." };

  // updateUser 관련
  if (code.includes("auth/user-not-found"))          return { status: 404, code: "user_not_found", message: "User not found." };
  if (code.includes("auth/insufficient-permission")) return { status: 403, code: "insufficient_permission", message: "Service account lacks permission." };

  // 서비스계정/키 문제
  if (msg.includes("PEM") || msg.includes("private key")) {
    return { status: 500, code: "private_key_invalid", message: "Invalid service account private key." };
  }

  return { status: 500, code: "auth_internal", message: "Auth operation failed." };
}

// ---------- Handler ----------
module.exports = async function handler(req, res) {
  try {
    allowCors(req, res);
    if (req.method === "OPTIONS") return res.status(204).end();
    if (req.method !== "POST") {
      res.setHeader("Allow", "POST, OPTIONS");
      return json(res, 405, { error: "method_not_allowed" });
    }

    // ENV/ADMIN 준비
    let app;
    try {
      app = initAdmin();
    } catch (e) {
      const code = e.code === "env_misconfigured" ? 500 : 500;
      return json(res, code, { ok: false, error: e.code || "env_misconfigured", message: e.message });
    }

    const body = parseBody(req);
    const reason = (body.reason && String(body.reason).slice(0, 120)) || "auto-ban";
    const suspicion = Number.isFinite(Number(body.suspicion)) ? Number(body.suspicion) : null;

    // 토큰 추출/검증
    const idToken = getIdTokenFromReq(req);
    if (!idToken) return json(res, 400, { ok: false, error: "missing_id_token", message: "idToken is required." });

    let decoded;
    try {
      // checkRevoked=true 사용 시, 만료/취소 토큰을 401로 식별
      decoded = await app.auth().verifyIdToken(idToken, true);
    } catch (e) {
      const m = mapAuthError(e);
      return json(res, m.status, { ok: false, error: m.code, message: m.message });
    }

    const uid = decoded.uid;

    // 계정 정지
    try {
      await app.auth().updateUser(uid, { disabled: true });
    } catch (e) {
      const m = mapAuthError(e);
      return json(res, m.status, { ok: false, error: m.code, message: m.message });
    }

    // RTDB 로그는 응답 차단하지 않도록 fire-and-forget
    // (네트워크 지연으로 타임아웃 유발하지 않게)
    try {
      const ts = Date.now();
      const ref = app.database().ref(`banLogs/${uid}/${ts}`);
      const payload = { reason, by: "vercel-api", at: ts };
      if (suspicion !== null) payload.suspicion = suspicion;
      // 굳이 await하지 않음 -> 지연으로 인한 500 방지
      ref.set(payload).catch(()=>{});
    } catch (_) {
      // 무시
    }

    return json(res, 200, { ok: true, uid, disabled: true });
  } catch (err) {
    // 어떤 예외든 마지막 방어막: INTERNAL 대신 구체 메시지
    console.error("[/api/ban] unexpected error:", err);
    return json(res, 500, { ok: false, error: "unhandled_error", message: err?.message || "Server error" });
  }
};
