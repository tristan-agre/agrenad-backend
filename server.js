// server.js
"use strict";

const express = require("express");
const cors = require("cors");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const bcrypt = require("bcryptjs");

const app = express();
const PORT = process.env.PORT || 3000;

// =====================================================
// CONFIG
// =====================================================
app.set("trust proxy", 1); // IMPORTANT sur Render (req.secure via x-forwarded-proto)

const DATA_FILE = path.join(__dirname, "commandes.json");

const SERVICES = ["petitdej", "bar", "entretien"];
const SESSION_COOKIE = "agrenad_session";
const SESSION_TTL_MS = 1000 * 60 * 60 * 8; // 8h

const SETUP_SECRET = process.env.SETUP_SECRET || "";
const MAX_PINS = 2;

// Si tu utilises Live Server ou localhost :
const FRONT_ORIGINS = [
  "http://localhost:5500",
  "http://127.0.0.1:5500",
  "http://localhost:3000",
  "http://127.0.0.1:3000",
  // Ajoute Netlify si tu l'as :
  // "https://ton-site.netlify.app",
];

// =====================================================
// MIDDLEWARES
// =====================================================
app.use(express.json({ limit: "1mb" }));

// CORS : avec cookies => PAS de "*"
app.use(
  cors({
    origin: (origin, cb) => {
      // origin undefined / null => typiquement file://
      // On autorise en dev (sinon tu ne peux pas tester depuis file://)
      if (!origin) return cb(null, true);

      if (FRONT_ORIGINS.includes(origin)) return cb(null, true);

      // Si tu veux être permissif le temps de dev :
      // return cb(null, true);

      return cb(new Error(`CORS blocked for origin: ${origin}`));
    },
    credentials: true,
  })
);

// Petit middleware pratique : répondre OK sur preflight
app.options("*", cors());
app.disable("etag");
app.use((req, res, next) => {
 /* if(req.acceptsCharsets.startsWith("/api/")) {
  res.setHeader("Cache-control", "no-store, no-cache, must-revalidate, proxy-revalidate");
  res.setHeader("Pragma", "no-cache");
  res.setHeader("Expires", "0");
  res.setHeader("Surrogate-control", "no-store");
  }*/
next();
});

// =====================================================
// HELPERS (cookies / https)
// =====================================================
function parseCookies(req) {
  const header = req.headers.cookie || "";
  const out = {};
  header.split(";").forEach((part) => {
    const [k, ...v] = part.trim().split("=");
    if (!k) return;
    out[k] = decodeURIComponent(v.join("=") || "");
  });
  return out;
}

function isHttpsRequest(req) {
  // Sur Render : x-forwarded-proto = https
  const xfProto = (req.headers["x-forwarded-proto"] || "").toString().toLowerCase();
  if (xfProto.includes("https")) return true;
  // Sur local https (rare) :
  if (req.secure) return true;
  return false;
}

function getBearerToken(req) {
  const h = req.headers.authorization || "";
  const m = /^Bearer\s+(.+)$/i.exec(h);
  return m ? m[1] : "";
}

function ensureService(service) {
  return SERVICES.includes(service);
}

// =====================================================
// DATA LAYER
// =====================================================
function defaultData() {
  return {
    petitdej: null,
    bar: null,
    entretien: null,
    validated: null, // snapshot validé
    pins: {}, // { pinId: { hash, createdAt } }
    sessions: {}, // { token: { pinId, expiresAt } }
  };
}

function loadData() {
  try {
    if (!fs.existsSync(DATA_FILE)) return defaultData();
    const raw = fs.readFileSync(DATA_FILE, "utf8");
    if (!raw || raw.trim() === "") return defaultData();

    const d = JSON.parse(raw);

    return {
      petitdej: d.petitdej ?? null,
      bar: d.bar ?? null,
      entretien: d.entretien ?? null,
      validated: d.validated ?? null,
      pins: d.pins ?? {},
      sessions: d.sessions ?? {},
    };
  } catch (e) {
    console.error("❌ loadData failed:", e);
    return defaultData();
  }
}

function saveData(data) {
  // purge sessions expirées
  const now = Date.now();
  if (data.sessions) {
    for (const token of Object.keys(data.sessions)) {
      const s = data.sessions[token];
      if (!s || s.expiresAt <= now) delete data.sessions[token];
    }
  }
  fs.writeFileSync(DATA_FILE, JSON.stringify(data, null, 2), "utf8");
}

function sanitizeValue(v) {
  if (v === null || v === undefined) return "";
  if (typeof v === "number") return String(v);
  if (typeof v === "string") return v.trim();
  if (typeof v === "boolean") return v ? "1" : "0";
  return "";
}

function normalizeDonnees(obj) {
  if (!obj || typeof obj !== "object") return {};
  const out = {};
  for (const k of Object.keys(obj)) {
    out[k] = sanitizeValue(obj[k]);
  }
  return out;
}

function extractDonneesFromBody(reqBody) {
  // Format attendu : { donnees: {...} }
  // Tolérance : si l'utilisateur envoie directement {...}
  if (!reqBody || typeof reqBody !== "object") return {};
  if (reqBody.donnees && typeof reqBody.donnees === "object") return normalizeDonnees(reqBody.donnees);
  return normalizeDonnees(reqBody);
}

// =====================================================
// AUTH (sessions cookie + bearer fallback)
// =====================================================
function createSession(data, pinId) {
  const token = crypto.randomBytes(24).toString("hex");
  data.sessions[token] = { pinId, expiresAt: Date.now() + SESSION_TTL_MS };
  return token;
}

function getSession(data, req) {
  // 1) Bearer (fallback si cookies bloqués)
  const bearer = getBearerToken(req);
  if (bearer && data.sessions?.[bearer] && data.sessions[bearer].expiresAt > Date.now()) {
    return { token: bearer, ...data.sessions[bearer] };
  }

  // 2) Cookie
  const cookies = parseCookies(req);
  const token = cookies[SESSION_COOKIE];
  if (!token) return null;
  const sess = data.sessions?.[token];
  if (!sess) return null;
  if (sess.expiresAt <= Date.now()) return null;
  return { token, ...sess };
}

function refreshSession(data, token) {
  if (data.sessions?.[token]) {
    data.sessions[token].expiresAt = Date.now() + SESSION_TTL_MS;
  }
}

function requireKitchenAuth(req, res, next) {
  const data = loadData();
  const sess = getSession(data, req);
  if (!sess) return res.status(401).json({ error: "UNAUTHORIZED" });

  refreshSession(data, sess.token);
  saveData(data);
  next();
  return next();
}

function setSessionCookie(req, res, token) {
  const maxAge = Math.floor(SESSION_TTL_MS / 1000);
  const https = isHttpsRequest(req);

  // En prod cross-site => SameSite=None; Secure obligatoire
  // En local http => Secure interdit, donc Lax
  const sameSite = https ? "None" : "Lax";
  const securePart = https ? " Secure;" : "";

  res.setHeader(
    "Set-Cookie",
    `${SESSION_COOKIE}=${encodeURIComponent(token)}; Path=/; HttpOnly; SameSite=${sameSite};${securePart} Max-Age=${maxAge}`
  );
}

function clearSessionCookie(req, res) {
  const https = isHttpsRequest(req);
  const sameSite = https ? "None" : "Lax";
  const securePart = https ? " Secure;" : "";

  res.setHeader(
    "Set-Cookie",
    `${SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=${sameSite};${securePart} Max-Age=0`
  );
}

// =====================================================
// ROUTES
// =====================================================
app.get("/", (req, res) => res.send("AGRENAD backend OK"));
app.get("/api/hello", (req, res) => res.json({ ok: true, message: "hello" }));

// ---------- COMMANDES ----------
app.get("/api/commandes", (req, res) => {
  const data = loadData();
  res.json({ petitdej: data.petitdej, bar: data.bar, entretien: data.entretien });
});

app.get("/api/commandes/:service", (req, res) => {
  const service = req.params.service;
  if (!ensureService(service)) return res.status(400).json({ error: "Service inconnu" });
  const data = loadData();
  res.json(data[service] || null);
});

// POST + PUT => même handler
function upsertCommande(req, res) {
  const service = req.params.service;
  if (!ensureService(service)) return res.status(400).json({ error: "Service inconnu" });

  const donnees = extractDonneesFromBody(req.body);
  const data = loadData();

  data[service] = {
    donnees,
    updatedAt: new Date().toISOString(),
  };

  try {
    saveData(data);
    res.json({ success: true, service, updatedAt: data[service].updatedAt });
  } catch (e) {
    console.error("❌ saveData failed (commandes upsert):", e);
    res.status(500).json({ error: "SAVE_FAILED" });
  }
}

app.post("/api/commandes/:service", upsertCommande);
app.put("/api/commandes/:service", upsertCommande);

app.post("/api/reset/:service", (req, res) => {
  const service = req.params.service;
  if (!ensureService(service)) return res.status(400).json({ error: "Service inconnu" });

  const data = loadData();
  data[service] = null;

  try {
    saveData(data);
    res.json({ success: true, service, reset: true });
  } catch (e) {
    console.error("❌ reset service failed:", e);
    res.status(500).json({ error: "RESET_FAILED" });
  }
});

app.post("/api/reset-all", (req, res) => {
  const data = loadData();
  data.petitdej = null;
  data.bar = null;
  data.entretien = null;
  data.validated = null;

  try {
    saveData(data);
    res.json({ success: true, resetAll: true });
  } catch (e) {
    console.error("❌ reset-all failed:", e);
    res.status(500).json({ error: "RESET_ALL_FAILED" });
  }
});

// ---------- VALIDATION ----------
app.post("/api/validate", requireKitchenAuth, (req, res) => {
  const data = loadData();
  data.validated = {
    commandes: {
      petitdej: data.petitdej,
      bar: data.bar,
      entretien: data.entretien,
    },
    validatedAt: new Date().toISOString(),
  };

  try {
    saveData(data);
    res.json({ success: true, validatedAt: data.validated.validatedAt });
  } catch (e) {
    console.error("❌ validate failed:", e);
    res.status(500).json({ error: "VALIDATE_FAILED" });
  }
});

app.get("/api/validated", (req, res) => {
  const data = loadData();
  res.json(data.validated || null);
});

app.post("/api/validated/reset", requireKitchenAuth, (req, res) => {
  const data = loadData();
  data.validated = null;

  try {
    saveData(data);
    res.json({ success: true, resetValidated: true });
  } catch (e) {
    console.error("❌ reset validated failed:", e);
    res.status(500).json({ error: "RESET_VALIDATED_FAILED" });
  }
});

// ---------- PIN / AUTH ----------
app.get("/api/pin/status", (req, res) => {
  const data = loadData();
  const count = Object.keys(data.pins || {}).length;
  res.json({
    pinsCount: count,
    maxPins: MAX_PINS,
    setupEnabled: !!SETUP_SECRET,
  });
});

app.post("/api/pin/setup", async (req, res) => {
  if (!SETUP_SECRET) return res.status(400).json({ error: "SETUP_SECRET_NOT_CONFIGURED" });

  const { setupSecret, pin } = req.body || {};
  if (!setupSecret || setupSecret !== SETUP_SECRET) return res.status(401).json({ error: "BAD_SETUP_SECRET" });

  const pinStr = String(pin || "").trim();
  if (!/^\d{4}$/.test(pinStr)) return res.status(400).json({ error: "PIN_MUST_BE_4_DIGITS" });

  const data = loadData();
  const ids = Object.keys(data.pins || {});
  if (ids.length >= MAX_PINS) return res.status(400).json({ error: "MAX_PINS_REACHED" });

  // empêche doublon
  for (const id of ids) {
    const ok = await bcrypt.compare(pinStr, data.pins[id].hash);
    if (ok) return res.status(400).json({ error: "PIN_ALREADY_EXISTS" });
  }

  const pinId = crypto.randomBytes(8).toString("hex");
  const hash = await bcrypt.hash(pinStr, 10);
  data.pins[pinId] = { hash, createdAt: new Date().toISOString() };

  try {
    saveData(data);
    res.json({ success: true, pinCreated: true, pinsCount: Object.keys(data.pins).length });
  } catch (e) {
    console.error("❌ pin setup save failed:", e);
    res.status(500).json({ error: "PIN_SETUP_SAVE_FAILED" });
  }
});

app.post("/api/pin/login", async (req, res) => {
  const { pin } = req.body || {};
  const pinStr = String(pin || "").trim();
  if (!/^\d{4}$/.test(pinStr)) return res.status(400).json({ error: "PIN_MUST_BE_4_DIGITS" });

  const data = loadData();
  const ids = Object.keys(data.pins || {});
  if (ids.length === 0) return res.status(400).json({ error: "NO_PIN_SET" });

  let matchedPinId = null;
  for (const id of ids) {
    const ok = await bcrypt.compare(pinStr, data.pins[id].hash);
    if (ok) { matchedPinId = id; break; }
  }
  if (!matchedPinId) return res.status(401).json({ error: "BAD_PIN" });

  const token = createSession(data, matchedPinId);

  try {
    saveData(data);
    setSessionCookie(req, res, token);

    // ✅ On renvoie AUSSI le token (fallback si cookies bloqués)
    res.json({ success: true, loggedIn: true, token });
  } catch (e) {
    console.error("❌ login save failed:", e);
    res.status(500).json({ error: "LOGIN_SAVE_FAILED" });
  }
});

app.post("/api/pin/logout", (req, res) => {
  const data = loadData();

  const cookies = parseCookies(req);
  const cookieToken = cookies[SESSION_COOKIE];
  const bearer = getBearerToken(req);

  const token = bearer || cookieToken;
  if (token && data.sessions?.[token]) delete data.sessions[token];

  try { saveData(data); } catch (e) { console.error("❌ logout save failed:", e); }

  clearSessionCookie(req, res);
  res.json({ success: true, loggedOut: true });
});

app.get("/api/pin/me", (req, res) => {
  const data = loadData();
  const sess = getSession(data, req);
  res.json({ authenticated: !!sess });
});

// =====================================================
// 404 API + ERROR
// =====================================================
app.use("/api", (req, res) => res.status(404).json({ error: "API_NOT_FOUND" }));

app.use((err, req, res, next) => {
  console.error("❌ SERVER ERROR:", err);
  res.status(500).json({ error: "Internal Server Error" });
});

// =====================================================
// START
// =====================================================
app.listen(PORT, () => {
  console.log(`✅ Backend AGRENAD listening on port ${PORT}`);
});
