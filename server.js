// server.js
const express = require("express");
const cors = require("cors");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const bcrypt = require("bcryptjs");

const app = express();
app.set("trust proxy", 1);
const PORT = process.env.PORT || 3000;

// ====================== CONFIG ======================
const FRONT_ORIGINS = [
  "http://localhost:5173",
  "http://localhost:5500",
  "http://127.0.0.1:5500",
  "http://localhost:3000",
  "http://127.0.0.1:3000",
  // Ajoute ton URL Netlify si tu veux verrouiller :
  // "https://ton-site.netlify.app"
];

// En prod, si tu veux zéro prise de tête CORS :
const CORS_ALLOW_ALL = true;

// Fichier de données
const DATA_FILE = path.join(__dirname, "commandes.json");

// Secret setup (Render env var)
const SETUP_SECRET = process.env.SETUP_SECRET || "";

// 2 PIN max (cheffe + toi)
const MAX_PINS = 2;

// Cookie session
const SESSION_COOKIE = "agrenad_session";
const SESSION_TTL_MS = 1000 * 60 * 60 * 8; // 8h

// ====================== MIDDLEWARES ======================
app.use(
  cors({
    origin: CORS_ALLOW_ALL ? true : FRONT_ORIGINS,
    credentials: true,
  })
);

app.use(express.json({ limit: "1mb" }));

function parseCookies(req) {
  const header = req.headers.cookie || "";
  const cookies = {};
  header.split(";").forEach((part) => {
    const [k, ...v] = part.trim().split("=");
    if (!k) return;
    cookies[k] = decodeURIComponent(v.join("=") || "");
  });
  return cookies;
}

// ====================== DATA LAYER ======================
function defaultData() {
  return {
    petitdej: null,
    bar: null,
    entretien: null,
    validated: null, // { validatedAt, commandes:{...} }
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
    console.error("❌ loadData() failed:", e);
    return defaultData();
  }
}

function saveData(data) {
  const now = Date.now();
  if (data.sessions) {
    for (const token of Object.keys(data.sessions)) {
      if (!data.sessions[token] || data.sessions[token].expiresAt <= now) {
        delete data.sessions[token];
      }
    }
  }
  fs.writeFileSync(DATA_FILE, JSON.stringify(data, null, 2), "utf8");
}

function ensureService(service) {
  return ["petitdej", "bar", "entretien"].includes(service);
}

function sanitizeNumberLike(v) {
  if (v === null || v === undefined) return "";
  if (typeof v === "number") return String(v);
  if (typeof v === "string") return v.trim();
  // objet / array => on ignore
  return "";
}

function normalizeDonnees(obj) {
  if (!obj || typeof obj !== "object") return {};
  const out = {};
  for (const k of Object.keys(obj)) {
    out[k] = sanitizeNumberLike(obj[k]);
  }
  return out;
}

/**
 * ✅ IMPORTANT :
 * Le front peut envoyer :
 * - { donnees: { ... } }
 * - { donnees: { donnees: { ... } } }
 * - directement { ... }
 */
function extractPayload(reqBody) {
  if (!reqBody || typeof reqBody !== "object") return {};

  // format: { donnees: { donnees: {...}} }
  if (reqBody.donnees && typeof reqBody.donnees === "object") {
    if (reqBody.donnees.donnees && typeof reqBody.donnees.donnees === "object") {
      return normalizeDonnees(reqBody.donnees.donnees);
    }
    // format: { donnees: {...} }
    return normalizeDonnees(reqBody.donnees);
  }

  // format: {...}
  return normalizeDonnees(reqBody);
}

// ====================== AUTH HELPERS ======================
function createSession(data, pinId) {
  const token = crypto.randomBytes(24).toString("hex");
  data.sessions[token] = {
    pinId,
    expiresAt: Date.now() + SESSION_TTL_MS,
  };
  return token;
}

function getTokenFromReq(req) {
 
  // 2) Cookie
  const cookies = parseCookies(req);
  if (cookies[SESSION_COOKIE]) return cookies[SESSION_COOKIE];

  return null;
}

function requireKitchenAuth(req, res, next) {
  const data = loadData();

  const cookies = parseCookies(req);
  const token = cookies[SESSION_COOKIE];
  if (!token) {
    return res.status(401).json({ error: "UNAUTHORIZED" });
  }

  const sess = data.sessions?.[token];
  if (!sess || sess.expiresAt <= Date.now()) {
    return res.status(401).json({ error: "UNAUTHORIZED" });
  }

  // ✅ refresh TTL ICI (et seulement ici)
  sess.expiresAt = Date.now() + SESSION_TTL_MS;
  saveData(data);

  next();
}
// ====================== ROUTES: HEALTH ======================
app.get("/", (req, res) => res.send("AGRENAD backend OK"));
app.get("/api/hello", (req, res) => res.json({ ok: true, message: "hello" }));

// ====================== ROUTES: COMMANDES ======================

// GET toutes les commandes (recap)
app.get("/api/commandes", (req, res) => {
  const data = loadData();
  res.json({
    petitdej: data.petitdej,
    bar: data.bar,
    entretien: data.entretien,
  });
});

// GET par service
app.get("/api/commandes/:service", (req, res) => {
  const service = req.params.service;
  if (!ensureService(service)) return res.status(400).json({ error: "Service inconnu" });
  const data = loadData();
  res.json(data[service] || null);
});

// POST depuis pages services (libre)
app.post("/api/commandes/:service", (req, res) => {
  const service = req.params.service;
  if (!ensureService(service)) return res.status(400).json({ error: "Service inconnu" });

  const payload = extractPayload(req.body);

  const data = loadData();
  data[service] = {
    donnees: payload, // ✅ plat
    updatedAt: new Date().toISOString(),
  };

  try {
    saveData(data);
    res.json({ success: true, service, updatedAt: data[service].updatedAt });
  } catch (e) {
    console.error("❌ saveData failed (POST /api/commandes/:service):", e);
    res.status(500).json({ error: "SAVE_FAILED" });
  }
});

// PUT depuis recap (protégé PIN)
app.put("/api/commandes/:service", requireKitchenAuth, (req, res) => {
  const service = req.params.service;
  if (!ensureService(service)) return res.status(400).json({ error: "Service inconnu" });

  const payload = extractPayload(req.body);

  const data = loadData();
  data[service] = {
    donnees: payload,
    updatedAt: new Date().toISOString(),
  };

  try {
    saveData(data);
    res.json({ success: true, service, updatedAt: data[service].updatedAt });
  } catch (e) {
    console.error("❌ saveData failed (PUT /api/commandes/:service):", e);
    res.status(500).json({ error: "SAVE_FAILED" });
  }
});

// Reset un service
app.post("/api/reset/:service", requireKitchenAuth, (req, res) => {
  const service = req.params.service;
  if (!ensureService(service)) return res.status(400).json({ error: "Service inconnu" });

  const data = loadData();
  data[service] = null;

  try {
    saveData(data);
    res.json({ success: true, service, reset: true });
  } catch (e) {
    console.error("❌ saveData failed (POST /api/reset/:service):", e);
    res.status(500).json({ error: "RESET_FAILED" });
  }
});

// fallback reset (si ton front teste /api/commandes/:service/reset)
app.post("/api/commandes/:service/reset", requireKitchenAuth, (req, res) => {
  const service = req.params.service;
  if (!ensureService(service)) return res.status(400).json({ error: "Service inconnu" });

  const data = loadData();
  data[service] = null;

  try {
    saveData(data);
    res.json({ success: true, service, reset: true });
  } catch (e) {
    console.error("❌ saveData failed (POST /api/commandes/:service/reset):", e);
    res.status(500).json({ error: "RESET_FAILED" });
  }
});

// Reset tout (commandes + validated)
app.post("/api/reset-all", requireKitchenAuth, (req, res) => {
  const data = loadData();
  data.petitdej = null;
  data.bar = null;
  data.entretien = null;
  data.validated = null;

  try {
    saveData();
    res.json({ success: true, resetAll: true });
  } catch (e) {
    console.error("❌ saveData failed (POST /api/reset-all):", e);
    res.status(500).json({ error: "RESET_ALL_FAILED" });
  }
});

// ====================== VALIDATION WORKFLOW ======================

// POST valider (snapshot) - protégé PIN
app.post("/api/validate", requireKitchenAuth, (req, res) => {
  const data = loadData();

  data.validated = {
    validatedAt: new Date().toISOString(),
    commandes: {
      petitdej: data.petitdej,
      bar: data.bar,
      entretien: data.entretien,
    },
  };

  try {
    saveData();
    res.json({ success: true, validatedAt: data.validated.validatedAt });
  } catch (e) {
    console.error("❌ saveData failed (POST /api/validate):", e);
    res.status(500).json({ error: "VALIDATE_FAILED" });
  }
});

// GET snapshot validé (pour courses.html)
// ✅ jamais null pour éviter crash JS
app.get("/api/validated", (req, res) => {
  const data = loadData();
  if (!data.validated) {
    return res.json({ validatedAt: null, commandes: {} });
  }
  res.json(data.validated);
});

// Reset snapshot validé - protégé PIN
app.post("/api/validated/reset", requireKitchenAuth, (req, res) => {
  const data = loadData();
  data.validated = null;

  try {
    saveData(data);
    res.json({ success: true, resetValidated: true });
  } catch (e) {
    console.error("❌ saveData failed (POST /api/validated/reset):", e);
    res.status(500).json({ error: "RESET_VALIDATED_FAILED" });
  }
});

// ====================== PIN / AUTH ======================

// Statut PIN (setup.html)
app.get("/api/pin/status", (req, res) => {
  const data = loadData();
  const count = Object.keys(data.pins || {}).length;

  res.json({
    pinsCount: count,
    maxPins: MAX_PINS,
    setupEnabled: !!SETUP_SECRET,
    // utile côté front :
    setupLocked: count >= MAX_PINS,
  });
});

// Setup PIN : créer un PIN (max 2) - nécessite SETUP_SECRET
app.post("/api/pin/setup", async (req, res) => {
  if (!SETUP_SECRET) return res.status(400).json({ error: "SETUP_SECRET_NOT_CONFIGURED" });

  const { setupSecret, pin } = req.body || {};
  if (!setupSecret || setupSecret !== SETUP_SECRET) {
    return res.status(401).json({ error: "BAD_SETUP_SECRET" });
  }

  const pinStr = String(pin || "").trim();
  if (!/^\d{4}$/.test(pinStr)) {
    return res.status(400).json({ error: "PIN_MUST_BE_4_DIGITS" });
  }

  const data = loadData();
  const ids = Object.keys(data.pins || {});
  if (ids.length >= MAX_PINS) {
    return res.status(400).json({ error: "MAX_PINS_REACHED" });
  }

  // Empêche doublon exact
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
    console.error("❌ saveData failed (POST /api/pin/setup):", e);
    res.status(500).json({ error: "PIN_SETUP_SAVE_FAILED" });
  }
});

// Login PIN
app.post("/api/pin/login", async (req, res) => {
  const { pin } = req.body || {};
  const pinStr = String(pin || "").trim();
  if (!/^\d{4}$/.test(pinStr)) {
    return res.status(400).json({ error: "PIN_MUST_BE_4_DIGITS" });
  }

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

  const maxAge = Math.floor(SESSION_TTL_MS / 1000);

  res.setHeader(
    "Set-Cookie",
    `${SESSION_COOKIE}=${encodeURIComponent(token)}; Path=/; HttpOnly; SameSite=None; Secure; Max-Age=${maxAge}`
  );

  return res.json({ success: true, loggedIn: true });
} catch (e) {
  console.error("❌ saveData failed (POST /api/pin/login):", e);
  return res.status(500).json({ error: "LOGIN_SAVE_FAILED" });
}
});

// Logout
app.post("/api/pin/logout", (req, res) => {
  const data = loadData();
  const token = getTokenFromReq(req);

  if (token && data.sessions?.[token]) {
    delete data.sessions[token];
  }

  try { saveData(data); } catch (e) { console.error("❌ logout save failed:", e); }

  res.setHeader("Set-Cookie", `${SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0`);
  res.json({ success: true, loggedOut: true });
});

// Me
app.get("/api/pin/me", (req, res) => {
  const data = loadData();



  const sess = getSession(data, req);
  res.json({ authenticated: !!sess });
});

// ====================== 404 API ======================
app.use("/api", (req, res) => { res.status(404).json({ error: "API_NOT_FOUND" });
});

// ====================== ERROR HANDLER ======================
app.use((err, req, res, next) => {
  console.error("❌ SERVER ERROR:", err);
  res.status(500).json({ error: "Internal Server Error" });
});

// ====================== START ======================
app.listen(PORT, () => {
  console.log(`✅ Backend AGRENAD dispo sur http://localhost:${PORT}`);
});
