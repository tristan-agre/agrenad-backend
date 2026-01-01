// server.js
const express = require("express");
const cors = require("cors");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const bcrypt = require("bcryptjs");

const app = express();
const PORT = process.env.PORT || 3000;

// ====================== CONFIG ======================
const FRONT_ORIGINS = [
  "http://localhost:5173",
  "http://localhost:5500",
  "http://127.0.0.1:5500",
  "http://localhost:3000",
  "http://127.0.0.1:3000",
  // Ajoute ici ton URL Netlify si tu veux verrouiller CORS :
  // "https://ton-site.netlify.app"
];

// En prod, tu peux laisser "*" si tu veux éviter les soucis CORS,
// mais c'est moins "propre" :
const CORS_ALLOW_ALL = true;

// Fichier de données
const DATA_FILE = path.join(__dirname, "commandes.json");

// Secret setup (OBLIGATOIRE si tu utilises setup PIN)
// Mets-le en variable d'environnement sur Render : SETUP_SECRET
const SETUP_SECRET = process.env.SETUP_SECRET || "";

// "Bague d'or" : second PIN autorisé (tu le crées via setup)
const MAX_PINS = 2;

// Cookie de session (simple)
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

// Parse cookies simple (sans dépendance)
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
    validated: null, // snapshot validé
    pins: {}, // { pinId: { hash, createdAt } } max 2
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
  // Nettoyage de sessions expirées
  const now = Date.now();
  if (data.sessions) {
    for (const token of Object.keys(data.sessions)) {
      if (!data.sessions[token] || data.sessions[token].expiresAt <= now) {
        delete data.sessions[token];
      }
    }
  }

  // Ecriture
  fs.writeFileSync(DATA_FILE, JSON.stringify(data, null, 2), "utf8");
}

function sanitizeNumberLike(v) {
  // ton front envoie souvent des strings "14"
  if (v === null || v === undefined) return "";
  if (typeof v === "number") return String(v);
  if (typeof v === "string") return v.trim();
  return "";
}

function normalizeDonnees(obj) {
  // On force un objet plat { produit: "valeur" }
  if (!obj || typeof obj !== "object") return {};
  const out = {};
  for (const k of Object.keys(obj)) {
    out[k] = sanitizeNumberLike(obj[k]);
  }
  return out;
}

function ensureService(service) {
  return ["petitdej", "bar", "entretien"].includes(service);
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

function getSession(data, req) {
  const cookies = parseCookies(req);
  const token = cookies[SESSION_COOKIE];
  if (!token) return null;
  const sess = data.sessions?.[token];
  if (!sess) return null;
  if (sess.expiresAt <= Date.now()) return null;
  return { token, ...sess };
}

function requireKitchenAuth(req, res, next) {
  const data = loadData();
  const sess = getSession(data, req);
  if (!sess) {
    return res.status(401).json({ error: "UNAUTHORIZED" });
  }
  // refresh TTL
  data.sessions[sess.token].expiresAt = Date.now() + SESSION_TTL_MS;
  saveData(data);
  next();
}

// ====================== ROUTES: HEALTH ======================
app.get("/", (req, res) => {
  res.send("AGRENAD backend OK");
});

app.get("/api/hello", (req, res) => {
  res.json({ ok: true, message: "hello" });
});

// ====================== ROUTES: COMMANDES ======================

// Récupérer toutes les commandes (pour recap global)
app.get("/api/commandes", (req, res) => {
  const data = loadData();
  res.json({
    petitdej: data.petitdej,
    bar: data.bar,
    entretien: data.entretien,
  });
});

// Récupérer une commande par service
app.get("/api/commandes/:service", (req, res) => {
  const service = req.params.service;
  if (!ensureService(service)) return res.status(400).json({ error: "Service inconnu" });

  const data = loadData();
  res.json(data[service] || null);
});

// Enregistrer une commande service (depuis pages petitdej/bar/entretien)
app.post("/api/commandes/:service", (req, res) => {
  const service = req.params.service;
  if (!ensureService(service)) return res.status(400).json({ error: "Service inconnu" });

  if (!req.body || typeof req.body !== "object") {
    return res.status(400).json({ error: "Body JSON manquant" });
  }

  const payload = normalizeDonnees(req.body);

  const data = loadData();
  data[service] = {
    donnees: payload,
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

// Reset un service
app.post("/api/reset/:service", (req, res) => {
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

// Reset tout (commandes + validated)
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
    console.error("❌ saveData failed (POST /api/reset-all):", e);
    res.status(500).json({ error: "RESET_ALL_FAILED" });
  }
});

// ====================== VALIDATION WORKFLOW ======================
// Valider les commandes (snapshot) - protégé PIN
app.post("/api/validate", requireKitchenAuth, (req, res) => {
  const data = loadData();

  data.validated = {
    petitdej: data.petitdej,
    bar: data.bar,
    entretien: data.entretien,
    validatedAt: new Date().toISOString(),
  };

  try {
    saveData(data);
    res.json({ success: true, validatedAt: data.validated.validatedAt });
  } catch (e) {
    console.error("❌ saveData failed (POST /api/validate):", e);
    res.status(500).json({ error: "VALIDATE_FAILED" });
  }
});

// Récupérer le snapshot validé (pour courses.html)
app.get("/api/validated", (req, res) => {
  const data = loadData();
  res.json(data.validated || null);
});

// Reset snapshot validé (après les courses) - protégé PIN
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

// Statut PIN (utile pour setup.html)
app.get("/api/pin/status", (req, res) => {
  const data = loadData();
  const count = Object.keys(data.pins || {}).length;
  res.json({
    pinsCount: count,
    maxPins: MAX_PINS,
    setupEnabled: !!SETUP_SECRET,
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

// Login PIN (pour accéder à recap/validation)
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
    if (ok) {
      matchedPinId = id;
      break;
    }
  }

  if (!matchedPinId) return res.status(401).json({ error: "BAD_PIN" });

  const token = createSession(data, matchedPinId);

  try {
    saveData(data);

    // Cookie httpOnly (sur Netlify/Render, SameSite Lax fonctionne bien en général)
    res.setHeader(
      "Set-Cookie",
      `${SESSION_COOKIE}=${encodeURIComponent(token)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${Math.floor(
        SESSION_TTL_MS / 1000
      )}`
    );

    res.json({ success: true, loggedIn: true });
  } catch (e) {
    console.error("❌ saveData failed (POST /api/pin/login):", e);
    res.status(500).json({ error: "LOGIN_SAVE_FAILED" });
  }
});

// Logout
app.post("/api/pin/logout", (req, res) => {
  const data = loadData();
  const cookies = parseCookies(req);
  const token = cookies[SESSION_COOKIE];

  if (token && data.sessions?.[token]) {
    delete data.sessions[token];
  }

  try {
    saveData(data);
  } catch (e) {
    console.error("❌ saveData failed (POST /api/pin/logout):", e);
  }

  // Expire cookie
  res.setHeader(
    "Set-Cookie",
    `${SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0`
  );

  res.json({ success: true, loggedOut: true });
});

// Me (statut session)
app.get("/api/pin/me", (req, res) => {
  const data = loadData();
  const sess = getSession(data, req);
  res.json({ authenticated: !!sess });
});

// ====================== 404 API ======================
app.use("/api", (req, res) => {
  res.status(404).json({ error: "API_NOT_FOUND" });
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
