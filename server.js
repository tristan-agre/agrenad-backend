// server.js
"use strict";

const express = require("express");
const cors = require("cors");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const app = express();
const PORT = process.env.PORT || 3000;

// =====================================================
// CONFIG
// =====================================================
app.set("trust proxy", 1);

const DATA_FILE = path.join(__dirname, "commandes.json");
const SERVICES = ["petitdej", "bar", "entretien"];
const SCOPES = ["petitdej", "bar", "entretien", "recap", "admin"];

const SESSION_TTL_MS = 1000 * 60 * 60 * 8; // 8h
const SESSION_COOKIE = "agrenad_token";

const PIN_SALT = String(process.env.PIN_SALT || "CHANGE_ME_SALT").trim();
const MASTER_PIN = String(process.env.MASTER_PIN || "9999").trim();

const FRONT_ORIGINS = [
  "http://localhost:5500",
  "http://127.0.0.1:5500",
  "http://localhost:3000",
  "http://127.0.0.1:3000",
  "https://commandeagrenad.netlify.app",
];

// =====================================================
// MIDDLEWARES
// =====================================================
app.use(express.json({ limit: "1mb" }));

app.use(
  cors({
    origin: (origin, cb) => {
      if (!origin) return cb(null, true);
      if (FRONT_ORIGINS.includes(origin)) return cb(null, true);
      return cb(new Error(`CORS blocked for origin: ${origin}`));
    },
    credentials: true,
  })
);

app.options("*", cors());
app.disable("etag");

app.use("/api", (req, res, next) => {
  res.setHeader("Cache-Control", "no-store");
  next();
});

// =====================================================
// DATA LAYER
// =====================================================
function defaultData() {
  return {
    petitdej: null,
    bar: null,
    entretien: null,
    courses: null,
    validated: null,
    pins: {},
  };
}

function loadData() {
  try {
    if (!fs.existsSync(DATA_FILE)) return defaultData();
    const raw = fs.readFileSync(DATA_FILE, "utf8");
    if (!raw || raw.trim() === "") return defaultData();

    const d = JSON.parse(raw);
    return {
      petitdej:  d.petitdej  ?? null,
      bar:       d.bar       ?? null,
      entretien: d.entretien ?? null,
      courses:   d.courses   ?? null,
      validated: d.validated ?? null,
      pins:      d.pins      ?? {},
    };
  } catch (e) {
    console.error("❌ loadData failed:", e);
    return defaultData();
  }
}

function saveData(data) {
  fs.writeFileSync(DATA_FILE, JSON.stringify(data, null, 2), "utf8");
}

function ensureService(service) {
  return SERVICES.includes(service);
}

function sanitizeDonnees(obj) {
  const out = {};
  if (!obj || typeof obj !== "object") return out;
  for (const [key, value] of Object.entries(obj)) {
    if (value === null || value === undefined) continue;
    out[key] = String(value).trim();
  }
  return out;
}

// =====================================================
// AUTH
// =====================================================
const sessions = new Map();

function isHttpsRequest(req) {
  const xfProto = (req.headers["x-forwarded-proto"] || "").toString().toLowerCase();
  if (xfProto.includes("https")) return true;
  if (req.secure) return true;
  return false;
}

function createToken() {
  return crypto.randomBytes(24).toString("hex");
}

function getBearerToken(req) {
  const h = req.headers.authorization || "";
  const m = /^Bearer\s+(.+)$/i.exec(h);
  return m ? m[1] : "";
}

function getCookieToken(req) {
  const cookie = req.headers.cookie || "";
  const m = cookie.match(new RegExp(`${SESSION_COOKIE}=([^;]+)`));
  return m ? decodeURIComponent(m[1]) : "";
}

function setSessionCookie(req, res, token) {
  const https = isHttpsRequest(req);
  const sameSite = https ? "None" : "Lax";
  const securePart = https ? " Secure;" : "";
  res.setHeader(
    "Set-Cookie",
    `${SESSION_COOKIE}=${encodeURIComponent(token)}; Path=/; HttpOnly; SameSite=${sameSite};${securePart} Max-Age=${Math.floor(SESSION_TTL_MS / 1000)}`
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

function hashPin(pin) {
  return crypto.createHash("sha256").update(`${pin}:${PIN_SALT}`).digest("hex");
}

function authMiddleware(req, res, next) {
  const token = getBearerToken(req) || getCookieToken(req);
  if (!token) return res.status(401).json({ error: "UNAUTHORIZED" });

  const sess = sessions.get(token);
  if (!sess) return res.status(401).json({ error: "UNAUTHORIZED" });

  if (sess.expiresAt <= Date.now()) {
    sessions.delete(token);
    return res.status(401).json({ error: "SESSION_EXPIRED" });
  }

  sess.expiresAt = Date.now() + SESSION_TTL_MS;
  req.user = { scope: sess.scope, token };
  next();
}

function requireScope(...allowed) {
  return (req, res, next) => {
    const scope = req.user?.scope;
    if (!scope) return res.status(401).json({ error: "UNAUTHORIZED" });
    if (scope === "admin") return next();
    if (!allowed.includes(scope)) return res.status(403).json({ error: "FORBIDDEN", scope, allowed });
    next();
  };
}

// =====================================================
// ROUTES
// =====================================================
app.get("/", (req, res) => res.send("AGRENAD backend OK"));
app.get("/api/hello", (req, res) => res.json({ ok: true, message: "hello" }));

// ---------- AUTH ----------
app.post("/api/auth/login", (req, res) => {
  const pin = String(req.body?.pin || "").trim();
  const wantCookie = Boolean(req.body?.setCookie);

  if (!/^\d{4}$/.test(pin)) return res.status(400).json({ error: "PIN_INVALID" });

  if (pin === MASTER_PIN) {
    const token = createToken();
    sessions.set(token, { scope: "admin", expiresAt: Date.now() + SESSION_TTL_MS });
    if (wantCookie) setSessionCookie(req, res, token);
    return res.json({ ok: true, token, scope: "admin" });
  }

  const data = loadData();
  const pinHash = hashPin(pin);

  let scope = null;
  for (const s of ["petitdej", "bar", "entretien", "recap"]) {
    if (data.pins?.[s]?.hash && data.pins[s].hash === pinHash) {
      scope = s;
      break;
    }
  }

  if (!scope) return res.status(401).json({ error: "BAD_PIN" });

  const token = createToken();
  sessions.set(token, { scope, expiresAt: Date.now() + SESSION_TTL_MS });
  if (wantCookie) setSessionCookie(req, res, token);

  res.json({ ok: true, token, scope });
});

app.get("/api/auth/me", authMiddleware, (req, res) => {
  res.json({ authenticated: true, scope: req.user.scope });
});

app.post("/api/auth/logout", authMiddleware, (req, res) => {
  sessions.delete(req.user.token);
  clearSessionCookie(req, res);
  res.json({ ok: true });
});

// ---------- ADMIN PIN MANAGEMENT ----------
app.get("/api/admin/pins", authMiddleware, requireScope("admin"), (req, res) => {
  const data = loadData();
  const out = {};
  for (const s of ["petitdej", "bar", "entretien", "recap"]) {
    out[s] = data.pins?.[s]?.updatedAt ? { updatedAt: data.pins[s].updatedAt } : null;
  }
  res.json({ ok: true, pins: out });
});

app.post("/api/admin/pins", authMiddleware, requireScope("admin"), (req, res) => {
  const scope = String(req.body?.scope || "").trim();
  const pin   = String(req.body?.pin   || "").trim();

  if (!["petitdej", "bar", "entretien", "recap"].includes(scope)) {
    return res.status(400).json({ error: "SCOPE_INVALID" });
  }
  if (!/^\d{4}$/.test(pin)) return res.status(400).json({ error: "PIN_INVALID" });

  const data = loadData();
  data.pins = data.pins || {};
  data.pins[scope] = {
    hash: hashPin(pin),
    updatedAt: new Date().toISOString(),
  };

  saveData(data);
  res.json({ ok: true, scope, updatedAt: data.pins[scope].updatedAt });
});

// ---------- COMMANDES (routes dédiées par service) ----------
function getCommande(service) {
  const data = loadData();
  return data[service] ?? null;
}

function setCommande(service, body) {
  const donnees = sanitizeDonnees(body);
  const data = loadData();
  data[service] = {
    donnees,
    updatedAt: new Date().toISOString(),
  };
  saveData(data);
  return { success: true, service, updatedAt: data[service].updatedAt };
}

// Routes dédiées par service
for (const s of SERVICES) {
  app.get(`/api/commandes/${s}`, authMiddleware, requireScope(s, "recap"), (req, res) => {
    res.json(getCommande(s));
  });

  app.post(`/api/commandes/${s}`, authMiddleware, requireScope(s, "recap"), (req, res) => {
    try {
      res.json(setCommande(s, req.body));
    } catch (e) {
      console.error("❌ save commande failed:", e);
      res.status(500).json({ error: "SAVE_FAILED" });
    }
  });
}

// Route recap (toutes les commandes d'un coup)
app.get("/api/commandes/recap", authMiddleware, requireScope("recap"), (req, res) => {
  const data = loadData();
  res.json({
    petitdej:  data.petitdej,
    bar:       data.bar,
    entretien: data.entretien,
  });
});

// Route compat globale
app.get("/api/commandes", authMiddleware, requireScope("recap"), (req, res) => {
  const data = loadData();
  res.json({
    petitdej:  data.petitdej,
    bar:       data.bar,
    entretien: data.entretien,
  });
});

// Route générique POST (fallback)
app.post("/api/commandes/:service", authMiddleware, (req, res) => {
  const service = req.params.service;
  if (!ensureService(service)) return res.status(400).json({ error: "Service inconnu" });

  const scope = req.user?.scope;
  if (scope !== "admin" && scope !== "recap" && scope !== service) {
    return res.status(403).json({ error: "FORBIDDEN" });
  }

  try {
    res.json(setCommande(service, req.body));
  } catch (e) {
    console.error("❌ save commande failed:", e);
    res.status(500).json({ error: "SAVE_FAILED" });
  }
});

// ---------- VALIDATION PAR SERVICE ----------
app.post("/api/validate/:service", authMiddleware, (req, res) => {
  const service = req.params.service;
  if (!ensureService(service)) return res.status(400).json({ error: "Service inconnu" });

  const scope = req.user?.scope;
  if (scope !== "admin" && scope !== "recap" && scope !== service) {
    return res.status(403).json({ error: "FORBIDDEN", scope, allowed: ["admin", "recap", service] });
  }

  const data = loadData();
  data.validated = data.validated || {};
  data.validated[service] = {
    validatedAt: new Date().toISOString(),
    payload: data[service] || null,
  };

  try {
    saveData(data);
    res.json({ success: true, service, validatedAt: data.validated[service].validatedAt });
  } catch (e) {
    console.error("❌ validate failed:", e);
    res.status(500).json({ error: "VALIDATE_FAILED" });
  }
});

// ---------- VALIDATION GLOBALE (tous les services) ----------
app.post("/api/validate", authMiddleware, requireScope("recap"), (req, res) => {
  try {
    const data = loadData();
    data.validated = data.validated || {};
    const now = new Date().toISOString();
    for (const s of SERVICES) {
      data.validated[s] = {
        validatedAt: now,
        payload: data[s] || null,
      };
    }
    saveData(data);
    res.json({ ok: true, validatedAt: now });
  } catch (e) {
    console.error("❌ validate-all failed:", e);
    res.status(500).json({ error: "VALIDATE_FAILED" });
  }
});

// ---------- COURSES ----------
app.get("/api/courses", authMiddleware, requireScope("recap"), (req, res) => {
  const data = loadData();
  res.json(data.courses ?? { donnees: {}, updatedAt: null });
});

app.post("/api/courses", authMiddleware, requireScope("recap"), (req, res) => {
  try {
    const data = loadData();
    data.courses = {
      donnees: sanitizeDonnees(req.body),
      updatedAt: new Date().toISOString(),
    };
    saveData(data);
    res.json({ ok: true, updatedAt: data.courses.updatedAt });
  } catch (e) {
    console.error("❌ save courses failed:", e);
    res.status(500).json({ error: "SAVE_FAILED" });
  }
});

app.post("/api/courses/validate", authMiddleware, requireScope("recap"), (req, res) => {
  try {
    const data = loadData();
    data.courses = data.courses || { donnees: {}, updatedAt: null };
    data.courses.validatedAt = new Date().toISOString();
    saveData(data);
    res.json({ ok: true, validatedAt: data.courses.validatedAt });
  } catch (e) {
    console.error("❌ validate courses failed:", e);
    res.status(500).json({ error: "VALIDATE_FAILED" });
  }
});

// ---------- RESET ALL ----------
app.post("/api/reset-all", authMiddleware, requireScope("recap"), (req, res) => {
  try {
    const data = loadData();
    data.petitdej  = null;
    data.bar       = null;
    data.entretien = null;
    data.courses   = null;
    data.validated = null;
    saveData(data);
    res.json({ ok: true, resetAt: new Date().toISOString() });
  } catch (e) {
    console.error("❌ reset-all failed:", e);
    res.status(500).json({ error: "RESET_FAILED" });
  }
});

// ---------- RESET RECAP (courses uniquement) ----------
app.post("/api/recap/reset", authMiddleware, requireScope("recap"), (req, res) => {
  try {
    const data = loadData();
    data.courses = null;
    saveData(data);
    res.json({ ok: true, resetAt: new Date().toISOString() });
  } catch (e) {
    console.error("❌ recap/reset failed:", e);
    res.status(500).json({ error: "RESET_FAILED" });
  }
});

// =====================================================
// 404 API + ERROR — TOUJOURS EN DERNIER
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