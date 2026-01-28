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
app.set("trust proxy", 1); // Render / proxy

const DATA_FILE = path.join(__dirname, "commandes.json");
const SERVICES = ["petitdej", "bar", "entretien"]; 
function ensureService(service) {
  return SERVICES.includes(service);
}// scopes services
const SCOPES = ["petitdej", "bar", "entretien", "recap", "admin"];

const SESSION_TTL_MS = 1000 * 60 * 60 * 8; // 8h
const SESSION_COOKIE = "agrenad_token";

// IMPORTANT : mets un sel en env sur Render (et en local) : PIN_SALT
// sinon fallback (OK en dev, moins bien en prod)
const PIN_SALT = String(process.env.PIN_SALT || "CHANGE_ME_SALT").trim();

// MASTER PIN en env (obligatoire en prod)
const MASTER_PIN = String(process.env.MASTER_PIN || "9999").trim();

// Front origins autorisés (Netlify + local)
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
      if (!origin) return cb(null, true); // file:// / certains tests
      if (FRONT_ORIGINS.includes(origin)) return cb(null, true);
      return cb(new Error(`CORS blocked for origin: ${origin}`));
    },
    credentials: true,
  })
);

app.options("*", cors());
app.disable("etag");

// no-cache API (optionnel mais propre)
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
    validated: null,
    pins: {
      // exemple :
      // bar: { hash: "...", updatedAt: "..." }
      // recap: { hash: "...", updatedAt: "..." }
    },
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
    const v = String(value).trim();
    // on garde tout, y compris "0"
    out[key] = v;
  }
  return out;
}

// =====================================================
// AUTH - PIN HASH + SESSIONS (mémoire)
// =====================================================

// Sessions en mémoire : token -> { scope, expiresAt }
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

  // cookie simple, HttpOnly, 8h
  res.setHeader(
    "Set-Cookie",
    `${SESSION_COOKIE}=${encodeURIComponent(token)}; Path=/; HttpOnly; SameSite=${sameSite};${securePart} Max-Age=${Math.floor(
      SESSION_TTL_MS / 1000
    )}`
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
  // sha256(pin + salt)
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

  // sliding session
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
  const wantCookie = Boolean(req.body?.setCookie); // optionnel

  if (!/^\d{4}$/.test(pin)) return res.status(400).json({ error: "PIN_INVALID" });

  // MASTER PIN => admin
  if (pin === MASTER_PIN) {
    const token = createToken();
    sessions.set(token, { scope: "admin", expiresAt: Date.now() + SESSION_TTL_MS });
    if (wantCookie) setSessionCookie(req, res, token);
    return res.json({ ok: true, token, scope: "admin" });
  }

  // sinon on check pins persistés
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

// ---------- ADMIN PIN MANAGEMENT (MASTER/admin only) ----------
app.get("/api/admin/pins", authMiddleware, requireScope("admin"), (req, res) => {
  const data = loadData();
  // On ne renvoie pas les hash en clair si tu veux, mais ici on peut renvoyer juste timestamps
  const out = {};
  for (const s of ["petitdej", "bar", "entretien", "recap"]) {
    out[s] = data.pins?.[s]?.updatedAt ? { updatedAt: data.pins[s].updatedAt } : null;
  }
  res.json({ ok: true, pins: out });
});

app.post("/api/admin/pins", authMiddleware, requireScope("admin"), (req, res) => {
  const scope = String(req.body?.scope || "").trim();
  const pin = String(req.body?.pin || "").trim();

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

// GET /api/commandes/<service>
for (const s of SERVICES) {
  app.get(`/api/commandes/${s}`, authMiddleware, requireScope(s, "recap"), (req, res) => {
    res.json(getCommande(s));
  });

  app.post(`/api/commandes/${s}`, authMiddleware, requireScope(s, "recap"), (req, res) => {
    try {
      const out = setCommande(s, req.body);
      res.json(out);
    } catch (e) {
      console.error("❌ save commande failed:", e);
      res.status(500).json({ error: "SAVE_FAILED" });
    }
  });
}

// recap : accès recap + admin
app.get("/api/commandes/recap", authMiddleware, requireScope("recap"), (req, res) => {
  const data = loadData();
  res.json({
    petitdej: data.petitdej,
    bar: data.bar,
    entretien: data.entretien,
  });
});

// ---------- COMPAT (ancienne route si tu en as encore besoin) ----------
app.get("/api/commandes", authMiddleware, requireScope("recap"), (req, res) => {
  const data = loadData();
  res.json({
    petitdej: data.petitdej,
    bar: data.bar,
    entretien: data.entretien,
  });
});

app.post("/api/commandes/:service", authMiddleware, (req, res) => {
  const service = req.params.service;
  if (!ensureService(service)) return res.status(400).json({ error: "Service inconnu" });

  // scope service ou recap/admin
  const scope = req.user?.scope;
  if (scope !== "admin" && scope !== "recap" && scope !== service) {
    return res.status(403).json({ error: "FORBIDDEN" });
  }

  try {
    const out = setCommande(service, req.body);
    res.json(out);
  } catch (e) {
    console.error("❌ save commande failed:", e);
    res.status(500).json({ error: "SAVE_FAILED" });
  }
});
// ---------- VALIDATION ----------
// Permet de valider un service (petitdej / bar / entretien)
// Autorisé : admin OU le scope du service OU recap (si tu veux que recap valide tout)
app.post("/api/validate/:service", authMiddleware, (req, res) => {
  const service = req.params.service;
  if (!ensureService(service)) return res.status(400).json({ error: "Service inconnu" });

  // scopes autorisés
  const scope = req.user?.scope;
  const allowed = (scope === "admin" || scope === "recap" || scope === service);
  if (!allowed) return res.status(403).json({ error: "FORBIDDEN", scope, allowed: ["admin", "recap", service] });

  const data = loadData();

  // snapshot validé (tu peux l’exploiter dans recap)
  data.validated = data.validated || {};
  data.validated[service] = {
    validatedAt: new Date().toISOString(),
    payload: data[service] || null
  };

  try {
    saveData(data);
    res.json({ success: true, service, validatedAt: data.validated[service].validatedAt });
  } catch (e) {
    console.error("❌ validate failed:", e);
    res.status(500).json({ error: "VALIDATE_FAILED" });
  }
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
