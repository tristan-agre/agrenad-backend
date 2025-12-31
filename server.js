const express = require("express");
const cors = require("cors");
const fs = require("fs");
const path = require("path");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();
app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 3000;

// === ENV VARS (Render) ===
const SETUP_SECRET = process.env.SETUP_SECRET || "";
const JWT_SECRET = process.env.JWT_SECRET || "dev_jwt_change_me";

// === FILES ===
const DATA_DIR = __dirname;
const COMMANDES_FILE = path.join(DATA_DIR, "commandes.json");
const VALIDATED_FILE = path.join(DATA_DIR, "validated.json");
const PINS_FILE = path.join(DATA_DIR, "pins.json");
const AUDIT_FILE = path.join(DATA_DIR, "audit.json");

// Services actuels (tu gardes ton fonctionnement)
const SERVICES = ["petitdej", "bar", "entretien"];

// ---------- Utils JSON ----------
function readJsonSafe(file, fallback) {
  try {
    return JSON.parse(fs.readFileSync(file, "utf-8"));
  } catch {
    return fallback;
  }
}
function writeJson(file, data) {
  fs.writeFileSync(file, JSON.stringify(data, null, 2), "utf-8");
}
function nowISO() {
  return new Date().toISOString();
}
function audit(event, meta = {}) {
  const logs = readJsonSafe(AUDIT_FILE, []);
  logs.push({ at: nowISO(), event, ...meta });
  writeJson(AUDIT_FILE, logs);
}

// ---------- Data init ----------
function ensureFiles() {
  const commandesDefault = {};
  for (const s of SERVICES) {
    commandesDefault[s] = { donnees: { donnees: {} }, updatedAt: null };
  }
  if (!fs.existsSync(COMMANDES_FILE)) writeJson(COMMANDES_FILE, commandesDefault);
  if (!fs.existsSync(VALIDATED_FILE)) writeJson(VALIDATED_FILE, { validatedAt: null, commandes: null });
  if (!fs.existsSync(PINS_FILE)) writeJson(PINS_FILE, { owner: null, chef: null });
  if (!fs.existsSync(AUDIT_FILE)) writeJson(AUDIT_FILE, []);
}
ensureFiles();

// ---------- PIN storage ----------
function loadPins() {
  return readJsonSafe(PINS_FILE, { owner: null, chef: null });
}
function savePins(pins) {
  writeJson(PINS_FILE, pins);
}

// ---------- Auth ----------
function requireAuth(roles = []) {
  return (req, res, next) => {
    const auth = req.headers.authorization || "";
    const token = auth.startsWith("Bearer ") ? auth.slice(7) : null;
    if (!token) return res.status(401).json({ error: "Non authentifié" });

    try {
      const payload = jwt.verify(token, JWT_SECRET);
      if (roles.length && !roles.includes(payload.role)) {
        return res.status(403).json({ error: "Accès refusé" });
      }
      req.user = payload;
      next();
    } catch {
      return res.status(401).json({ error: "Token invalide" });
    }
  };
}

// ---------- Health ----------
app.get("/api/hello", (req, res) => {
  res.json({ ok: true, msg: "API OK", at: nowISO() });
});

// =====================================================
// PIN API (2 PIN max, login sans choix de rôle)
// =====================================================

// Statut : est-ce que les 2 PIN existent ?
app.get("/api/pin/status", (req, res) => {
  const pins = loadPins();
  res.json({
    ownerExists: !!pins.owner,
    chefExists: !!pins.chef,
    setupLocked: !!pins.owner && !!pins.chef
  });
});

// Setup PIN (création) : nécessite SETUP_SECRET
// body: { setupSecret, role: "owner"|"chef", pin: "1234" }
app.post("/api/pin/setup", async (req, res) => {
  const { setupSecret, role, pin } = req.body || {};
  if (!SETUP_SECRET || setupSecret !== SETUP_SECRET) {
    return res.status(401).json({ error: "Setup secret invalide" });
  }
  if (!["owner", "chef"].includes(role)) {
    return res.status(400).json({ error: "Role invalide" });
  }
  if (!/^\d{4}$/.test(String(pin || ""))) {
    return res.status(400).json({ error: "PIN invalide (4 chiffres)" });
  }

  const pins = loadPins();
  if (pins.owner && pins.chef) {
    return res.status(403).json({ error: "Setup verrouillé (2 PIN déjà créés)" });
  }
  if (pins[role]) {
    return res.status(409).json({ error: "Ce rôle a déjà un PIN" });
  }

  const hash = await bcrypt.hash(String(pin), 10);
  pins[role] = { hash, createdAt: nowISO() };
  savePins(pins);

  audit("PIN_CREATED", { role, ip: req.ip, ua: req.headers["user-agent"] });
  res.json({ ok: true });
});

// Login : tu donnes juste un PIN, le serveur trouve si c’est OWNER ou CHEF.
// body: { pin: "1234" }
app.post("/api/pin/login", async (req, res) => {
  const { pin } = req.body || {};
  if (!/^\d{4}$/.test(String(pin || ""))) {
    return res.status(400).json({ error: "PIN invalide (4 chiffres)" });
  }

  const pins = loadPins();
  const pinStr = String(pin);

  let roleMatched = null;

  // On teste owner puis chef (ordre volontaire)
  if (pins.owner?.hash && await bcrypt.compare(pinStr, pins.owner.hash)) roleMatched = "owner";
  else if (pins.chef?.hash && await bcrypt.compare(pinStr, pins.chef.hash)) roleMatched = "chef";

  if (!roleMatched) {
    audit("PIN_LOGIN_FAIL", { ip: req.ip, ua: req.headers["user-agent"] });
    return res.status(401).json({ error: "PIN incorrect" });
  }

  const token = jwt.sign({ role: roleMatched }, JWT_SECRET, { expiresIn: "12h" });
  audit("PIN_LOGIN_OK", { role: roleMatched, ip: req.ip, ua: req.headers["user-agent"] });

  // On NE renvoie PAS le rôle au front (tu voulais que ce soit invisible)
  res.json({ ok: true, token });
});

// Owner reset le PIN chef (bague d’or)
// body: { newPin: "5678" }
app.post("/api/pin/reset-chef", requireAuth(["owner"]), async (req, res) => {
  const { newPin } = req.body || {};
  if (!/^\d{4}$/.test(String(newPin || ""))) {
    return res.status(400).json({ error: "PIN invalide (4 chiffres)" });
  }

  const pins = loadPins();
  if (!pins.chef) return res.status(404).json({ error: "PIN chef non créé" });

  pins.chef.hash = await bcrypt.hash(String(newPin), 10);
  pins.chef.resetAt = nowISO();
  savePins(pins);

  audit("PIN_CHEF_RESET_BY_OWNER", { ip: req.ip, ua: req.headers["user-agent"] });
  res.json({ ok: true });
});

// =====================================================
// COMMANDES API
// =====================================================

// Lire toutes les commandes (brouillon)
app.get("/api/commandes", (req, res) => {
  const data = readJsonSafe(COMMANDES_FILE, {});
  res.json(data);
});
// Enregistrer commande service (ADMIN) -> réservé chef/owner
app.put("/api/admin/commandes/:service", requireAuth(["owner", "chef"]), (req, res) => {
  const service = req.params.service;
  const payload = req.body || {};

  const data = readJsonSafe(COMMANDES_FILE, {});
  if (!data[service]) data[service] = { donnees: { donnees: {} }, updatedAt: null };

  const incoming = payload?.donnees?.donnees || payload?.donnees || {};
  const existing = data[service]?.donnees?.donnees || {};

  data[service].donnees = { donnees: { ...existing, ...incoming } };
  data[service].updatedAt = nowISO();

  writeJson(COMMANDES_FILE, data);
  audit("ADMIN_SAVE_SERVICE", { service, by: req.user.role, ip: req.ip });

  res.json({ ok: true, updatedAt: data[service].updatedAt });
});
// Lire une commande service
app.get("/api/commandes/:service", (req, res) => {
  const service = req.params.service;
  const data = readJsonSafe(COMMANDES_FILE, {});
  res.json(data[service] || { donnees: { donnees: {} }, updatedAt: null });
});

// Enregistrer commande service (brouillon)
// ICI on laisse ouvert (tout le monde peut enregistrer) OU tu peux fermer si tu veux
// -> toi tu veux que tout le monde puisse commander : donc OPEN.
app.put("/api/commandes/:service", (req, res) => {
  const service = req.params.service;
  const payload = req.body || {};

  const data = readJsonSafe(COMMANDES_FILE, {});
  if (!data[service]) data[service] = { donnees: { donnees: {} }, updatedAt: null };

  // merge propre
  const incoming = payload?.donnees?.donnees || payload?.donnees || {};
  const existing = data[service]?.donnees?.donnees || {};

  data[service].donnees = { donnees: { ...existing, ...incoming } };
  data[service].updatedAt = nowISO();

  writeJson(COMMANDES_FILE, data);
  res.json({ ok: true, updatedAt: data[service].updatedAt });
});

// Reset service (PROTÉGÉ PIN)
app.post("/api/reset/:service", requireAuth(["owner", "chef"]), (req, res) => {
  const service = req.params.service;
  const data = readJsonSafe(COMMANDES_FILE, {});
  if (!data[service]) data[service] = { donnees: { donnees: {} }, updatedAt: null };

  data[service].donnees = { donnees: {} };
  data[service].updatedAt = nowISO();

  writeJson(COMMANDES_FILE, data);
  audit("RESET_SERVICE", { service, by: req.user.role, ip: req.ip });

  res.json({ ok: true, service });
});

// Valider (snapshot) (PROTÉGÉ PIN)
app.post("/api/validate", requireAuth(["owner", "chef"]), (req, res) => {
  const data = readJsonSafe(COMMANDES_FILE, {});
  const snapshot = {
    validatedAt: nowISO(),
    commandes: data
  };
  writeJson(VALIDATED_FILE, snapshot);
  audit("VALIDATED", { by: req.user.role, ip: req.ip });

  res.json({ ok: true, validatedAt: snapshot.validatedAt });
});

// Lire le snapshot validé (courses)
app.get("/api/validated", (req, res) => {
  const snap = readJsonSafe(VALIDATED_FILE, { validatedAt: null, commandes: null });
  res.json(snap);
});

// =====================================================
app.listen(PORT, () => {
  console.log(`Backend dispo sur http://localhost:${PORT}`);
});
