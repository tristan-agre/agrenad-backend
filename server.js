// server.js
const express = require("express");
const cors = require("cors");
const fs = require("fs");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;

// Fichiers de stockage
const DATA_FILE = path.join(__dirname, "commandes.json");
const VALIDATED_FILE = path.join(__dirname, "validated.json");

app.use(cors());
app.use(express.json());

// ---------- Helpers ----------
function loadJSON(filePath, fallback) {
  try {
    if (!fs.existsSync(filePath)) return fallback;
    const raw = fs.readFileSync(filePath, "utf8");
    if (!raw.trim()) return fallback;
    return JSON.parse(raw);
  } catch {
    return fallback;
  }
}

function saveJSON(filePath, data) {
  fs.writeFileSync(filePath, JSON.stringify(data, null, 2), "utf8");
}

function loadData() {
  const fallback = { petitdej: null, bar: null, entretien: null };
  const data = loadJSON(DATA_FILE, fallback);
  return {
    petitdej: data.petitdej || null,
    bar: data.bar || null,
    entretien: data.entretien || null,
  };
}

function saveData(data) {
  saveJSON(DATA_FILE, data);
}

function nowISO() {
  return new Date().toISOString();
}

function normalizeService(service) {
  const ok = ["petitdej", "bar", "entretien"];
  return ok.includes(service) ? service : null;
}

// ---------- Routes ----------
app.get("/", (req, res) => {
  res.json({ ok: true, message: "Backend AGRENAD OK" });
});

// Récap global
app.get("/api/commandes", (req, res) => {
  const data = loadData();
  res.json(data);
});

// Récupérer commande d'un service
app.get("/api/commandes/:service", (req, res) => {
  const service = normalizeService(req.params.service);
  if (!service) return res.status(400).json({ error: "Service inconnu" });
  const data = loadData();
  res.json(data[service] || null);
});

// Enregistrer / mettre à jour la commande d'un service (utilisé par tes pages de saisie)
app.post("/api/commandes/:service", (req, res) => {
  const service = normalizeService(req.params.service);
  if (!service) return res.status(400).json({ error: "Service inconnu" });

  const body = req.body || {};
  // On stocke exactement au format que tu utilises déjà: { donnees: {donnees:{...}}, updatedAt }
  const record = {
    donnees: body.donnees ?? body, // tolérant
    updatedAt: nowISO(),
  };

  const data = loadData();
  data[service] = record;
  saveData(data);

  res.json({ ok: true, service, updatedAt: record.updatedAt });
});

// ✅ NOUVEAU : modification fine depuis recap (PUT = remplace les donnees du service)
app.put("/api/commandes/:service", (req, res) => {
  const service = normalizeService(req.params.service);
  if (!service) return res.status(400).json({ error: "Service inconnu" });

  const payload = req.body || {};
  // attendu: { donnees: {...} } ou directement {...}
  const newDonnees = payload.donnees ?? payload;

  const record = {
    donnees: newDonnees,
    updatedAt: nowISO(),
  };

  const data = loadData();
  data[service] = record;
  saveData(data);

  res.json({ ok: true, service, updatedAt: record.updatedAt });
});

// Reset d'un service
app.post("/api/reset/:service", (req, res) => {
  const service = normalizeService(req.params.service);
  if (!service) return res.status(400).json({ error: "Service inconnu" });

  const data = loadData();
  data[service] = null;
  saveData(data);

  res.json({ ok: true, service, reset: true });
});

// ✅ NOUVEAU : VALIDATION (snapshot figé pour les courses)
app.post("/api/validate", (req, res) => {
  const data = loadData();
  const snapshot = {
    validatedAt: nowISO(),
    commandes: data,
  };
  saveJSON(VALIDATED_FILE, snapshot);
  res.json({ ok: true, validatedAt: snapshot.validatedAt });
});

// ✅ NOUVEAU : récupérer le snapshot validé (lu par courses.html)
app.get("/api/validated", (req, res) => {
  const fallback = { validatedAt: null, commandes: { petitdej: null, bar: null, entretien: null } };
  const snap = loadJSON(VALIDATED_FILE, fallback);
  res.json(snap);
});

// ✅ NOUVEAU : reset snapshot validé (optionnel)
app.post("/api/validated/reset", (req, res) => {
  const fallback = { validatedAt: null, commandes: { petitdej: null, bar: null, entretien: null } };
  saveJSON(VALIDATED_FILE, fallback);
  res.json({ ok: true, resetValidated: true });
});

app.listen(PORT, () => {
  console.log(`Backend AGRENAD dispo sur le port ${PORT}`);
});
