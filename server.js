// server.js
const express = require("express");
const cors = require("cors");
const fs = require("fs");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;

// Fichier où on stocke toutes les commandes
const DATA_FILE = path.join(__dirname, "commandes.json");

app.use(cors());
app.use(express.json());

// ---------- Helpers pour lire/écrire le fichier ----------

function loadData() {
  try {
    const raw = fs.readFileSync(DATA_FILE, "utf8");
    const data = JSON.parse(raw);
    return {
      petitdej: data.petitdej || null,
      bar: data.bar || null,
      entretien: data.entretien || null,
    };
  } catch (e) {
    // Si fichier inexistant ou illisible
    return { petitdej: null, bar: null, entretien: null };
  }
}

function saveData(data) {
  fs.writeFileSync(DATA_FILE, JSON.stringify(data, null, 2), "utf8");
}

// ---------- Routes API ----------

// Récupérer toutes les commandes (pour le récap global)
app.get("/api/commandes", (req, res) => {
  const data = loadData();
  res.json(data);
});

// Récupérer la commande d'un service (petitdej, bar, entretien)
app.get("/api/commandes/:service", (req, res) => {
  const service = req.params.service; // "petitdej", "bar", "entretien"
  const data = loadData();

  if (!["petitdej", "bar", "entretien"].includes(service)) {
    return res.status(400).json({ error: "Service inconnu" });
  }

  res.json(data[service]);
});

// Enregistrer / remplacer la commande d'un service
app.post("/api/commandes/:service", (req, res) => {
  const service = req.params.service;

  if (!["petitdej", "bar", "entretien"].includes(service)) {
    return res.status(400).json({ error: "Service inconnu" });
  }

  const all = loadData();

  all[service] = {
    donnees: req.body.donnees || {},
    updatedAt: new Date().toISOString(),
  };

  saveData(all);

  res.json({ ok: true, service, commande: all[service] });
});

// Réinitialiser un service (effacer sa commande)
app.delete("/api/commandes/:service", (req, res) => {
  const service = req.params.service;

  if (!["petitdej", "bar", "entretien"].includes(service)) {
    return res.status(400).json({ error: "Service inconnu" });
  }

  const all = loadData();
  all[service] = null;
  saveData(all);
  res.json({ ok: true, service });
});

// ---------- Lancement du serveur ----------
app.listen(PORT, () => {
  console.log(`Backend AGRENAD dispo sur http://localhost:${PORT}`);
});