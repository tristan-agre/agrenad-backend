// ------------------------------
// server.js
// ------------------------------

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

// ------------------------------
// Chargement / Sauvegarde JSON
// ------------------------------

function loadData() {
  try {
    const raw = fs.readFileSync(DATA_FILE, "utf8");
    const data = JSON.parse(raw);
    return {
      petitdej: data.petitdej || { donnees: {}, updatedAt: null },
      bar: data.bar || { donnees: {}, updatedAt: null },
      entretien: data.entretien || { donnees: {}, updatedAt: null }
    };
  } catch (err) {
    // Si le fichier n'existe pas ou erreur -> structure vide
    return {
      petitdej: { donnees: {}, updatedAt: null },
      bar: { donnees: {}, updatedAt: null },
      entretien: { donnees: {}, updatedAt: null }
    };
  }
}

function saveData(data) {
  fs.writeFileSync(
    DATA_FILE,
    JSON.stringify(data, null, 2),
    "utf8"
  );
}

// ------------------------------
// ROUTES API
// ------------------------------

// Obtenir toutes les commandes
app.get("/api/commandes", (req, res) => {
  const data = loadData();
  res.json(data);
});

// Obtenir la commande d'un service
app.get("/api/commandes/:service", (req, res) => {
  const service = req.params.service;

  if (!["petitdej", "bar", "entretien"].includes(service)) {
    return res.status(400).json({ error: "Service inconnu" });
  }

  const data = loadData();
  res.json(data[service]);
});

// Enregistrer une commande (écraser/remplacer)
app.post("/api/commandes/:service", (req, res) => {
  const service = req.params.service;

  if (!["petitdej", "bar", "entretien"].includes(service)) {
    return res.status(400).json({ error: "Service inconnu" });
  }

  const data = loadData();

  // On stocke les données envoyées
  data[service] = {
    donnees: req.body || {},
    updatedAt: new Date().toISOString()
  };

  saveData(data);
  res.json({ message: `Commande '${service}' enregistrée.` });
});

// ------------------------------
// Réinitialiser un service
// ------------------------------
app.post("/api/reset/:service", (req, res) => {
  const service = req.params.service;

  if (!["petitdej", "bar", "entretien"].includes(service)) {
    return res.status(400).json({ error: "Service inconnu" });
  }

  const data = loadData();

  data[service] = {
    donnees: {},
    updatedAt: null
  };

  saveData(data);

  res.json({ message: `Service '${service}' réinitialisé.` });
});

// ------------------------------
// LANCEMENT
// ------------------------------

app.listen(PORT, () => {
  console.log(`Backend AGRENAD disponible sur le port ${PORT}`);
});
