/* ─── ZKP Demo v2 — app.js ─────────────────────────────────────── */

const STEP_LABELS = {
  client:  "Client",
  network: "Réseau",
  server:  "Serveur",
  pki:     "PKI / CA",
  attack:  "Attaque"
};

/* ── Helpers ──────────────────────────────────────────────────── */
function showLoading(text = "Calcul cryptographique...") {
  document.getElementById("loading-text").textContent = text;
  document.getElementById("loading").style.display = "flex";
}
function hideLoading() {
  document.getElementById("loading").style.display = "none";
}
function clearSteps() {
  document.getElementById("idle-state").style.display = "flex";
  document.getElementById("steps-container").style.display = "none";
  document.getElementById("steps-container").innerHTML = "";
  document.getElementById("result-banner").style.display = "none";
  document.getElementById("result-banner").className = "result-banner";
}
function updateDB(db) {
  const el    = document.getElementById("db-display");
  const count = Object.keys(db).length;
  document.getElementById("db-count").textContent = `DB: ${count} utilisateur${count !== 1 ? "s" : ""}`;
  if (count === 0) {
    el.innerHTML = '<span class="db-empty">Base vide — inscrivez un utilisateur</span>';
    return;
  }
  el.innerHTML = Object.entries(db).map(([name, key]) => `
    <div class="db-entry">
      <span class="db-entry-name">▸ ${name}</span>
      <span class="db-entry-key">${key}</span>
    </div>
  `).join("");
}

/* ── Render one data value ────────────────────────────────────── */
function renderValue(key, val) {
  if (typeof val === "object" && val !== null) {
    return `<pre class="data-object">${JSON.stringify(val, null, 2)}</pre>`;
  }
  const str = String(val);
  let cls = "";
  if (key.toLowerCase().includes("formule") || key.toLowerCase().includes("équation")) cls = "formula";
  else if (str.startsWith("❌") || str.includes("absent") || str.includes("Impossible")) cls = "absent";
  else if (str.startsWith("✅") || str.includes("✓")) cls = "note-ok";
  else if (str.startsWith("🛡")) cls = "note-ok";
  return `<span class="data-value ${cls}">${str}</span>`;
}

/* ── Build and reveal step cards ──────────────────────────────── */
function renderSteps(steps, isAttack = false) {
  const container = document.getElementById("steps-container");
  container.innerHTML = "";
  document.getElementById("idle-state").style.display = "none";
  container.style.display = "flex";

  steps.forEach((step, index) => {
    const card = document.createElement("div");
    const typeClass = isAttack && step.type === "attack" ? "type-attack" : `type-${step.type || "client"}`;
    card.className = `step-card ${typeClass}`;
    card.dataset.index = index;

    const dataRows = step.data
      ? Object.entries(step.data).map(([k, v]) => `
          <div class="data-row">
            <span class="data-key">${k}</span>
            <span>${renderValue(k, v)}</span>
          </div>`).join("")
      : "";

    card.innerHTML = `
      <div class="step-header" onclick="toggleStep(this)">
        <div class="step-type-indicator"></div>
        <span class="step-number">0${index + 1}</span>
        <div class="step-info">
          <div class="step-title">${step.title}</div>
        </div>
        <span class="step-badge">${STEP_LABELS[step.type] || step.type}</span>
        <span class="step-chevron">▶</span>
      </div>
      <div class="step-body">
        <div class="step-content">
          <div class="step-description">${step.description}</div>
          ${dataRows ? `<div class="step-data">${dataRows}</div>` : ""}
        </div>
      </div>`;

    container.appendChild(card);
    setTimeout(() => card.classList.add("visible"), 60 * index);
  });
}

function toggleStep(header) {
  header.closest(".step-card").classList.toggle("expanded");
}

function showResult(text, type) {
  const el = document.getElementById("result-banner");
  el.textContent = text;
  el.className = `result-banner ${type}`;
  el.style.display = "block";
}

/* ── API calls ────────────────────────────────────────────────── */
window.registerUser = async function () {
  const username = document.getElementById("username").value.trim();
  const password = document.getElementById("password").value;
  if (!username || !password) { alert("Veuillez remplir l'identifiant et le mot de passe."); return; }

  showLoading("Génération des clés + émission certificat PKI...");
  try {
    const res  = await fetch("/register", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password })
    });
    const data = await res.json();
    hideLoading();
    if (data.status === "error") { showResult("⚠ " + data.msg, "fail"); clearSteps(); return; }
    renderSteps(data.steps);
    showResult(data.result, data.result_type);
    updateDB(data.db);
  } catch (err) {
    hideLoading();
    showResult("❌ Erreur réseau : " + err.message, "fail");
  }
};

window.loginUser = async function () {
  const username = document.getElementById("username").value.trim();
  const password = document.getElementById("password").value;
  if (!username || !password) { alert("Veuillez remplir l'identifiant et le mot de passe."); return; }

  showLoading("Vérification certificat PKI + génération preuve ZKP...");
  try {
    const res  = await fetch("/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password })
    });
    const data = await res.json();
    hideLoading();
    renderSteps(data.steps);
    showResult(data.result, data.result_type);
    updateDB(data.db);
  } catch (err) {
    hideLoading();
    showResult("❌ Erreur réseau : " + err.message, "fail");
  }
};

window.simulateAttack = async function (attackType) {
  const username = document.getElementById("username").value.trim();
  if (!username) { alert("Entrez d'abord un identifiant inscrit."); return; }

  const labels = {
    "wrong-password": "Simulation attaque — mauvais mot de passe...",
    "replay":         "Simulation replay attack...",
    "forgery":        "Simulation forgery — génération preuve forgée...",
    "mitm":           "Simulation Man-in-the-Middle..."
  };
  showLoading(labels[attackType] || "Simulation d'attaque...");

  try {
    const res  = await fetch(`/attack/${attackType}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username })
    });
    const data = await res.json();
    hideLoading();
    if (data.status === "error") { showResult("⚠ " + data.msg, "fail"); clearSteps(); return; }
    renderSteps(data.steps, true);
    showResult(data.result, data.result_type);
    updateDB(data.db);
  } catch (err) {
    hideLoading();
    showResult("❌ Erreur réseau : " + err.message, "fail");
  }
};

/* ── PKI Modal ────────────────────────────────────────────────── */
window.showPkiModal = async function () {
  document.getElementById("pki-modal").style.display = "flex";
  const body = document.getElementById("pki-modal-body");
  body.innerHTML = '<div class="loading-text">Chargement PKI...</div>';
  try {
    const res  = await fetch("/pki");
    const data = await res.json();
    const certs = Object.entries(data.certificates);
    body.innerHTML = `
      <div class="pki-section">
        <div class="pki-label">Clé publique CA (RSA-2048)</div>
        <pre class="pki-key">${data.ca_public_key}</pre>
      </div>
      <div class="pki-section">
        <div class="pki-label">Certificats émis (${data.total_issued})</div>
        ${certs.length === 0 ? '<div class="pki-empty">Aucun certificat — inscrivez un utilisateur</div>' :
          certs.map(([u, c]) => `
            <div class="pki-cert">
              <div class="cert-row"><span class="cert-key">Sujet</span><span class="cert-val">${u}</span></div>
              <div class="cert-row"><span class="cert-key">Serial</span><span class="cert-val cert-mono">${c.serial}</span></div>
              <div class="cert-row"><span class="cert-key">Issuer</span><span class="cert-val">${c.issuer}</span></div>
              <div class="cert-row"><span class="cert-key">Algorithme</span><span class="cert-val">${c.algorithm}</span></div>
              <div class="cert-row"><span class="cert-key">Émis le</span><span class="cert-val">${new Date(c.issued_at * 1000).toLocaleString('fr-FR')}</span></div>
              <div class="cert-row"><span class="cert-key">Signature CA</span><span class="cert-val cert-mono">${c.signature}</span></div>
            </div>
          `).join("")
        }
      </div>
    `;
  } catch {
    body.innerHTML = '<div class="pki-empty">Erreur de chargement PKI</div>';
  }
};

window.closePkiModal = function (e) {
  if (!e || e.target.id === "pki-modal" || e.target.classList.contains("modal-close")) {
    document.getElementById("pki-modal").style.display = "none";
  }
};

/* ── Init ─────────────────────────────────────────────────────── */
document.addEventListener("DOMContentLoaded", () => {
  fetch("/db").then(r => r.json()).then(d => updateDB(d.db)).catch(() => {});
});
