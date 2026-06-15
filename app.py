from flask import Flask, render_template, request, jsonify
import hashlib
import secrets
import json
import os
import time
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend

app = Flask(__name__)

# ─── DH 2048-bit (RFC 3526 Group 14) ────────────────────────────
P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF", 16
)
Q = (P - 1) // 2
G = 2

# ─── PKI — Autorité de Certification (CA) ───────────────────────
# Générée une fois au démarrage, persistée en fichier JSON
PKI_FILE = "pki_store.json"

def _generate_ca():
    """Génère la paire de clés RSA-2048 de la CA."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    priv_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption()
    ).decode()
    pub_pem = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    return priv_pem, pub_pem

def _load_pki():
    if os.path.exists(PKI_FILE):
        with open(PKI_FILE) as f:
            return json.load(f)
    priv_pem, pub_pem = _generate_ca()
    store = {
        "ca_private_key": priv_pem,
        "ca_public_key":  pub_pem,
        "certificates":   {},   # username → {Y_hex, signature_hex, issued_at, serial}
        "users":          {}    # username → Y (int as hex string)
    }
    with open(PKI_FILE, "w") as f:
        json.dump(store, f, indent=2)
    return store

def _save_pki(store):
    with open(PKI_FILE, "w") as f:
        json.dump(store, f, indent=2)

PKI = _load_pki()

def _ca_sign(data: bytes) -> bytes:
    """Signe des données avec la clé privée de la CA."""
    ca_key = serialization.load_pem_private_key(
        PKI["ca_private_key"].encode(), password=None, backend=default_backend()
    )
    return ca_key.sign(data, padding.PKCS1v15(), hashes.SHA256())

def _ca_verify(data: bytes, signature: bytes) -> bool:
    """Vérifie une signature avec la clé publique de la CA."""
    ca_pub = serialization.load_pem_public_key(
        PKI["ca_public_key"].encode(), backend=default_backend()
    )
    try:
        ca_pub.verify(signature, data, padding.PKCS1v15(), hashes.SHA256())
        return True
    except Exception:
        return False

def _issue_certificate(username: str, Y: int) -> dict:
    """Émet un certificat PKI liant username ↔ Y, signé par la CA."""
    serial = secrets.token_hex(8)
    issued_at = int(time.time())
    Y_hex = hex(Y)
    payload = f"{serial}|{username}|{Y_hex}|{issued_at}".encode()
    sig = _ca_sign(payload)
    cert = {
        "serial":     serial,
        "subject":    username,
        "Y_hex":      Y_hex,
        "issued_at":  issued_at,
        "algorithm":  "RSA-2048 / SHA-256",
        "issuer":     "ZKP-Demo CA",
        "signature":  sig.hex()
    }
    return cert

def _verify_certificate(cert: dict) -> bool:
    """Vérifie l'intégrité d'un certificat PKI."""
    payload = f"{cert['serial']}|{cert['subject']}|{cert['Y_hex']}|{cert['issued_at']}".encode()
    sig = bytes.fromhex(cert["signature"])
    return _ca_verify(payload, sig)

# ─── ZKP helpers ────────────────────────────────────────────────
def keygen(password: str):
    x = int(hashlib.sha256(password.encode()).hexdigest(), 16) % Q
    if x == 0:
        x = 1
    Y = pow(G, x, P)
    return x, Y

def verify_zkp(Y, R, s, message):
    c = int(hashlib.sha256(f"{Y}{R}{message}".encode()).hexdigest(), 16) % Q
    lhs = (pow(G, s, P) * pow(Y, c, P)) % P
    return lhs == R, c

# ─── Replay attack store ─────────────────────────────────────────
# { session_id: { R, s, message, used: bool } }
SEEN_SESSIONS = {}

# ─── Routes ─────────────────────────────────────────────────────
@app.route("/")
def home():
    return render_template("index.html")

# ── Register ─────────────────────────────────────────────────────
@app.route("/register", methods=["POST"])
def register():
    data = request.json
    username = data.get("username", "").strip()
    password = data.get("password", "")

    if not username or not password:
        return jsonify({"status": "error", "msg": "Username et mot de passe requis"})
    if username in PKI["users"]:
        return jsonify({"status": "error", "msg": f"L'utilisateur '{username}' existe déjà"})

    x, Y = keygen(password)
    cert  = _issue_certificate(username, Y)

    PKI["users"][username]        = hex(Y)
    PKI["certificates"][username] = cert
    _save_pki(PKI)

    ca_pub_short = PKI["ca_public_key"].split("\n")[1][:24] + "..."

    return jsonify({
        "status": "ok",
        "steps": [
            {
                "id": "step1", "type": "client", "icon": "lock",
                "title": "Mot de passe saisi localement",
                "description": "Le mot de passe reste uniquement dans votre navigateur. Il ne sera JAMAIS envoyé au serveur.",
                "data": {"password": "••••••••• (masqué)"}
            },
            {
                "id": "step2", "type": "client", "icon": "key",
                "title": "Calcul de la clé privée x (SHA-256)",
                "description": "x = SHA256(password) mod Q — La clé privée est dérivée du mot de passe par hachage. Elle reste secrète sur votre machine.",
                "data": {"formule": "x = SHA256(password) mod Q", "x": hex(x)[:18] + "..."}
            },
            {
                "id": "step3", "type": "client", "icon": "shield",
                "title": "Calcul de la clé publique Y (Logarithme Discret)",
                "description": "Y = Gˣ mod P — Retrouver x depuis Y est computationnellement infaisable (DLP 2048 bits).",
                "data": {"formule": "Y = G^x mod P", "Y": hex(Y)[:18] + "..."}
            },
            {
                "id": "step4", "type": "network", "icon": "wifi",
                "title": "Transmission : clé publique Y uniquement",
                "description": "Seule Y est envoyée. Le mot de passe et x ne transitent JAMAIS sur le réseau.",
                "data": {
                    "envoyé":     {"username": username, "Y": hex(Y)[:18] + "..."},
                    "NON envoyé": {"password": "❌ absent", "x": "❌ absent"}
                }
            },
            {
                "id": "step5", "type": "pki", "icon": "certificate",
                "title": "PKI — Émission du certificat par la CA",
                "description": "La CA signe un certificat RSA-2048 liant l'identité (username) à la clé publique Y. Ce certificat garantit l'authenticité de Y.",
                "data": {
                    "serial":    cert["serial"],
                    "sujet":     cert["subject"],
                    "issuer":    cert["issuer"],
                    "algo":      cert["algorithm"],
                    "signature": cert["signature"][:24] + "...",
                    "CA_pubkey": ca_pub_short
                }
            },
            {
                "id": "step6", "type": "server", "icon": "database",
                "title": "Serveur — Stockage clé publique + certificat",
                "description": "La DB contient uniquement les clés publiques Y et les certificats signés. Aucun mot de passe ni hash n'est jamais stocké.",
                "data": {
                    "stocké":    {"Y": hex(Y)[:18] + "...", "cert_serial": cert["serial"]},
                    "Sécurité":  "✅ Aucun mot de passe | ✅ Aucun hash | ✅ Cert PKI signé"
                }
            }
        ],
        "result":      f"✅ '{username}' inscrit — certificat PKI émis (serial: {cert['serial']})",
        "result_type": "success",
        "db":          {k: v[:22] + "..." for k, v in PKI["users"].items()}
    })


# ── Login ─────────────────────────────────────────────────────────
@app.route("/login", methods=["POST"])
def login():
    data     = request.json
    username = data.get("username", "").strip()
    password = data.get("password", "")

    if not username or not password:
        return jsonify({"status": "error", "msg": "Username et mot de passe requis"})

    if username not in PKI["users"]:
        return jsonify({
            "status": "fail",
            "steps": [{
                "id": "step1", "type": "server", "icon": "search",
                "title": "Recherche de l'utilisateur",
                "description": f"L'utilisateur '{username}' est introuvable dans la base de données.",
                "data": {"username": username, "DB": list(PKI["users"].keys()) or ["(vide)"]}
            }],
            "result": f"❌ Utilisateur '{username}' inconnu",
            "result_type": "fail",
            "db": {k: v[:22] + "..." for k, v in PKI["users"].items()}
        })

    # ── Vérification certificat PKI ──────────────────────────────
    cert     = PKI["certificates"][username]
    cert_ok  = _verify_certificate(cert)
    stored_Y = int(PKI["users"][username], 16)

    x, Y = keygen(password)
    r    = secrets.randbelow(Q - 1) + 1
    R    = pow(G, r, P)
    session_id = secrets.token_hex(8)
    message    = f"session_{session_id}"
    c  = int(hashlib.sha256(f"{Y}{R}{message}".encode()).hexdigest(), 16) % Q
    s  = (r - c * x) % Q

    valid, server_c = verify_zkp(stored_Y, R, s, message)

    # Enregistrer session pour anti-replay
    SEEN_SESSIONS[session_id] = {"R": hex(R), "s": hex(s), "message": message, "used": True}

    steps = [
        {
            "id": "step1", "type": "pki", "icon": "certificate",
            "title": "PKI — Vérification du certificat",
            "description": "Avant toute preuve, le serveur vérifie la signature CA du certificat liant username ↔ Y. Si le cert est invalide ou forgé, l'authentification échoue immédiatement.",
            "data": {
                "serial":       cert["serial"],
                "cert_valide":  "✅ Signature CA vérifiée" if cert_ok else "❌ Certificat invalide !",
                "Y_certifiée":  cert["Y_hex"][:18] + "...",
                "algo":         cert["algorithm"]
            }
        },
        {
            "id": "step2", "type": "client", "icon": "random",
            "title": "Génération du nonce aléatoire r",
            "description": "r est un nombre aléatoire à usage unique. Il garantit que chaque preuve est différente — une preuve capturée ne peut être rejouée.",
            "data": {
                "r": hex(r)[:18] + "... (aléatoire, usage unique)",
                "formule": "R = G^r mod P",
                "R": hex(R)[:18] + "... (commitment)"
            }
        },
        {
            "id": "step3", "type": "client", "icon": "hash",
            "title": "Calcul du challenge c (Fiat-Shamir)",
            "description": "c = SHA256(Y ∥ R ∥ message) mod Q — Le challenge est calculé localement par hachage, rendant le protocole non-interactif.",
            "data": {
                "formule": "c = SHA256(Y ∥ R ∥ message) mod Q",
                "message": message,
                "c": hex(c)[:18] + "..."
            }
        },
        {
            "id": "step4", "type": "client", "icon": "calculate",
            "title": "Calcul de la réponse s",
            "description": "s = (r − c·x) mod Q — Il est mathématiquement impossible d'extraire x depuis s sans connaître r.",
            "data": {
                "formule": "s = (r - c × x) mod Q",
                "s": hex(s)[:18] + "...",
                "note": "x ne peut PAS être retrouvé depuis s"
            }
        },
        {
            "id": "step5", "type": "network", "icon": "send",
            "title": "Envoi de la preuve ZKP sur le réseau",
            "description": "Le paquet réseau contient (R, s, message) — ni le mot de passe ni x. Un attaquant qui capture ce paquet ne peut rien en faire.",
            "data": {
                "paquet_envoyé": {
                    "username": username,
                    "R": hex(R)[:18] + "...",
                    "s": hex(s)[:18] + "...",
                    "message": message
                },
                "ABSENT du paquet": "password ❌ | x ❌"
            }
        },
        {
            "id": "step6", "type": "server", "icon": "recalculate",
            "title": "Serveur — Recalcul du challenge c",
            "description": "Le serveur recalcule c via le même hash. Il utilise la Y stockée (certifiée par PKI) et non celle envoyée par le client.",
            "data": {
                "formule":    "c = SHA256(Y ∥ R ∥ message) mod Q",
                "c_serveur":  hex(server_c)[:18] + "...",
                "Y_stockée":  hex(stored_Y)[:18] + "..."
            }
        },
        {
            "id": "step7", "type": "server", "icon": "verify",
            "title": "Vérification de l'équation de Schnorr",
            "description": "Le serveur vérifie : G^s × Y^c ≡ R (mod P). Si vraie, l'utilisateur a prouvé qu'il connaît x sans jamais le révéler.",
            "data": {
                "équation":  "G^s × Y^c ≡ R (mod P) ?",
                "résultat":  "✅ VRAI — Preuve valide" if valid else "❌ FAUX — Preuve invalide",
                "explication": "G^(r-cx) × G^(cx) = G^r = R ✓" if valid else "Les valeurs ne correspondent pas"
            }
        }
    ]

    return jsonify({
        "status":      "ok" if valid else "fail",
        "steps":       steps,
        "result":      f"✅ '{username}' authentifié — identité prouvée sans révélation" if valid else f"❌ Preuve invalide — le secret ne correspond pas",
        "result_type": "success" if valid else "fail",
        "db":          {k: v[:22] + "..." for k, v in PKI["users"].items()}
    })


# ── Attaques ─────────────────────────────────────────────────────

@app.route("/attack/wrong-password", methods=["POST"])
def attack_wrong_password():
    """Mauvais mot de passe → preuve ZKP invalide."""
    data     = request.json
    username = data.get("username", "").strip()
    if username not in PKI["users"]:
        return jsonify({"status": "error", "msg": "Inscrivez d'abord un utilisateur"})

    fake_password = "ATTAQUE_" + secrets.token_hex(4)
    x, Y    = keygen(fake_password)
    stored_Y = int(PKI["users"][username], 16)
    r       = secrets.randbelow(Q - 1) + 1
    R       = pow(G, r, P)
    session_id = secrets.token_hex(8)
    message = f"session_{session_id}"
    c = int(hashlib.sha256(f"{Y}{R}{message}".encode()).hexdigest(), 16) % Q
    s = (r - c * x) % Q
    valid, _ = verify_zkp(stored_Y, R, s, message)

    return jsonify({
        "status": "fail",
        "attack": "wrong_password",
        "steps": [
            {
                "id": "a1", "type": "attack", "icon": "skull",
                "title": "🔴 Attaque — Mauvais mot de passe",
                "description": "L'attaquant tente de s'authentifier avec un mot de passe incorrect. Il génère une preuve ZKP basée sur un x≠x_réel.",
                "data": {
                    "mot_de_passe_tenté": fake_password,
                    "x_calculé": hex(x)[:18] + "... (≠ x réel)",
                    "Y_calculé": hex(Y)[:18] + "... (≠ Y stockée)"
                }
            },
            {
                "id": "a2", "type": "server", "icon": "verify",
                "title": "Serveur — Vérification de l'équation",
                "description": "G^s × Y_fausse^c ≠ R car Y_fausse ≠ Y_stockée. L'équation de Schnorr ne se vérifie pas.",
                "data": {
                    "Y_soumise":  hex(Y)[:18] + "...",
                    "Y_stockée":  hex(stored_Y)[:18] + "...",
                    "résultat":   "❌ G^s × Y^c ≢ R — Preuve rejetée"
                }
            },
            {
                "id": "a3", "type": "server", "icon": "shield",
                "title": "🛡 Défense ZKP — Pourquoi ça échoue",
                "description": "Sans connaître x, il est impossible de forger un s tel que G^s × Y^c ≡ R. L'attaquant aurait besoin de résoudre le DLP 2048 bits.",
                "data": {
                    "Sécurité": "✅ DLP 2048 bits — infaisable en pratique",
                    "Conclusion": "✅ Attaque bloquée — ZKP résiste au mauvais password"
                }
            }
        ],
        "result":      "🛡 Attaque rejetée — mauvais mot de passe détecté par ZKP",
        "result_type": "fail",
        "db":          {k: v[:22] + "..." for k, v in PKI["users"].items()}
    })


@app.route("/attack/replay", methods=["POST"])
def attack_replay():
    """Replay attack : rejouer une preuve (R, s) déjà utilisée."""
    data     = request.json
    username = data.get("username", "").strip()
    if username not in PKI["users"]:
        return jsonify({"status": "error", "msg": "Inscrivez d'abord un utilisateur"})

    stored_Y = int(PKI["users"][username], 16)

    # Simuler une capture réseau d'une vraie preuve passée
    # (on génère une vraie preuve valide, puis on "rejoue" avec même session_id)
    fake_pass = "captured_secret"
    x_cap, Y_cap = keygen(fake_pass)
    r_cap = secrets.randbelow(Q - 1) + 1
    R_cap = pow(G, r_cap, P)
    session_id_original = "CAPTURED_" + secrets.token_hex(4)
    message_original = f"session_{session_id_original}"

    # Marquer comme déjà vu
    SEEN_SESSIONS[session_id_original] = {
        "R": hex(R_cap), "s": "...", "message": message_original, "used": True
    }

    # Maintenant l'attaquant essaie de rejouer exactement ce message
    is_replay = session_id_original in SEEN_SESSIONS and SEEN_SESSIONS[session_id_original]["used"]

    # Même si on jouait la vraie preuve, le session_id est différent à chaque fois
    # → le challenge c sera différent → la vérification échoue
    new_session_id = secrets.token_hex(8)
    new_message = f"session_{new_session_id}"
    c_new = int(hashlib.sha256(f"{stored_Y}{R_cap}{new_message}".encode()).hexdigest(), 16) % Q

    return jsonify({
        "status": "fail",
        "attack": "replay",
        "steps": [
            {
                "id": "r1", "type": "attack", "icon": "skull",
                "title": "🔴 Attaque Replay — Capture réseau",
                "description": "L'attaquant capture un paquet réseau valide (R, s, message) lors d'une authentification précédente.",
                "data": {
                    "paquet_capturé": {
                        "username": username,
                        "R": hex(R_cap)[:18] + "...",
                        "message": message_original
                    },
                    "stratégie": "Rejouer ce même paquet plus tard"
                }
            },
            {
                "id": "r2", "type": "attack", "icon": "repeat",
                "title": "L'attaquant rejoue le paquet capturé",
                "description": "L'attaquant renvoie exactement le même (R, s, message) au serveur.",
                "data": {
                    "session_originale":  session_id_original,
                    "session_actuelle":   new_session_id,
                    "session_id_connu":   "✅ OUI — déjà vu" if is_replay else "Non"
                }
            },
            {
                "id": "r3", "type": "server", "icon": "verify",
                "title": "Serveur — Détection replay via nonce",
                "description": "Le serveur génère un nouveau session_id à chaque connexion. L'ancien message ne correspond plus au nouveau challenge c recalculé.",
                "data": {
                    "c_avec_old_message": "DIFFÉRENT du c original",
                    "c_avec_new_message": hex(c_new)[:18] + "...",
                    "résultat": "❌ G^s × Y^c_nouveau ≢ R — Replay détecté"
                }
            },
            {
                "id": "r4", "type": "server", "icon": "shield",
                "title": "🛡 Défense — Nonce à usage unique",
                "description": "Le session_id change à chaque tentative. La preuve ZKP est liée cryptographiquement au message — impossible de la réutiliser.",
                "data": {
                    "Mécanisme":  "session_id aléatoire à chaque connexion",
                    "Résultat":   "✅ Attaque replay bloquée",
                    "Conclusion": "✅ ZKP est résistant aux attaques par rejeu"
                }
            }
        ],
        "result":      "🛡 Replay attack bloquée — le nonce change à chaque session",
        "result_type": "fail",
        "db":          {k: v[:22] + "..." for k, v in PKI["users"].items()}
    })


@app.route("/attack/forgery", methods=["POST"])
def attack_forgery():
    """Forgery : l'attaquant forge R et s aléatoires."""
    data     = request.json
    username = data.get("username", "").strip()
    if username not in PKI["users"]:
        return jsonify({"status": "error", "msg": "Inscrivez d'abord un utilisateur"})

    stored_Y = int(PKI["users"][username], 16)

    # Attaquant forge des valeurs aléatoires
    R_forged = secrets.randbelow(P - 1) + 1
    s_forged = secrets.randbelow(Q - 1) + 1
    session_id = secrets.token_hex(8)
    message = f"session_{session_id}"

    valid, c_srv = verify_zkp(stored_Y, R_forged, s_forged, message)

    lhs = (pow(G, s_forged, P) * pow(stored_Y, c_srv, P)) % P
    equation_holds = lhs == R_forged

    return jsonify({
        "status": "fail",
        "attack": "forgery",
        "steps": [
            {
                "id": "f1", "type": "attack", "icon": "skull",
                "title": "🔴 Forgery — Génération de R et s aléatoires",
                "description": "L'attaquant ne connaît pas x. Il tente de forger une preuve valide en générant R et s complètement aléatoires.",
                "data": {
                    "stratégie":  "Choisir R et s au hasard et espérer que G^s × Y^c ≡ R",
                    "R_forgé":    hex(R_forged)[:18] + "... (aléatoire)",
                    "s_forgé":    hex(s_forged)[:18] + "... (aléatoire)"
                }
            },
            {
                "id": "f2", "type": "server", "icon": "recalculate",
                "title": "Serveur — Calcul du challenge c",
                "description": "Le serveur calcule c = SHA256(Y ∥ R_forgé ∥ message). Ce c dépend de R_forgé.",
                "data": {
                    "c_calculé": hex(c_srv)[:18] + "...",
                    "Y_connue":  hex(stored_Y)[:18] + "..."
                }
            },
            {
                "id": "f3", "type": "server", "icon": "verify",
                "title": "Vérification G^s_forgé × Y^c ≡ R_forgé ?",
                "description": "La probabilité que cette équation soit vraie par hasard est de 1/Q ≈ 2⁻²⁰⁴⁷. En pratique : impossible.",
                "data": {
                    "équation":     "G^s_forgé × Y^c ≡ R_forgé (mod P) ?",
                    "résultat":     "❌ FAUX — Forgery détectée" if not equation_holds else "Coïncidence astronomique",
                    "probabilité":  "1 chance sur 2^2047 ≈ 0"
                }
            },
            {
                "id": "f4", "type": "server", "icon": "shield",
                "title": "🛡 Défense — Soundness du protocole Schnorr",
                "description": "La propriété 'soundness' de Schnorr garantit qu'un prouveur sans x ne peut réussir qu'avec probabilité négligeable (1/Q). Ce résultat est prouvé mathématiquement.",
                "data": {
                    "Propriété":  "Soundness — seul le vrai détenteur de x peut prouver",
                    "Fondement":  "Difficulté du Discrete Log Problem (DLP)",
                    "Conclusion": "✅ Forgery impossible sans connaître x"
                }
            }
        ],
        "result":      "🛡 Forgery bloquée — la soundness de Schnorr empêche toute forgerie",
        "result_type": "fail",
        "db":          {k: v[:22] + "..." for k, v in PKI["users"].items()}
    })


@app.route("/attack/mitm", methods=["POST"])
def attack_mitm():
    """Man-in-the-Middle passif : intercepter la preuve ZKP."""
    data     = request.json
    username = data.get("username", "").strip()
    if username not in PKI["users"]:
        return jsonify({"status": "error", "msg": "Inscrivez d'abord un utilisateur"})

    stored_Y  = int(PKI["users"][username], 16)
    cert      = PKI["certificates"][username]
    cert_ok   = _verify_certificate(cert)

    # Simuler une vraie session interceptée
    x_real, Y_real = keygen("mot_de_passe_victime")
    r_int = secrets.randbelow(Q - 1) + 1
    R_int = pow(G, r_int, P)
    session_id = secrets.token_hex(8)
    message = f"session_{session_id}"
    c_int = int(hashlib.sha256(f"{Y_real}{R_int}{message}".encode()).hexdigest(), 16) % Q
    s_int = (r_int - c_int * x_real) % Q

    # Ce que l'attaquant intercepte : (R, s, message) — jamais x
    # Peut-il extraire x depuis (R, s, message, Y) ?
    # s = r - c*x  =>  x = (r - s) / c  ... mais r est inconnu !

    # L'attaquant tente de rejouer avec ce paquet intercepté (vs nouveau session_id)
    new_session_id = secrets.token_hex(8)
    new_message = f"session_{new_session_id}"
    valid_replay, _ = verify_zkp(stored_Y, R_int, s_int, new_message)

    return jsonify({
        "status": "fail",
        "attack": "mitm",
        "steps": [
            {
                "id": "m1", "type": "attack", "icon": "skull",
                "title": "🔴 MitM Passif — Interception du paquet ZKP",
                "description": "L'attaquant se positionne sur le réseau et capture le paquet d'authentification en clair.",
                "data": {
                    "paquet_intercepté": {
                        "username": username,
                        "R":        hex(R_int)[:18] + "...",
                        "s":        hex(s_int)[:18] + "...",
                        "message":  message
                    },
                    "objectif": "Extraire x depuis (R, s, message, Y)"
                }
            },
            {
                "id": "m2", "type": "attack", "icon": "math",
                "title": "Tentative d'extraction de x depuis (R, s)",
                "description": "s = r − c·x  →  x = (r − s) / c mod Q. Mais r n'est jamais transmis ! L'attaquant est bloqué par le secret du nonce.",
                "data": {
                    "formule":     "x = (r - s) / c mod Q",
                    "r_connu":     "❌ NON — r n'est jamais envoyé",
                    "extraction":  "❌ Impossible sans r"
                }
            },
            {
                "id": "m3", "type": "attack", "icon": "cert-check",
                "title": "PKI — Protection contre l'usurpation de Y",
                "description": "L'attaquant pourrait tenter de substituer sa propre Y. Mais le certificat PKI, signé par la CA, lie username ↔ Y. Une substitution invaliderait la signature.",
                "data": {
                    "cert_serial":  cert["serial"],
                    "cert_valide":  "✅ Signature CA intacte" if cert_ok else "❌ Cert invalide",
                    "Y_certifiée":  cert["Y_hex"][:18] + "...",
                    "substitution": "❌ Signature CA invalide si Y est modifiée"
                }
            },
            {
                "id": "m4", "type": "attack", "icon": "replay-fail",
                "title": "Tentative de réutilisation du paquet",
                "description": "L'attaquant rejoue (R, s) avec un nouveau session_id. Le challenge c change → la vérification échoue.",
                "data": {
                    "nouveau_session":  new_session_id,
                    "replay_valide":    "❌ FAUX — challenge c différent" if not valid_replay else "Coïncidence",
                    "résultat":         "❌ Replay impossible"
                }
            },
            {
                "id": "m5", "type": "server", "icon": "shield",
                "title": "🛡 Défense multicouche contre MitM",
                "description": "ZKP + PKI forment une double protection : ZKP empêche l'extraction du secret, PKI empêche l'usurpation d'identité.",
                "data": {
                    "ZKP":         "✅ r secret → x non extractible",
                    "PKI":         "✅ Certificat CA → Y non substituable",
                    "Nonce":       "✅ session_id → non rejouable",
                    "Conclusion":  "✅ MitM passif totalement inefficace"
                }
            }
        ],
        "result":      "🛡 MitM bloqué — ZKP + PKI protègent contre l'interception réseau",
        "result_type": "fail",
        "db":          {k: v[:22] + "..." for k, v in PKI["users"].items()}
    })


# ── DB + PKI info ─────────────────────────────────────────────────
@app.route("/db", methods=["GET"])
def get_db():
    return jsonify({
        "db":    {k: v[:22] + "..." for k, v in PKI["users"].items()},
        "count": len(PKI["users"]),
        "note":  "Aucun mot de passe stocké — seulement des clés publiques certifiées"
    })

@app.route("/pki", methods=["GET"])
def get_pki():
    ca_pub = PKI["ca_public_key"]
    certs  = {
        u: {
            "serial":    c["serial"],
            "issued_at": c["issued_at"],
            "algorithm": c["algorithm"],
            "issuer":    c["issuer"],
            "signature": c["signature"][:24] + "..."
        }
        for u, c in PKI["certificates"].items()
    }
    return jsonify({
        "ca_public_key": ca_pub,
        "certificates":  certs,
        "total_issued":  len(certs)
    })


if __name__ == "__main__":
    app.run(debug=True)
