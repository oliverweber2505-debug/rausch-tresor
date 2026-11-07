import os
import datetime
from flask import Flask, render_template_string, request, redirect, url_for
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

app = Flask(__name__)
VAULT_DIR = os.path.expanduser("~/tresor_daten")
OUT_DIR = os.path.expanduser("~/tresor_app/daten")

os.makedirs(VAULT_DIR, exist_ok=True)
os.makedirs(OUT_DIR, exist_ok=True)

# HTML-Oberfläche im Messenger-Look
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="de">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Rausch-Tresor Messenger</title>
    <style>
        body { font-family: sans-serif; background: #121212; color: #e0e0e0; margin: 0; padding: 20px; }
        .container { max-width: 600px; margin: auto; background: #1e1e1e; padding: 20px; border-radius: 12px; box-shadow: 0 4px 15px rgba(0,0,0,0.5); }
        h1 { color: #00ff66; text-align: center; font-size: 24px; }
        textarea, input, button { width: 100%; padding: 12px; margin: 8px 0; border-radius: 6px; border: 1px solid #333; background: #2d2d2d; color: #fff; box-sizing: border-box; }
        button { background: #00ff66; color: #121212; font-weight: bold; cursor: pointer; border: none; }
        button:hover { background: #00cc52; }
        .vault-box { background: #252525; padding: 10px; margin: 10px 0; border-radius: 6px; border-left: 4px solid #00ff66; }
        .msg { background: #2a2a2a; padding: 10px; margin: 5px 0; border-radius: 6px; }
        hr { border: 0; border-top: 1px solid #333; margin: 20px 0; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔒 Rausch-Messenger</h1>
        
        <h3>Nachricht verschlüsseln</h3>
        <form method="POST" action="/encrypt">
            <input type="text" name="empfaenger" placeholder="Empfänger / Label (z.B. Alice)" required>
            <textarea name="nachricht" rows="4" placeholder="Geheime Nachricht eingeben..." required></textarea>
            <input type="password" name="passphrase" placeholder="Geheime Passphrase" required>
            <button type="submit">In Rauschen verwandeln (.vault)</button>
        </form>

        <hr>

        <h3>Gespeicherte Tresore (Rauschen)</h3>
        {% for vault in vaults %}
        <div class="vault-box">
            <strong>{{ vault }}</strong>
            <form method="POST" action="/decrypt" style="margin-top: 8px;">
                <input type="hidden" name="vault_name" value="{{ vault }}">
                <input type="password" name="passphrase" placeholder="Passphrase zum Entschlüsseln" required>
                <button type="submit" style="background: #333; color: #00ff66; border: 1px solid #00ff66;">Entschlüsseln</button>
            </form>
        </div>
        {% else %}
        <p style="color: #888;">Keine Tresore vorhanden.</p>
        {% endfor %}

        {% if decrypted_text %}
        <hr>
        <h3>Entschlüsselter Inhalt:</h3>
        <div class="msg">
            <pre style="white-space: pre-wrap; margin:0;">{{ decrypted_text }}</pre>
        </div>
        {% endif %}
    </div>
</body>
</html>
"""

@app.route("/")
def index():
    vaults = [f for f in os.listdir(VAULT_DIR) if f.endswith(".vault")]
    return render_template_string(HTML_TEMPLATE, vaults=vaults, decrypted_text=None)

@app.route("/encrypt", methods=["POST"])
def encrypt():
    empfaenger = request.form.get("empfaenger", "nachricht")
    nachricht = request.form.get("nachricht", "")
    passphrase = request.form.get("passphrase", "")

    if not nachricht or not passphrase:
        return redirect(url_for("index"))

    salt = os.urandom(16)
    nonce = os.urandom(12)
    
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000)
    key = kdf.derive(passphrase.encode())
    
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, nachricht.encode('utf-8'), None)
    
    zeitstempel = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    ziel_pfad = os.path.join(VAULT_DIR, f"msg_{zeitstempel}_{empfaenger}.vault")
    
    with open(ziel_pfad, "wb") as f:
        f.write(salt + nonce + ciphertext)
        
    return redirect(url_for("index"))

@app.route("/decrypt", methods=["POST"])
def decrypt():
    vault_name = request.form.get("vault_name")
    passphrase = request.form.get("passphrase")
    vault_path = os.path.join(VAULT_DIR, vault_name)

    decrypted_text = None
    try:
        with open(vault_path, "rb") as f:
            data = f.read()
        salt = data[:16]
        nonce = data[16:28]
        ciphertext = data[28:]
        
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000)
        key = kdf.derive(passphrase.encode())
        
        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        decrypted_text = plaintext.decode('utf-8')
    except Exception:
        decrypted_text = "[-] Fehler: Falsche Passphrase oder beschädigte Datei!"

    vaults = [f for f in os.listdir(VAULT_DIR) if f.endswith(".vault")]
    return render_template_string(HTML_TEMPLATE, vaults=vaults, decrypted_text=decrypted_text)

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000)
