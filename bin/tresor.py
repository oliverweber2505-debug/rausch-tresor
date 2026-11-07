import os
import sys
from getpass import getpass
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

VAULT_DIR = os.path.expanduser("~/tresor_daten")

def encrypt_file(file_path, passphrase):
    if not os.path.exists(file_path):
        print(f"[-] Fehler: Datei '{file_path}' nicht gefunden.")
        return

    # 1. Zufälliges Salz und Nonce erzeugen
    salt = os.urandom(16)
    nonce = os.urandom(12)
    
    # 2. Schlüsselableitung mit PBKDF2 (100.000 Runden)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = kdf.derive(passphrase.encode())
    
    # 3. Datei einlesen
    with open(file_path, "rb") as f:
        plaintext = f.read()
        
    # 4. Mit AES-GCM verschlüsseln (Ergebnis = reines Rauschen)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    
    # 5. Im Tresor-Ordner speichern
    base_name = os.path.basename(file_path)
    output_path = os.path.join(VAULT_DIR, base_name + ".vault")
    
    with open(output_path, "wb") as f:
        f.write(salt + nonce + ciphertext)
        
    # 6. Originaldatei sicher mit Zufallsdaten überschreiben und löschen
    file_size = os.path.getsize(file_path)
    with open(file_path, "wb") as f:
        f.write(os.urandom(file_size))
    os.remove(file_path)
    
    print(f"[+] Erfolgreich in Rauschen verwandelt: {output_path}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Verwendung: python3 tresor.py <pfad_zur_datei>")
        sys.exit(1)
        
    ziel = sys.argv[1]
    passwort = getpass("Geheime Passphrase eingeben: ")
    bestätigung = getpass("Passphrase wiederholen: ")
    
    if passwort == bestätigung:
        encrypt_file(ziel, passwort)
    else:
        print("[-] Fehler: Passphrasen stimmen nicht überein!")
