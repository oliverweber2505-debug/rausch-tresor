import os
import sys
from getpass import getpass
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

OUT_DIR = os.path.expanduser("~/tresor_app/daten")

def decrypt_file(vault_path, passphrase_input):
    if not os.path.exists(vault_path):
        print(f"[-] Fehler: Tresor-Datei '{vault_path}' nicht gefunden.")
        return

    with open(vault_path, "rb") as f:
        data = f.read()
        
    salt = data[:16]
    nonce = data[16:28]
    ciphertext = data[28:]
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = kdf.derive(passphrase_input.encode())
    
    try:
        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        
        base_name = os.path.basename(vault_path)
        original_name = base_name[:-6] if base_name.endswith(".vault") else base_name + ".decrypted"
        output_path = os.path.join(OUT_DIR, original_name)
        
        with open(output_path, "wb") as f:
            f.write(plaintext)
            
        print(f"[+] Erfolgreich entschlüsselt nach: {output_path}")
    except Exception:
        print("[-] Fehler: Falsche Passphrase oder beschädigte Datei (Authentifizierung fehlgeschlagen).")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Verwendung: python3 entrschluesseln.py <pfad_zur_.vault>")
        sys.exit(1)
        
    vault = sys.argv[1]
    passwort = getpass("Passphrase eingeben: ")
    decrypt_file(vault, passwort)
