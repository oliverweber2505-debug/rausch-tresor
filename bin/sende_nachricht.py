import os
import sys
import datetime
from getpass import getpass
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

VAULT_DIR = os.path.expanduser("~/tresor_daten")

def erstelle_nachricht():
    print("=" * 40)
    print("      NACHRICHTEN-SCHREIBER (E2EE)      ")
    print("=" * 40)
    
    # 1. Empfänger oder Betreff eingeben
    empfaenger = input("Empfänger / Label: ").strip()
    if not empfaenger:
        empfaenger = "nachricht"
        
    print("\nGib deine Nachricht ein (Beende die Eingabe mit STRG+D oder 2x Enter):")
    
    # 2. Mehrzeiligen Text einlesen
    zeilen = []
    while True:
        try:
            zeile = input()
            if zeile == "" and (len(zeilen) > 0 and zeilen[-1] == ""):
                break
            zeilen.append(zeile)
        except EOFError:
            break
            
    nachricht_text = "\n".join(zeilen).strip()
    if not nachricht_text:
        print("[-] Abgebrochen: Keine Nachricht eingegeben.")
        return

    # 3. Passphrase abfragen
    print("\n" + "-" * 40)
    passphrase = getpass("Passphrase zum Verschlüsseln: ")
    bestaetigung = getpass("Passphrase wiederholen:     ")
    
    if passphrase != bestaetigung:
        print("[-] Fehler: Passphrasen stimmen nicht überein.")
        return

    # 4. Verschlüsselung vorbereiten
    salt = os.urandom(16)
    nonce = os.urandom(12)
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = kdf.derive(passphrase.encode())
    
    # 5. Text in Bytes umwandeln und AES-GCM anwenden
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, nachricht_text.encode('utf-8'), None)
    
    # 6. Dateinamen mit Zeitstempel generieren
    zeitstempel = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    dateiname = f"msg_{zeitstempel}_{empfaenger}.vault"
    ziel_pfad = os.path.join(VAULT_DIR, dateiname)
    
    # 7. Als Rauschen speichern
    with open(ziel_pfad, "wb") as f:
        f.write(salt + nonce + ciphertext)
        
    print("=" * 40)
    print(f"[+] Nachricht verschlüsselt im Tresor gespeichert:")
    print(f"    -> {ziel_pfad}")
    print("=" * 40)

if __name__ == "__main__":
    erstelle_nachricht()
