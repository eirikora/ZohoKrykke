import os
import base64
import hashlib
from cryptography.fernet import Fernet

# Navn på miljøvariabel der vi oppbevarer passordfrasen.
PASSWORD_ENV_VAR_NAME = "API_ENCRYPT_PASSWORD"

def _derive_key_from_env_password() -> bytes:
    """
    Henter passordfrasen fra en miljøvariabel
    og avleder en nøkkel (Fernet-kompatibel) ved hjelp av SHA-256.
    """
    password = os.environ.get(PASSWORD_ENV_VAR_NAME)
    if not password:
        raise ValueError(f"Mangler miljøvariabel: {PASSWORD_ENV_VAR_NAME}")
    sha256 = hashlib.sha256(password.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(sha256)

def encrypt_word(api_key: str) -> str:
    """
    Krypterer API-nøkkelen med en nøkkel avledet fra passordfrasen i miljøvariabel.
    Returnerer kryptert tekst (base64/Fernet).
    """
    try:
        key = _derive_key_from_env_password()
        fernet = Fernet(key)
        encrypted = fernet.encrypt(api_key.encode("utf-8"))
        result = encrypted.decode("utf-8")
    except Exception as e:
        result = f"FAILED TO ENCRYPT! {e}"
    return result

def decrypt_word(encrypted_api_key: str) -> str:
    """
    Dekrypterer en tidligere kryptert API-nøkkel, 
    basert på samme passordfrase i miljøvariabelen.
    """
    try:
        key = _derive_key_from_env_password()
        fernet = Fernet(key)
        decrypted = fernet.decrypt(encrypted_api_key.encode("utf-8"))
        result = decrypted.decode("utf-8")
    except Exception as e:
        result = f"FAILED TO DECRYPT! {e}"
    return result

if __name__ == "__main__":
    # Enkel CLI-eksempel:
    import sys

    if len(sys.argv) < 3:
        print("Bruk: python script.py <encrypt|decrypt> <tekst>")
        sys.exit(1)

    command = sys.argv[1]
    text = sys.argv[2]

    if command == "encrypt":
        result = encrypt_word(text)
        print(f"Kryptert nøkkel:\n{result}")
    elif command == "decrypt":
        result = decrypt_word(text)
        print(f"Dekryptert nøkkel:\n{result}")
    else:
        print("Ugyldig kommando. Bruk 'encrypt' eller 'decrypt'.")
        sys.exit(1)
