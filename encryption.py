import os
import base64
import hashlib
import urllib.parse
from Crypto.Cipher import AES

# Navn på miljøvariabel der vi oppbevarer passordfrasen.
PASSWORD_ENV_VAR_NAME = "API_ENCRYPT_PASSWORD"
IV_STRING       = "0000000000000000"         # 16 ASCII-tegn '0'

def _derive_key_from_env_password() -> bytes:
    """
    Henter passordfrasen fra en miljøvariabel
    og avleder en nøkkel (Fernet-kompatibel) ved hjelp av SHA-256.
    """
    password = os.environ.get(PASSWORD_ENV_VAR_NAME)
    if not password:
        raise ValueError(f"Mangler miljøvariabel: {PASSWORD_ENV_VAR_NAME}")
    return hashlib.sha256(password.encode("utf-8")).hexdigest()

def encrypt_word(api_key: str) -> str:
    """
    Krypterer streng `api_key` på samme måte som Zoho Deluge:
      1) hashed_password = sha256(passord) -> 64-tegns hex
      2) klipp til 32 tegn -> AES-nøkkel
      3) IV = 16 ASCII-tegn '0'
      4) AES i CBC-modus + PKCS#7-padding
      5) Base64-encode av resulterende ciphertext

    Returnerer base64-strengen.
    """
    try:
        # 1) Hent 64-tegns hex av passordet fra miljøvariabel
        hashed_hex = _derive_key_from_env_password()

        # 2) Konverter til bytes og klipp til 32 for nøkkelen
        ascii_64 = hashed_hex.encode("ascii")  # f.eks. b'4154b8865ea1c6a0...'
        key_32   = ascii_64[:32]              # b'4154b8865ea1c6a04e19e26510d0d5f'

        # 3) IV = '0000000000000000' (ASCII)
        iv_bytes = IV_STRING.encode("ascii")  # b'0000000000000000'

        # 4) PKCS#7-padding av data
        block_size   = 16
        data_bytes   = api_key.encode("utf-8")
        pad_len      = block_size - (len(data_bytes) % block_size)
        data_padded  = data_bytes + bytes([pad_len]) * pad_len

        # 5) Krypter med AES CBC
        cipher  = AES.new(key_32, AES.MODE_CBC, iv_bytes)
        cipher_bytes = cipher.encrypt(data_padded)

        # 6) Base64-encod ciphertext
        encrypted_b64 = base64.b64encode(cipher_bytes).decode("ascii")
        return encrypted_b64

    except Exception as e:
        return f"FAILED TO ENCRYPT! {e}"

def decrypt_word(encrypted_api_key: str) -> str:
    """
    Dekrypterer en tidligere kryptert API-nøkkel, 
    basert på samme passordfrase i miljøvariabelen.
    """
    try:
        # 1) Hent passordet og lag 64-tegns hex av passordet
        hashed_hex = _derive_key_from_env_password()
        # f.eks.: "4154b8865ea1c6a04e19e26510d0d5fb513cf00d24141b50d0705e3e6836f044"

        # 2) Konverter hashed_hex til ASCII (64 bytes), klipp til 32
        ascii_64 = hashed_hex.encode("ascii")   # b'4154b8865ea1c6a0...'
        key_32   = ascii_64[:32]               # b'4154b8865ea1c6a04e19e26510d0d5f'

        # 3) IV = 16 ASCII-tegn '0', d.v.s. b'0000000000000000'
        iv_bytes = IV_STRING.encode("ascii")

        # 4) Base64-dekod ciphertext fra Zoho
        URLdecoded_key = urllib.parse.unquote(encrypted_api_key)
        print(URLdecoded_key)
        cipher_bytes = base64.b64decode(URLdecoded_key)

        # 5) Dekrypter med AES i CBC-modus
        cipher = AES.new(key_32, AES.MODE_CBC, iv_bytes)
        raw_decrypted = cipher.decrypt(cipher_bytes)

        # 6) Fjern PKCS#7-padding
        pad_len  = raw_decrypted[-1]
        plaintext_bytes = raw_decrypted[:-pad_len]

        result = plaintext_bytes.decode("utf-8")
    except Exception as e:
        result = f"FAILED TO DECRYPT! {e}"
    return result

if __name__ == "__main__":
    # Enkel CLI-eksempel:
    import sys

    if len(sys.argv) < 3:
        print("Bruk: python encryption.py <encrypt|decrypt> <tekst>")
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
