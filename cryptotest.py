import base64
import hashlib
from Crypto.Cipher import AES

def decrypt_deluge_cbc_ascii_key(encrypted_b64: str, password: str, iv_str: str) -> str:
    """
    Dekrypterer en streng som er produsert i Zoho med:
        hashed_password = zoho.encryption.sha256(password)  // 64-tegn hex-streng
        // aesEncode(hashed_password, openKey, iv_str) i CBC-modus
        // MEN Zoho bruker ASCII-stringen av hashed_password (64 tegn) 
        // og klipper den til 32 tegn som nøkkel.

    Parametere:
        encrypted_b64: Strengen Zoho returnerer (base64)
        password:      Passordet Zoho hashet med SHA-256
        iv_str:        16 ASCII-tegn, f.eks. "0000000000000000"

    Returnerer dekryptert klartekst (f.eks. "HemmeligMelding").
    """

    # 1) Lag 64-tegns hex av passordet
    hashed_hex = hashlib.sha256(password.encode("utf-8")).hexdigest()
    # f.eks.: "4154b8865ea1c6a04e19e26510d0d5fb513cf00d24141b50d0705e3e6836f044"

    # 2) Konverter hashed_hex til ASCII (64 bytes), klipp til 32
    ascii_64 = hashed_hex.encode("ascii")   # b'4154b8865ea1c6a0...'
    key_32   = ascii_64[:32]               # b'4154b8865ea1c6a04e19e26510d0d5f'

    # 3) IV = 16 ASCII-tegn '0', d.v.s. b'0000000000000000'
    iv_bytes = iv_str.encode("ascii")

    # 4) Base64-dekod ciphertext fra Zoho
    cipher_bytes = base64.b64decode(encrypted_b64)

    # 5) Dekrypter med AES i CBC-modus
    cipher = AES.new(key_32, AES.MODE_CBC, iv_bytes)
    raw_decrypted = cipher.decrypt(cipher_bytes)

    # 6) Fjern PKCS#7-padding
    pad_len  = raw_decrypted[-1]
    plaintext_bytes = raw_decrypted[:-pad_len]

    return plaintext_bytes.decode("utf-8")

if __name__ == "__main__":
    encryptedKey = "MZoLwJ8aCoSay2Lha65lQw=="  # Output fra Zoho
    password     = "guest@a2norge"
    iv_str       = "0000000000000000"         # 16 ASCII-tegn '0'

    plain = decrypt_deluge_cbc_ascii_key(encryptedKey, password, iv_str)
    print("Dekryptert melding:", plain)
    # Forventet output: "HemmeligMelding"
