import base64
import json

from Crypto import Random
from Crypto.Cipher import AES


def encrypt_data(data: list, app_secret: bytes, block_size: int) -> str:
    plain_text = pad(json.dumps(data), block_size=block_size)
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(app_secret, AES.MODE_CBC, iv)
    return base64.b64encode(iv + cipher.encrypt(plain_text.encode())).decode()


def decrypt_data(cipher_text: str, app_secret: bytes, block_size: int) -> str:
    # TODO: Move this to the server code
    cipher_text = base64.b64decode(cipher_text)
    iv = cipher_text[:block_size]
    cipher = AES.new(app_secret, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(cipher_text[16:]).decode())


def pad(text: str, block_size: int) -> str:
    return text + (block_size - len(text) % block_size) * chr(
        block_size - len(text) % block_size
    )


def unpad(text: str) -> str:
    return text[: -ord(text[len(text) - 1 :])]
