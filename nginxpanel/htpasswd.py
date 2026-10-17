"""Hash {SSHA} compatible con auth_basic de nginx (sin dependencia de crypt)."""
import base64
import hashlib
import os


def ssha(password):
    salt = os.urandom(8)
    digest = hashlib.sha1(password.encode() + salt).digest()
    return "{SSHA}" + base64.b64encode(digest + salt).decode()
