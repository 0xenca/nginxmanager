"""{SSHA} hash compatible with nginx auth_basic (no dependency on crypt)."""
import base64
import hashlib
import os


def ssha(password):
    salt = os.urandom(8)
    digest = hashlib.sha1(password.encode() + salt).digest()
    return "{SSHA}" + base64.b64encode(digest + salt).decode()
