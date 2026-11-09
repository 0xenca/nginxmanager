"""Hash de contraseñas para auth_basic de nginx.

Se usa SHA-512 crypt ($6$, 5000 rondas con sal), que nginx valida mediante crypt(3) de la
libc. Antes se usaba {SSHA} (un único SHA-1 con sal): los hashes antiguos siguen
funcionando en nginx y se regeneran al cambiar la contraseña.
"""
import subprocess


class HashError(Exception):
    pass


def hash_password(password):
    try:
        p = subprocess.run(["openssl", "passwd", "-6", "-stdin"], input=password + "\n",
                           capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired) as e:
        raise HashError(f"No se pudo ejecutar openssl: {e}") from e
    out = p.stdout.strip()
    if p.returncode != 0 or not out.startswith("$6$"):
        raise HashError("openssl passwd -6 no está disponible (se necesita OpenSSL 1.1.1+)")
    return out
