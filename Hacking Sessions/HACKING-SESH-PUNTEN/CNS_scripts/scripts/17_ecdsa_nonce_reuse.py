"""
ECDSA NONCE-REUSE AANVAL (privesleutel herleiden)
======================================================
WANNEER GEBRUIKEN?
  - Je hebt TWEE verschillende ECDSA-signatures die TOEVALLIG (door een
    implementatiefout) dezelfde "random" nonce k gebruikten.
  - HERKENNING: twee signatures (r1,s1) en (r2,s2) met DEZELFDE r-waarde
    -> dat is het bewijs van nonce-hergebruik (r hangt namelijk enkel af
    van k, niet van het bericht).

PRINCIPE (zelfde "hergebruik-logica" als bij stream ciphers, maar dan
wiskundig op de elliptic-curve-order n toegepast):
  s1 = k^-1 (h1 + r*priv) mod n
  s2 = k^-1 (h2 + r*priv) mod n
  => s1 - s2 = k^-1 (h1 - h2) mod n
  => k = (h1 - h2) / (s1 - s2) mod n
  => priv = (s1*k - h1) / r mod n

VEREIST: pip install ecdsa --break-system-packages (optioneel, enkel om
de curve-orde 'n' van een standaardcurve op te zoeken; de wiskunde
hieronder werkt met pure Python modulaire rekenkunde)
"""
import hashlib


def sha256_int(message: bytes) -> int:
    return int.from_bytes(hashlib.sha256(message).digest(), "big")


def recover_private_key(r: int, s1: int, s2: int, h1: int, h2: int, n: int):
    """
    r       : de gedeelde r-waarde van beide signatures
    s1, s2  : de s-waarden van signature 1 en 2
    h1, h2  : SHA-256(bericht) als integer, voor bericht 1 en 2
    n       : de orde van de gebruikte elliptic curve
              (bv. secp256k1: n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141)
    """
    s_diff_inv = pow((s1 - s2) % n, -1, n)
    k = ((h1 - h2) * s_diff_inv) % n

    r_inv = pow(r, -1, n)
    priv = ((s1 * k - h1) * r_inv) % n
    return priv, k


if __name__ == "__main__":
    # Bekende curve-ordes (voorbeelden, pas aan naar de gebruikte curve):
    SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    SECP256R1_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551

    # TODO: vul de echte waarden in (uit de 2 afgeluisterde signatures)
    r = 0        # TODO (gedeelde r van beide signatures)
    s1 = 0       # TODO
    s2 = 0       # TODO
    h1 = sha256_int(b"bericht1")   # TODO: het ECHTE ondertekende bericht
    h2 = sha256_int(b"bericht2")   # TODO

    priv, k = recover_private_key(r, s1, s2, h1, h2, SECP256K1_N)
    print("Herwonnen nonce k:", hex(k))
    print("Herwonnen privesleutel:", hex(priv))
