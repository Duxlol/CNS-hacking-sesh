"""
BRUTE FORCE VAN EEN KLEINE/VOORSPELBARE SLEUTELRUIMTE
========================================================
WANNEER GEBRUIKEN?
  - De opgave zegt expliciet dat sleutels "gestandaardiseerd", kort, of
    afgeleid zijn van iets voorspelbaars (naam, namespace, bedrijfsnaam).
  - Werkt voor DES (8-byte sleutel) en AES (16/24/32-byte sleutel).

STRATEGIE:
  1. Probeer eerst een lijst van "voor de hand liggende" volledige sleutels
     (padding met nullen, herhalingen, hoofdletters/kleine letters).
  2. Als dat niks geeft: bruteforce de ONBEKENDE resterende karakters als
     die beperkt zijn (bv. "prefix + 2 onbekende tekens uit een alfabet").
  3. Check altijd op een herkenbaar stuk plaintext (b"cns{") in het resultaat.

VOORBEELD WAAR DIT OP TOEGEPAST WERD: "Key Standardisation" (DES).
"""
from Crypto.Cipher import DES, AES


def try_des_candidates(ciphertext: bytes, candidates: list[bytes]):
    for k in candidates:
        if len(k) != 8:
            continue
        try:
            pt = DES.new(k, DES.MODE_ECB).decrypt(ciphertext)
            if b"cns{" in pt or pt.isascii():
                print("Kandidaat sleutel:", k, "-> plaintext:", pt)
        except Exception:
            continue


def bruteforce_suffix(ciphertext: bytes, prefix: bytes, suffix_len: int,
                       alphabet: str, cipher="DES"):
    """
    Bruteforce de laatste 'suffix_len' tekens van een sleutel, met een vaste
    'prefix' ervoor. Werkt enkel praktisch als len(alphabet)**suffix_len klein is
    (bv. 2 onbekende tekens uit 62 mogelijke -> 3844 pogingen, triviaal snel).
    """
    import itertools
    for combo in itertools.product(alphabet, repeat=suffix_len):
        candidate = prefix + "".join(combo).encode()
        if cipher == "DES" and len(candidate) != 8:
            continue
        if cipher == "AES" and len(candidate) not in (16, 24, 32):
            continue
        try:
            if cipher == "DES":
                pt = DES.new(candidate, DES.MODE_ECB).decrypt(ciphertext)
            else:
                pt = AES.new(candidate, AES.MODE_ECB).decrypt(ciphertext)
            if b"cns{" in pt:
                print("GEVONDEN! sleutel =", candidate, "plaintext =", pt)
                return candidate, pt
        except Exception:
            continue
    print("Niets gevonden binnen dit bereik.")
    return None, None


if __name__ == "__main__":
    # TODO: vul de echte ciphertext in
    ciphertext = bytes.fromhex(
        "74eb40cf03b84d0bc4cd2c6e0fe97fb4e70546d3e09c530d35b344e530351bac"
    )

    # Stap 1: voor de hand liggende volledige sleutels proberen
    namespace = b"IOTDEV"   # TODO: pas aan
    candidates = [
        namespace + b"\x00" * (8 - len(namespace)),
        b"\x00" * (8 - len(namespace)) + namespace,
        (namespace * 2)[:8],
        namespace.lower() + b"\x00" * (8 - len(namespace)),
    ]
    try_des_candidates(ciphertext, candidates)

    # Stap 2: als dat niks gaf, probeer de laatste 2 tekens te bruteforcen
    alphabet = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    bruteforce_suffix(ciphertext, prefix=namespace, suffix_len=8 - len(namespace),
                       alphabet=alphabet, cipher="DES")
