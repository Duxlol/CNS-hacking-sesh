"""
BLOCK CIPHER MODE HERKENNEN (ECB vs CBC vs CTR/stream)
==========================================================
WANNEER GEBRUIKEN?
  - Je weet niet zeker welke mode gebruikt is, en wil dat snel uitvinden
    aan de hand van de ciphertext zelf (zonder broncode te zien).

HERKENNINGSSIGNALEN (zie ook de cheatsheet §2.3):
  - Identieke 16-byte blokken herhaaldelijk in de ciphertext -> ECB
  - 1 byte wijzigen in ciphertext -> 1 HEEL blok verandert bij decryptie,
    en het volgende blok krijgt exact diezelfde bit-flip -> CBC
  - 1 byte wijzigen in ciphertext -> enkel DAT ene byte verandert bij
    decryptie -> stream cipher / CTR / OFB (malleable, zie script 03)
"""
from collections import Counter


def detect_ecb(ciphertext: bytes, block_size: int = 16) -> bool:
    """True als er herhaalde blokken zijn -> sterk signaal voor ECB."""
    blocks = [ciphertext[i:i + block_size]
              for i in range(0, len(ciphertext) - block_size + 1, block_size)]
    counts = Counter(blocks)
    repeated = {b: c for b, c in counts.items() if c > 1}
    if repeated:
        print(f"[!] {len(repeated)} blok(ken) komen meermaals voor -> waarschijnlijk ECB")
        for b, c in repeated.items():
            print(f"    {b.hex()} komt {c}x voor")
        return True
    print("Geen herhaalde blokken gevonden (kan nog steeds ECB zijn bij korte data)")
    return False


def probe_mode_with_oracle(encrypt_oracle, block_size: int = 16):
    """
    Als je zelf plaintext kan laten versleutelen (chosen-plaintext oracle):
    stuur 2 identieke blokken achter elkaar. Bij ECB levert dit 2 identieke
    ciphertext-blokken op; bij CBC/CTR (normaal) niet.

    encrypt_oracle: functie die bytes plaintext aanneemt en bytes ciphertext
                    teruggeeft (bv. een wrapper rond een server-call).
    """
    probe = b"A" * block_size * 3
    ct = encrypt_oracle(probe)
    b1 = ct[0:block_size]
    b2 = ct[block_size:2 * block_size]
    if b1 == b2:
        print("ECB gedetecteerd (identieke plaintext-blokken -> identieke ciphertext-blokken)")
        return "ECB"
    print("Waarschijnlijk GEEN ECB (CBC/CTR/stream)")
    return "NOT_ECB"


if __name__ == "__main__":
    # TODO: vul de ciphertext in die je wil onderzoeken
    ct = bytes.fromhex("...")
    detect_ecb(ct, block_size=16)
