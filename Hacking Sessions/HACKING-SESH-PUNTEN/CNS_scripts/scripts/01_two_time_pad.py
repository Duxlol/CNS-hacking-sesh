"""
TWEE-KEER-PAD AANVAL (keystream/nonce hergebruik)
==================================================
WANNEER GEBRUIKEN?
  - Je hebt TWEE (of meer) berichten versleuteld met DEZELFDE keystream
    (zelfde seed bij een stream cipher, of zelfde nonce bij AES-CTR).
  - Van minstens EEN van die berichten ken je het plaintext.

WAAROM WERKT DIT?
  ciphertext = plaintext XOR keystream
  => keystream = ciphertext XOR plaintext   (reken dit om, XOR is omkeerbaar)
  Als bericht 2 dezelfde keystream gebruikt, kan je 'm direct hergebruiken:
  => plaintext_2 = ciphertext_2 XOR keystream

VOORBEELDEN WAAR DIT OP TOEGEPAST WERD: "Replanting", "Noncense" (AES-CTR nonce reuse).
"""

def xor_bytes(a: bytes, b: bytes) -> bytes:
    """XOR twee byte-reeksen. Resultaat heeft de lengte van de KORTSTE input."""
    return bytes(x ^ y for x, y in zip(a, b))


# ---- VUL HIER DE ECHTE WAARDEN IN -----------------------------------------
known_plaintext = b"STATUS: SERVER ONLINE"          # TODO: wat je al kent (string/bytes)
ciphertext_known = bytes.fromhex("22135cc0b9daa9e717f98a998e6ee5e92655e1a88f")   # TODO
ciphertext_secret = bytes.fromhex("12296eef9eece6b42dd2bf90aa63b6d21a7cc98b95c78b4b01d833d628a941b82fb65176b4ed3c3f64")  # TODO
# -----------------------------------------------------------------------------

keystream = xor_bytes(ciphertext_known, known_plaintext)
print("Herwonnen keystream (hex):", keystream.hex())
print("Keystream lengte:", len(keystream), "bytes")

# Pas de keystream toe op het geheime bericht (enkel zo ver als de keystream reikt!)
decrypted = xor_bytes(ciphertext_secret, keystream)
print("Ontsleuteld (zo ver mogelijk):", decrypted)

if len(ciphertext_secret) > len(keystream):
    print(f"\n[!] LET OP: het geheime bericht is {len(ciphertext_secret)} bytes,")
    print(f"    maar je kent maar {len(keystream)} keystream-bytes.")
    print("    Je moet de keystream VERLENGEN (zie 02_lcg_state_recovery.py voor")
    print("    een custom-LCG-voorbeeld, of herbereken de AES-CTR-counter verder).")
