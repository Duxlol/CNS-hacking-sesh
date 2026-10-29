"""
CBC PADDING ORACLE AANVAL
============================
WANNEER GEBRUIKEN?
  - CBC-mode, EN de server/applicatie laat je op de een of andere manier
    weten of de PADDING van een ontsleuteld bericht geldig was of niet
    (expliciete foutmelding "invalid padding", of een merkbaar verschil
    in gedrag/timing/statuscode).

PRINCIPE (kort):
  PKCS#7-padding: de laatste bytes van het plaintext geven aan hoeveel
  paddingbytes er zijn (bv. laatste byte 0x04 -> de laatste 4 bytes moeten
  ALLEMAAL 0x04 zijn). Door de VOORLAATSTE ciphertext-blok byte per byte
  te wijzigen en te kijken of de server "padding OK" zegt, kan je ELKE
  byte van het plaintext achterhalen -- zonder de sleutel te kennen.

  We werken per blok, van de LAATSTE byte naar de EERSTE.

BELANGRIJK: je moet zelf 'padding_oracle()' hieronder invullen met de
ECHTE manier waarop je kan zien of de server de padding goedkeurt
(bv. HTTP 200 vs 400, of een specifieke foutmelding-string).
"""


def padding_oracle(iv_or_prev_block: bytes, target_block: bytes) -> bool:
    """
    TODO: stuur (iv_or_prev_block + target_block) naar de server/oracle en
    return True als de server zegt "padding is geldig", anders False.
    Dit is het ENIGE stuk dat je zelf moet aanpassen aan de specifieke opgave.
    """
    raise NotImplementedError("Vul dit in met een echte call naar de server/oracle")


def decrypt_block(prev_block: bytes, target_block: bytes, block_size: int = 16) -> bytes:
    """Ontsleutel 1 blok (16 bytes) puur via het padding-oracle, geen sleutel nodig."""
    intermediate = bytearray(block_size)   # AES_decrypt(key, target_block) zonder XOR met prev_block
    plaintext = bytearray(block_size)

    for pad_val in range(1, block_size + 1):
        pos = block_size - pad_val
        fake_prev = bytearray(block_size)
        # zet de al gekende bytes zo dat ze matchen met de huidige pad_val
        for i in range(pos + 1, block_size):
            fake_prev[i] = intermediate[i] ^ pad_val

        found = False
        for guess in range(256):
            fake_prev[pos] = guess
            if padding_oracle(bytes(fake_prev), target_block):
                # Let op: bij pos == block_size-1 (pad_val==1) kan een VALSE
                # positive optreden als het echte plaintext toevallig op
                # 0x02 0x02 eindigt. Dubbelcheck in dat geval desnoods door
                # fake_prev[pos-1] met 1 te verhogen en opnieuw te testen.
                intermediate[pos] = guess ^ pad_val
                plaintext[pos] = intermediate[pos] ^ prev_block[pos]
                found = True
                break
        if not found:
            raise RuntimeError(f"Geen geldige byte gevonden op positie {pos}")

    return bytes(plaintext)


def decrypt_ciphertext(iv: bytes, ciphertext: bytes, block_size: int = 16) -> bytes:
    """Decrypt een volledige ciphertext (IV + blokken) puur via het oracle."""
    blocks = [iv] + [ciphertext[i:i + block_size]
                      for i in range(0, len(ciphertext), block_size)]
    plaintext = b""
    for i in range(1, len(blocks)):
        plaintext += decrypt_block(blocks[i - 1], blocks[i], block_size)
    return plaintext


if __name__ == "__main__":
    print("Vul eerst padding_oracle() in met een echte call naar de server,")
    print("vul daarna IV en ciphertext in en roep decrypt_ciphertext() aan.")
    # iv = bytes.fromhex("...")
    # ciphertext = bytes.fromhex("...")
    # print(decrypt_ciphertext(iv, ciphertext))
