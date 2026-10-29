"""
BIT-FLIPPING / MALLEABILITY AANVAL (encryptie zonder MAC)
===========================================================
WANNEER GEBRUIKEN?
  - Het systeem versleutelt met een stream cipher (of AES-CTR/OFB) ZONDER
    integriteitscontrole (geen HMAC/signature/checksum op de ciphertext).
  - De opgave vraagt om een BESTAANDE actie te wijzigen (bedrag, rol, ...),
    niet om een geheim te ontsleutelen.

PRINCIPE:
  ciphertext = plaintext XOR keystream
  Als je het ORIGINELE plaintext kent (bv. omdat je het al succesvol liet
  verwerken, of omdat je het formaat exact kent), kan je de keystream
  berekenen EN gebruiken om een NIEUW plaintext van dezelfde lengte te
  versleutelen -- zonder ooit de sleutel te kennen.

  keystream        = ciphertext XOR known_plaintext
  new_ciphertext    = keystream XOR new_desired_plaintext

BELANGRIJK:
  - new_desired_plaintext moet EXACT dezelfde lengte hebben als known_plaintext.
  - De keystream hangt af van de NONCE. Gebruik 'm binnen dezelfde sessie/
    nonce -- verbind niet opnieuw tussen het berekenen en het versturen!

VOORBEELD WAAR DIT OP TOEGEPAST WERD: "Secure Bank 1" (Salsa20 money transfer).
"""
import socket
import re

HOST = "cns-test.idlab.uantwerpen.be"   # TODO
PORT = 50001                             # TODO


def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def get_banner_and_ciphertext(sock: socket.socket) -> tuple[str, bytes]:
    """Leest de greeting/banner en haalt de hex-blob eruit (pas regex aan!)."""
    data = b""
    while b"\n\n" not in data and len(data) < 8192:   # pas stopconditie aan
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
    text = data.decode(errors="replace")
    m = re.search(r"([0-9a-f]{90,})", text)   # pas minimale hex-lengte aan
    ct_hex = m.group(1) if m else None
    return text, (bytes.fromhex(ct_hex) if ct_hex else b"")


if __name__ == "__main__":
    # TODO: pas aan op basis van het exacte, bevestigde JSON-formaat van de server
    # (grootte-match EERST handmatig uitrekenen zoals we deden: lengte ciphertext
    #  min nonce-lengte moet exact overeenkomen met len(known_plaintext)!)
    KNOWN_PLAINTEXT = b'{"from":"alice","to":"bob","amount":"000010"}'
    NEW_PLAINTEXT   = b'{"from":"alice","to":"bob","amount":"000000"}'
    assert len(KNOWN_PLAINTEXT) == len(NEW_PLAINTEXT), "lengtes moeten gelijk zijn!"

    NONCE_LEN = 8   # TODO: hoeveel bytes is de nonce (vaak 8 voor Salsa20, 16 voor AES)?

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        greeting, raw = get_banner_and_ciphertext(s)
        print(greeting)

        nonce, ciphertext = raw[:NONCE_LEN], raw[NONCE_LEN:]
        assert len(ciphertext) == len(KNOWN_PLAINTEXT), \
            f"lengte klopt niet: ciphertext={len(ciphertext)}, verwacht={len(KNOWN_PLAINTEXT)}"

        keystream = xor_bytes(ciphertext, KNOWN_PLAINTEXT)
        new_ciphertext = xor_bytes(keystream, NEW_PLAINTEXT)
        new_hex = (nonce + new_ciphertext).hex()

        s.sendall(new_hex.encode())
        print(s.recv(4096).decode(errors="replace"))
        print(s.recv(4096).decode(errors="replace"))
