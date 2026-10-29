"""
BIRTHDAY-ATTACK OP EEN AFGEKAPTE HASH (collision zoeken)
=============================================================
WANNEER GEBRUIKEN?
  - Een server berekent een hash/fingerprint maar slaat maar een paar
    bytes ervan op (hint: "we don't have enough space/money to store the
    full fingerprint"). Zo'n afgekapte hash is zwak tegen botsingen.

WAAROM WERKT DIT?
  Door de verjaardagsparadox vind je met maar ~2^(n/2) pogingen een
  collision in een n-bit hash, i.p.v. 2^n. Bij 32 bits (8 hex-tekens):
  slechts ~65.536 pogingen nodig, een kwestie van seconden.

VOORBEELD WAAR DIT OP TOEGEPAST WERD: "Secure Bank 2".
"""
import hashlib
import json
import random
import string


def canonicalize(payment: dict) -> bytes:
    """TODO: pas aan naar de EXACTE canonicalize-functie uit de opgave."""
    return json.dumps(
        payment, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


def random_field(length: int = 10) -> str:
    return "".join(random.choices(string.ascii_lowercase, k=length))


def find_collision(base_record: dict, varying_field: str,
                    hash_func=hashlib.sha256, digest_bytes: int = 4,
                    max_attempts: int = 10_000_000):
    """
    Genereert records die enkel verschillen in 'varying_field' (bv.
    "reference"), tot er twee met dezelfde afgekapte hash gevonden zijn.

    LET OP: houd alle andere velden (zoals een timestamp) CONSTANT tussen
    de twee pogingen, anders zijn je records "toevallig" verschillend op
    een manier die niets met de hash-collision te maken heeft!
    """
    seen = {}
    for attempt in range(max_attempts):
        record = base_record.copy()
        record[varying_field] = random_field()
        fp = hash_func(canonicalize(record)).digest()[:digest_bytes]

        if fp in seen and seen[fp] != record:
            print(f"[+] Collision gevonden na {attempt} pogingen!")
            print(f"    Fingerprint: {fp.hex()}")
            return seen[fp], record

        seen[fp] = record

        if attempt % 100_000 == 0 and attempt > 0:
            print(f"[*] {attempt} pogingen gedaan...")

    raise RuntimeError("Geen collision gevonden binnen max_attempts")


if __name__ == "__main__":
    # TODO: pas aan naar het exacte formaat/velden van de opgave
    base = {
        "from_account": "SIM-111",
        "to_account": "SIM-222",
        "amount": 10,
        "currency": "EUR",
        "timestamp": "2026-10-28T12:00:00+00:00",   # CONSTANT houden!
    }

    # TODO: pas digest_bytes aan op basis van de ECHT geobserveerde fingerprint-lengte
    #       van de server (lengte van de hex-string / 2)
    rec1, rec2 = find_collision(base, varying_field="reference", digest_bytes=4)

    print("\n--- Record 1 ---")
    print(json.dumps(rec1, indent=2))
    print("\n--- Record 2 ---")
    print(json.dumps(rec2, indent=2))

    # Stuur ze pas NU naar de server (eerst rekenen, dan versturen):
    # import socket
    # with socket.create_connection((HOST, PORT)) as s:
    #     s.recv(4096)  # banner
    #     s.sendall((json.dumps(rec1) + "\n").encode()); s.recv(4096)
    #     s.sendall((json.dumps(rec2) + "\n").encode())
    #     print(s.recv(4096).decode(errors="replace"))
