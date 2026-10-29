"""
HASH LENGTH-EXTENSION AANVAL
================================
WANNEER GEBRUIKEN?
  - Een MAC is geconstrueerd als hash(secret || message) (GEEN echte HMAC!)
    met MD5, SHA-1 of SHA-256 (Merkle-Damgard-constructies zijn hiervoor
    kwetsbaar; SHA-3/BLAKE2 NIET).
  - Je kent hash(secret||message) EN het bericht 'message' zelf, maar NIET
    de secret -- en je wil data ACHTERAAN toevoegen met een nieuwe, geldige hash.

VEREIST (installeer dit VOORAF, op voorhand getest -- dit vraagt een build-stap,
dus doe dit thuis en neem de code/installatie mee, reken niet op internet
tijdens de sessie zelf):
    pip install hashpumpy --break-system-packages
(LET OP: "hlextend" bestaat NIET meer op PyPI -- de juiste, beschikbare
library heet "hashpumpy", een Python-wrapper rond de klassieke HashPump
C-tool. Test dit dus vooraf thuis!)

PRINCIPE:
  Merkle-Damgard hashes verwerken data in blokken en hun output IS gewoon
  de interne state op dat moment. Als je de hash kent, ken je dus de
  interne state, en kan je --zonder de secret te kennen-- "verdergaan"
  met hashen alsof je de secret + message + padding al had verwerkt.

ALS hashpumpy NIET BESCHIKBAAR IS tijdens de sessie (geen internet/build-
tools): zoek dan de CLI-tool "hashpump" op het systeem, of val terug op de
online uitleg van het algoritme (Wikipedia: "Length extension attack") en
implementeer de padding + state-hergebruik manueel -- dat is aanzienlijk
meer werk, dus test hashpumpy zeker vooraf!
"""
try:
    import hashpumpy
    HASHPUMPY_AVAILABLE = True
except ImportError:
    HASHPUMPY_AVAILABLE = False


def length_extend(known_mac_hex: str, known_message: bytes,
                   data_to_append: bytes, secret_length_guess: int,
                   algorithm: str = "sha256"):
    """
    known_mac_hex: de hash/MAC die je al kent (hex-string)
    known_message: het bericht zoals JIJ het kent (zonder de geheime prefix)
    data_to_append: wat je achteraan wil plakken (bv. b";admin=true")
    secret_length_guess: GOK voor de lengte van de onbekende secret (in bytes)
    algorithm: 'md5', 'sha1', of 'sha256' (moet overeenkomen met de server)

    Returns: (nieuwe_mac_hex, nieuw_bericht_bytes_met_padding_en_toevoeging)
    """
    new_mac, new_message = hashpumpy.hashpump(
        known_mac_hex, known_message, data_to_append, secret_length_guess
    )
    return new_mac, new_message


if __name__ == "__main__":
    if not HASHPUMPY_AVAILABLE:
        print("[!] hashpumpy is niet geinstalleerd. Installeer dit VOORAF thuis met:")
        print("    pip install hashpumpy --break-system-packages")
        raise SystemExit(1)

    # TODO: vul de echte waarden in
    known_mac = "originele_mac_hex_hier"
    known_message = b"user=guest&role=user"
    data_to_append = b"&role=admin"

    print("Probeer verschillende secret-lengtes (meestal 1 t.e.m. 32 of 64 bytes):")
    for guess_len in range(1, 33):
        try:
            new_mac, new_message = length_extend(
                known_mac, known_message, data_to_append, guess_len, algorithm="sha256"
            )
            print(f"secret_len={guess_len}: nieuwe MAC={new_mac}  bericht(hex)={new_message.hex()}")
            # TODO: test dit effectief tegen de server, en kijk welke lengte 'geldig' wordt bevonden
        except Exception as e:
            print(f"secret_len={guess_len}: fout ({e})")
