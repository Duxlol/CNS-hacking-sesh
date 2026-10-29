"""
MEET-IN-THE-MIDDLE AANVAL OP DUBBELE ENCRYPTIE
==================================================
WANNEER GEBRUIKEN?
  - C = Enc(K2, Enc(K1, P))  -- data is TWEE keer versleuteld met twee
    verschillende (kleine) sleutels K1 en K2.
  - Elke sleutel apart heeft een KLEINE sleutelruimte (bv. 2^20), zodat
    2 * 2^20 haalbaar is, ook al zou 2^20 * 2^20 (brute force van de
    combinatie) te traag zijn.

PRINCIPE:
  Enc(K1, P) = Dec(K2, C)
  Links hangt enkel van K1 af, rechts enkel van K2 -- ze zijn losgekoppeld!
  1. Bereken Enc(K1, P) voor ALLE K1 -> stop in een hashtabel (dict).
  2. Bereken Dec(K2, C) voor ALLE K2 -> zoek elk resultaat op in de tabel.
  3. Bij een match heb je het (K1, K2)-paar gevonden.

VEREIST: een bekend (plaintext-blok, ciphertext-blok)-paar van HETZELFDE
blok (16 bytes voor AES). Bestandsheaders zijn hiervoor ideaal:
  BMP:  b"BM" + bestandsgrootte (4 bytes, little-endian) + ...
  PNG:  b"\\x89PNG\\r\\n\\x1a\\n"
  JPEG: b"\\xFF\\xD8\\xFF"
  ZIP:  b"PK\\x03\\x04"
  PDF:  b"%PDF-"

VOORBEELD WAAR DIT OP TOEGEPAST WERD: "AES 2 demo version".
"""
from Crypto.Cipher import AES


def make_key(k_small: int, key_len: int = 16) -> bytes:
    """Pas dit aan het EXACTE sleutelformaat van de opgave aan!"""
    return k_small.to_bytes(3, "big") + b"\x00" * (key_len - 3)


def meet_in_the_middle(P: bytes, C: bytes, keyspace: int = 2 ** 20,
                        key_len: int = 16):
    """
    P: bekend 16-byte plaintext-blok
    C: het BIJBEHORENDE 16-byte ciphertext-blok (zelfde positie!)
    keyspace: hoeveel kandidaten voor elke deelsleutel (bv. 2**20)
    """
    assert len(P) == 16 and len(C) == 16, "blokken moeten exact 16 bytes zijn"

    print(f"Stap 1/2: tabel opbouwen voor {keyspace} K1-kandidaten...")
    table = {}
    for k1 in range(keyspace):
        key1 = make_key(k1, key_len)
        mid = AES.new(key1, AES.MODE_ECB).encrypt(P)
        table[mid] = k1

    print(f"Stap 2/2: {keyspace} K2-kandidaten testen...")
    for k2 in range(keyspace):
        key2 = make_key(k2, key_len)
        mid = AES.new(key2, AES.MODE_ECB).decrypt(C)
        if mid in table:
            k1 = table[mid]
            print(f"GEVONDEN! K1={k1} (0x{k1:x}), K2={k2} (0x{k2:x})")
            return k1, k2

    print("Geen match gevonden -- controleer volgorde (misschien Enc(K2,Enc(K1,P))")
    print("omgekeerd?), het sleutelformaat, of de mode (geen ECB?).")
    return None, None


if __name__ == "__main__":
    # TODO: vul het bekende plaintext-blok in (bv. eerste 16 bytes van een BMP-header)
    P = b"BM" + (1671).to_bytes(4, "little") + b"\x00" * 10   # VOORBEELD, pas aan!
    # TODO: vul het bijbehorende ciphertext-blok in (eerste 16 bytes van enc.bmp)
    C = bytes.fromhex("0123456789abcdef0123456789abcdef")      # TODO

    k1, k2 = meet_in_the_middle(P, C, keyspace=2 ** 20, key_len=16)

    if k1 is not None:
        # Nu kan je het VOLLEDIGE bestand ontsleutelen:
        # with open("enc.bmp", "rb") as f:
        #     full_ct = f.read()
        # mid = AES.new(make_key(k1), AES.MODE_ECB).decrypt(full_ct)
        # plaintext = AES.new(make_key(k2), AES.MODE_ECB).decrypt(mid)
        pass
