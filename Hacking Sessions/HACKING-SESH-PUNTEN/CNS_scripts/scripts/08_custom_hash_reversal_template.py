"""
ZELFGESCHREVEN ("HOME-MADE") HASH OMKEREN
=============================================
WANNEER GEBRUIKEN?
  - Een eigen hash-functie, opgebouwd uit XOR / bit-rotatie (rol/ror) /
    array-manipulatie -- GEEN echte SHA/MD5 uit een standaardbibliotheek.

AANPAK (stappenplan, zie ook onze uitgewerkte uitleg):
  1. Lijst alle operaties binnen EEN ronde op, IN VOLGORDE.
  2. Keer de RONDEVOLGORDE om (laatste ronde eerst: range(N-1, -1, -1)).
  3. Keer BINNEN elke ronde de VOLGORDE van de stappen om ("jas-trui-principe":
     laatst aangedaan = eerst uitgedaan).
  4. Vervang elke operatie door haar inverse:
       - XOR met constante        -> XOR met dezelfde constante (eigen inverse)
       - rol(x, n)                -> ror(x, n) (en omgekeerd)
       - lijst-rotatie links      -> lijst-rotatie rechts (en omgekeerd)
       - lopende/ketting-XOR      -> loop van HOOG naar LAAG i.p.v. laag naar hoog
         (state[i] ^= state[i-1], voorwaarts = prefix-XOR; achterwaarts = inverse)

Dit bestand bevat het VOLLEDIG UITGEWERKTE voorbeeld voor "Better Hash" als
referentie-template. Pas de forward-functie (ter controle/vergelijking) en
de inverse-functie aan naar de NIEUWE hash-functie die je in de opgave krijgt.
"""


def rol(x: int, n: int) -> int:
    return ((x << n) | (x >> (8 - n))) & 0xff


def ror(x: int, n: int) -> int:
    return ((x >> n) | (x << (8 - n))) & 0xff


# ---- FORWARD (ter referentie/controle -- dit stond in de opgave zelf) -----
def forward_hash(msg: bytes) -> str:
    state = bytearray(msg)
    for rnd in range(8):
        for i in range(len(state)):
            state[i] ^= (rnd * 41 + i * 17) & 0xff
            state[i] = rol(state[i], (rnd + i) & 7)
        for i in range(1, len(state)):
            state[i] ^= state[i - 1]
        state = state[1:] + state[:1]
    return state.hex()


# ---- INVERSE (dit moet je zelf opbouwen per nieuwe hash-functie) ----------
def inverse_hash(hash_hex: str) -> bytes:
    state = bytearray.fromhex(hash_hex)
    L = len(state)

    for rnd in range(7, -1, -1):                      # ronden omgekeerd
        state = state[-1:] + state[:-1]                # stap 3 omgekeerd (lijst-rotatie)

        for i in range(L - 1, 0, -1):                  # stap 2 omgekeerd (ketting-XOR, hoog->laag)
            state[i] ^= state[i - 1]

        for i in range(L):                              # stap 1 omgekeerd (ror dan XOR)
            n = (rnd + i) & 7
            state[i] = ror(state[i], n)
            state[i] ^= (rnd * 41 + i * 17) & 0xff

    return bytes(state)


if __name__ == "__main__":
    # Sanity check met het bekende voorbeeld:
    test_hash = "5f070b54361613bca31a123e95321cff154ba64f549bb34fdc7688f10efb569aed4ccbd6ba"
    result = inverse_hash(test_hash)
    print("Resultaat:", result)
    assert result == forward_hash(result).encode().hex()[:0] or True  # (zie forward check hieronder)
    assert bytes.fromhex(forward_hash(result)) == bytes.fromhex(test_hash)
    print("Controle geslaagd: forward_hash(resultaat) == originele hash")
