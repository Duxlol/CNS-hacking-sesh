"""
CUSTOM ROTOR-/ENIGMA-ACHTIGE CIJFERS KRAKEN
===============================================
WANNEER GEBRUIKEN?
  - De opgave beschrijft een EIGEN, volledig custom "machine" (meestal in
    woorden, geen bestaande cipher) met rotoren/substitutie-alfabetten die
    na elke letter ROTEREN, en waarbij de rotatie van een volgende rotor
    afhangt van wanneer de vorige een volledige cyclus gemaakt heeft
    (klassiek Enigma-odometer-mechanisme).
  - Dit soort opgave kan je NERGENS opzoeken -- de machine is uniek voor
    deze opgave. Je MOET 'm zelf simuleren en programmeren.

ALGEMENE SLEUTEL TOT DIT SOORT OPGAVEN:
  Bij een "zuivere" rotor-machine (zonder reflector/plugboard) hangt de
  rotatie van elke rotor ENKEL af van HOEVEEL letters er al verwerkt zijn
  -- NIET van de inhoud van het bericht zelf. Dat betekent dat je de
  volledige reeks rotor-standen voor ELKE positie kan voorberekenen, los
  van wat het plaintext/ciphertext is. Elke stap is dan gewoon een
  SUBSTITUTIE (permutatie) die je met .index() kan omkeren.

  STAPPENPLAN:
  1. Simuleer de machine FORWARD (plaintext -> ciphertext) exact zoals
     de opgave het beschrijft -- dit test je begrip van de rotatieregels.
  2. Voor DECRYPTIE: loop de pijplijn in OMGEKEERDE volgorde per letter,
     en gebruik .index(letter) i.p.v. rotor[index] om elke stap terug
     te draaien (een substitutie-rotor is altijd een bijectie/permutatie,
     dus elke stap is sowieso omkeerbaar).
  3. Niet-letter-tekens (spaties, "-", "{", "}", ...): meestal gaan die
     NIET door de rotoren en laten ze de rotor-staat ONGEMOEID -- maar
     TEST dit (zie VARIANT A hieronder als dat niet klopt).

BEVESTIGD GEWERKT VOORBEELD: "My First Enigma Machine"
  3 rotoren, Rotor 1 roteert elke letter, Rotor 2 roteert als Rotor 1 een
  volledige cyclus (26 letters) gemaakt heeft, Rotor 3 roteert als Rotor 2
  een volledige cyclus gemaakt heeft. Geen reflector (1 richting: R1->R2->R3).
"""


def rotate(s: str) -> str:
    """Eerste karakter naar achteren verplaatsen (zoals in de opgave beschreven)."""
    return s[1:] + s[0]


def enigma_decrypt(ciphertext: str, rotor_inits: list[str],
                    advance_every: list[int] | None = None) -> str:
    """
    rotor_inits   : lijst van start-alfabetten, bv. [rotor1, rotor2, rotor3]
    advance_every : hoe vaak de VORIGE rotor moet roteren voor DEZE rotor
                    1 keer roteert (bij klassiek Enigma-gedrag altijd 26,
                    want elk rotor-alfabet heeft 26 letters -- pas aan als
                    de opgave een ANDER getal specificeert!)

    Gaat er van uit: rotoren roteren puur op basis van POSITIE (niet van
    de data), en enkel LETTERS (A-Z) tellen mee / worden verwerkt.
    """
    n_rotors = len(rotor_inits)
    if advance_every is None:
        advance_every = [26] * n_rotors   # standaard: elke rotor heeft 26 posities

    states = list(rotor_inits)
    counters = [0] * n_rotors   # hoe vaak elke rotor al geroteerd heeft

    out = []
    for ch in ciphertext:
        if not ch.isalpha():
            out.append(ch)   # niet-letters: ongewijzigd doorgeven, GEEN rotatie
            continue

        # --- Stap 1: roteer de rotoren (odometer-mechanisme) -----------
        # Rotor 0 (eerste) roteert ALTIJD bij elke letter.
        states[0] = rotate(states[0])
        counters[0] += 1

        for i in range(1, n_rotors):
            if counters[i - 1] % advance_every[i - 1] == 0:
                states[i] = rotate(states[i])
                counters[i] += 1
            else:
                break   # als rotor i niet roteert, roteert i+1 zeker ook niet

        # --- Stap 2: loop de substitutie-pijplijn OMGEKEERD -------------
        # Forward was: idx -> rotor[0][idx] -> rotor[1][...] -> ... -> output
        # Dus decrypt: begin bij de LAATSTE rotor, werk terug naar de eerste.
        idx = ord(ch) - ord('A')
        for i in range(n_rotors - 1, -1, -1):
            letter_at_idx = chr(idx + ord('A'))
            idx = states[i].index(letter_at_idx)
        out.append(chr(idx + ord('A')))

    return "".join(out)


def enigma_encrypt(plaintext: str, rotor_inits: list[str],
                    advance_every: list[int] | None = None) -> str:
    """Forward-richting, vooral nuttig om je begrip te TESTEN/verifieren."""
    n_rotors = len(rotor_inits)
    if advance_every is None:
        advance_every = [26] * n_rotors

    states = list(rotor_inits)
    counters = [0] * n_rotors

    out = []
    for ch in plaintext:
        if not ch.isalpha():
            out.append(ch)
            continue

        states[0] = rotate(states[0])
        counters[0] += 1
        for i in range(1, n_rotors):
            if counters[i - 1] % advance_every[i - 1] == 0:
                states[i] = rotate(states[i])
                counters[i] += 1
            else:
                break

        idx = ord(ch) - ord('A')
        for i in range(n_rotors):
            idx = ord(states[i][idx]) - ord('A')
        out.append(chr(idx + ord('A')))

    return "".join(out)


# ---------------------------------------------------------------------------
# VARIANTEN DIE DE PROF OOK KAN GEVEN -- lees de opgavetekst GOED en pas aan:
# ---------------------------------------------------------------------------
# VARIANT A: niet-letters tellen WEL mee voor de rotatie (dus "-" en "{"
#            laten de rotor ook 1 stap draaien, ook al worden ze zelf niet
#            vervangen). Test dit als je resultaat niet leesbaar is: haal
#            de "if not ch.isalpha(): continue"-achtige skip weg bij het
#            tellen, maar behoud 'm bij de substitutie zelf.
#
# VARIANT B: een REFLECTOR (zoals de ECHTE Enigma) -- het signaal gaat
#            heen EN terug door de rotoren (R1->R2->R3->reflector->R3->R2->R1).
#            Een reflector is typisch een zelf-inverse permutatie (als
#            reflector[x]=y dan reflector[y]=x, en reflector[x]!=x).
#            Implementatie: na de laatste rotor, pas de reflector toe,
#            loop dan de rotoren in omgekeerde volgorde NOGMAALS (met
#            dezelfde, AL GEROTEERDE staat) terug naar voren.
#
# VARIANT C: de rotatie van rotor i+1 hangt af van de rotor i in een
#            ANDER aantal stappen dan 26 (bv. elke rotor heeft een eigen
#            "notch"-positie, niet noodzakelijk na een volledige cyclus).
#            Lees de opgave: als er een specifiek getal/letter genoemd
#            wordt waarop een rotor "doorschakelt", pas advance_every aan.
#
# VARIANT D: een PLUGBOARD (extra vaste letter-voor-letter swap VOOR en
#            NA de rotoren, bv. A<->Q, B<->W, ...). Implementeer dit als
#            een simpele dict die je toepast voor je de rotoren ingaat en
#            nadat je eruit komt.
#
# VARIANT E: rotoren STARTEN niet op positie 0 maar op een gegeven
#            letter/index (bv. "rotors started at 5, 2, 9"). Roteer de
#            rotor_inits-string VOORAF dat aantal keer voor je begint:
#            state = rotor_init
#            for _ in range(start_offset): state = rotate(state)
# ---------------------------------------------------------------------------


if __name__ == "__main__":
    rotor1 = "MACHINEBDFGJKLOPQRSTUVWXYZ"
    rotor2 = "ORBITACDEFGHJKLMNPQSUVWXYZ"
    rotor3 = "CIPHERABDFGJKLMNOQSTUVWXYZ"

    ciphertext = "HKV{BSBU-B-SJYZNNB-DNFW-IXH-YTA-RPL-RTXOLWFQ}"
    plaintext = enigma_decrypt(ciphertext, [rotor1, rotor2, rotor3])
    print("Ontsleuteld:", plaintext)

    # Sanity check: encrypt het resultaat terug, moet weer de ciphertext geven
    check = enigma_encrypt(plaintext, [rotor1, rotor2, rotor3])
    assert check == ciphertext, f"MISMATCH: {check} != {ciphertext}"
    print("Controle geslaagd: encrypt(decrypt(ciphertext)) == ciphertext")
