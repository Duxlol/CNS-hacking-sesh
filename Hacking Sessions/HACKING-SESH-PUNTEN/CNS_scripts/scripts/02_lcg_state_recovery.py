"""
ZWAKKE PRNG / LCG STATE RECOVERY
=================================
WANNEER GEBRUIKEN?
  - De cipher gebruikt een CUSTOM/zelfgeschreven keystream-generator i.p.v.
    een cryptografisch veilige RNG (bv. een Linear Congruential Generator:
    next_state = (A*state + C) mod M), en toont maar een DEEL van de interne
    state als keystream-byte (bv. "(state >> 16) & 0xff").
  - Je hebt via known-plaintext al een paar keystream-bytes (zie script 01),
    maar het bericht dat je wil kraken is LANGER dan wat je al weet.

PRINCIPE:
  Brute-force enkel de bits van de state die je ECHT niet kent (vaak is dat
  minder dan de volledige state-grootte, omdat sommige bits de zichtbare
  output helemaal niet beinvloeden -- reken dit na voor jouw specifieke LCG!).
  Verifieer elke kandidaat tegen de volgende bekende keystream-bytes, met
  vroege afbreking (break) zodra 1 byte niet klopt -> heel snel in de praktijk.

VOORBEELD WAAR DIT OP TOEGEPAST WERD: "Replanting".
"""

# ---- VUL HIER DE ECHTE LCG-PARAMETERS IN (uit het gegeven cipher.py) ------
A = 1103515245
C = 12345
M = 2 ** 31


def next_state(state: int) -> int:
    return (A * state + C) % M


def keystream_byte(state: int) -> int:
    """Pas aan naar hoe JOUW cipher een byte uit de state haalt."""
    return (state >> 16) & 0xff
# -----------------------------------------------------------------------------


def recover_state(known_keystream: bytes, unknown_low_bits: int = 16,
                   unknown_high_bits: int = 0) -> int | None:
    """
    Zoekt de interne state die, na next_state(), de eerste byte van
    'known_keystream' produceert, en waarvan alle VOLGENDE states ook
    matchen met de rest van known_keystream.

    unknown_low_bits  : hoeveel LAGE bits van de state je moet bruteforcen
    unknown_high_bits : hoeveel HOGE bits je moet bruteforcen (vaak 0, want
                         die beinvloeden de zichtbare byte vaak niet -- TEST dit!)

    Pas dit aan je eigen keystream_byte()-formule aan: reken manueel na welk
    deel van de 'state' zichtbaar is, en bruteforce enkel de rest.
    """
    target0 = known_keystream[0]

    for high in range(1 << unknown_high_bits):
        for low in range(1 << unknown_low_bits):
            # Pas deze samenstelling aan je eigen bit-indeling aan!
            s = (high << 24) | (target0 << 16) | low
            if s >= M:
                continue
            state = s
            ok = True
            for i in range(1, len(known_keystream)):
                state = next_state(state)
                if keystream_byte(state) != known_keystream[i]:
                    ok = False
                    break
            if ok:
                return s
    return None


def extend_keystream(state_after_byte0: int, total_length: int) -> bytes:
    """Genereer meer keystream-bytes, verdergaand vanaf de gevonden state."""
    out = bytearray()
    state = state_after_byte0
    out.append(keystream_byte(state))
    for _ in range(1, total_length):
        state = next_state(state)
        out.append(keystream_byte(state))
    return bytes(out)


if __name__ == "__main__":
    # TODO: vul de keystream-bytes in die je via known-plaintext kon berekenen
    known_keystream = bytes.fromhex("71471d94ec8993c744bcd8cfcb3cc5a66819a8e6ca")

    s1 = recover_state(known_keystream, unknown_low_bits=16, unknown_high_bits=0)
    print("Gevonden state:", s1)

    if s1 is not None:
        # TODO: hoeveel bytes heeft het geheime bericht?
        needed_length = 41
        full_keystream = extend_keystream(s1, needed_length)
        print("Volledige keystream (hex):", full_keystream.hex())

        # TODO: XOR met de echte geheime ciphertext
        secret_ct = bytes.fromhex("12296eef9eece6b42dd2bf90aa63b6d21a7cc98b95c78b4b01d833d628a941b82fb65176b4ed3c3f64")
        flag = bytes(c ^ k for c, k in zip(secret_ct, full_keystream))
        print("FLAG:", flag)
