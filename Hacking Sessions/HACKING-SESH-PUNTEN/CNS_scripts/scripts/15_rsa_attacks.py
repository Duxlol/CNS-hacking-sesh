"""
RSA-AANVALLEN (verzameling)
===============================
WANNEER GEBRUIKEN?
  - Je krijgt publieke RSA-parameters (n, e) en een ciphertext c, en moet
    het plaintext m achterhalen ZONDER de privesleutel d te kennen op de
    normale manier (die zou immers onbreekbaar zijn bij een correcte
    implementatie -- dus er zit ALTIJD een specifieke zwakte in de opgave).

VEREIST: pip install sympy gmpy2 --break-system-packages
  (gmpy2 is optioneel maar veel sneller voor grote getallen; de code
   hieronder valt terug op pure Python als gmpy2 niet beschikbaar is)

VOLG DEZE VOLGORDE VAN TESTEN (zie ook cheatsheet §5.1):
  1. Zoek 'n' op in https://factordb.com -- vaak al bekend/gefactoriseerd!
  2. Is 'e' klein (bv. 3) en het bericht kort? -> cube_root_attack()
  3. Dezelfde 'n', twee verschillende 'e'? -> common_modulus_attack()
  4. 'p' en 'q' dicht bij elkaar? -> fermat_factorization()
  5. 'd' klein? -> wiener_attack()
  6. Niks van bovenstaand? -> probeer gewoon factoriseren met sympy.
"""
import math
from sympy import mod_inverse, isprime, factorint
from functools import reduce


# ---------------------------------------------------------------------------
# 1. CUBE-ROOT ATTACK (kleine e, kort bericht zodat m^e < n)
# ---------------------------------------------------------------------------
def integer_nth_root(x: int, n: int) -> int:
    """Geeft floor(x ** (1/n)) exact voor (hele) grote integers."""
    if x < 0:
        raise ValueError("x moet niet-negatief zijn")
    if x == 0:
        return 0
    high = 1
    while high ** n <= x:
        high *= 2
    low = high // 2
    while low < high:
        mid = (low + high + 1) // 2
        if mid ** n <= x:
            low = mid
        else:
            high = mid - 1
    return low


def cube_root_attack(c: int, e: int = 3):
    """Als m^e < n (geen modulo-wraparound), is m gewoon de e-de wortel van c."""
    m = integer_nth_root(c, e)
    if m ** e == c:
        return m
    print("Geen exacte wortel -- probeer Hastad's broadcast attack (meerdere ciphertexts nodig)")
    return None


def hastad_broadcast_attack(ciphertexts: list[int], moduli: list[int], e: int = 3):
    """
    Zelfde bericht naar e of meer ontvangers met verschillende n's, zelfde
    kleine e. Combineer via Chinese Reststelling (CRT), neem dan e-de wortel.
    """
    assert len(ciphertexts) >= e and len(moduli) >= e
    combined = crt(ciphertexts[:e], moduli[:e])
    N = reduce(lambda a, b: a * b, moduli[:e])
    m = integer_nth_root(combined % N, e)
    return m


def crt(residues: list[int], moduli: list[int]) -> int:
    """Chinese Reststelling: vind x zodat x = residues[i] mod moduli[i] voor elke i."""
    N = reduce(lambda a, b: a * b, moduli)
    total = 0
    for r_i, n_i in zip(residues, moduli):
        N_i = N // n_i
        total += r_i * mod_inverse(N_i, n_i) * N_i
    return total % N


# ---------------------------------------------------------------------------
# 2. COMMON MODULUS ATTACK (zelfde n, verschillende e1/e2, zelfde bericht)
# ---------------------------------------------------------------------------
def extended_gcd(a: int, b: int):
    if b == 0:
        return a, 1, 0
    g, x1, y1 = extended_gcd(b, a % b)
    return g, y1, x1 - (a // b) * y1


def common_modulus_attack(c1: int, e1: int, c2: int, e2: int, n: int):
    g, a, b = extended_gcd(e1, e2)
    assert g == 1, "e1 en e2 moeten coprime zijn"
    if a < 0:
        c1 = mod_inverse(c1, n)
        a = -a
    if b < 0:
        c2 = mod_inverse(c2, n)
        b = -b
    m = (pow(c1, a, n) * pow(c2, b, n)) % n
    return m


# ---------------------------------------------------------------------------
# 3. FERMAT-FACTORISATIE (p en q liggen dicht bij elkaar)
# ---------------------------------------------------------------------------
def fermat_factorization(n: int, max_iterations: int = 10_000_000):
    a = math.isqrt(n) + 1
    for _ in range(max_iterations):
        b2 = a * a - n
        b = math.isqrt(b2)
        if b * b == b2:
            p, q = a + b, a - b
            return p, q
        a += 1
    return None, None


# ---------------------------------------------------------------------------
# 4. WIENER'S ATTACK (kleine privesleutel d)
# ---------------------------------------------------------------------------
def continued_fraction(num: int, den: int):
    cf = []
    while den:
        cf.append(num // den)
        num, den = den, num % den
    return cf


def convergents(cf: list[int]):
    convs = []
    for i in range(len(cf)):
        num, den = cf[i], 1
        for j in range(i - 1, -1, -1):
            num, den = cf[j] * num + den, num
        convs.append((num, den))
    return convs


def wiener_attack(e: int, n: int):
    cf = continued_fraction(e, n)
    for k, d in convergents(cf):
        if k == 0:
            continue
        if (e * d - 1) % k != 0:
            continue
        phi = (e * d - 1) // k
        # los x^2 - (n - phi + 1)x + n = 0 op voor p, q
        b = n - phi + 1
        disc = b * b - 4 * n
        if disc < 0:
            continue
        sqrt_disc = math.isqrt(disc)
        if sqrt_disc * sqrt_disc != disc:
            continue
        p = (b + sqrt_disc) // 2
        q = (b - sqrt_disc) // 2
        if p * q == n:
            return d, p, q
    return None, None, None


# ---------------------------------------------------------------------------
# 5. ALGEMENE FACTORISATIE (laatste redmiddel voor kleine/kwetsbare n)
# ---------------------------------------------------------------------------
def factor_and_decrypt(n: int, e: int, c: int):
    print("Probeer te factoriseren met sympy (kan lang duren voor grote n)...")
    factors = factorint(n)   # enkel haalbaar voor kleine/kwetsbare n
    primes = list(factors.keys())
    if len(primes) != 2:
        print("Niet gelukt binnen een redelijke tijd -- probeer factordb.com")
        return None
    p, q = primes
    phi = (p - 1) * (q - 1)
    d = mod_inverse(e, phi)
    m = pow(c, d, n)
    return m


if __name__ == "__main__":
    # TODO: vul de echte RSA-parameters in en kies de juiste aanval
    n = 0  # TODO
    e = 3  # TODO
    c = 0  # TODO

    # Voorbeeld: cube root attack
    m = cube_root_attack(c, e)
    print("plaintext (int):", m)
    if m:
        try:
            print("als bytes:", m.to_bytes((m.bit_length() + 7) // 8, "big"))
        except Exception:
            pass
