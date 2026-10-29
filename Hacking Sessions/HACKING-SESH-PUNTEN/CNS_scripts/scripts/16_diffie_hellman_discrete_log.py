"""
DIFFIE-HELLMAN AANVALLEN (kleine/zwakke parameters)
========================================================
WANNEER GEBRUIKEN?
  - Je krijgt DH-parameters (g, p) en een publieke sleutel A = g^a mod p,
    en moet de geheime exponent 'a' achterhalen (het discrete-log-probleem).
  - Dit is enkel haalbaar als 'p' KLEIN is, of als p-1 veel kleine
    priemfactoren heeft (small subgroup confinement / Pohlig-Hellman).

VEREIST: pip install sympy --break-system-packages
"""
from sympy.ntheory.residue_ntheory import discrete_log
from sympy import factorint


def bruteforce_discrete_log(g: int, A: int, p: int, max_a: int = 10_000_000):
    """Simpele brute force: probeer a = 0, 1, 2, ... tot g^a mod p == A.
    Enkel haalbaar voor KLEINE p (of kleine verwachte a)."""
    val = 1
    for a in range(max_a):
        if val == A:
            return a
        val = (val * g) % p
    return None


def discrete_log_sympy(g: int, A: int, p: int):
    """Gebruikt sympy's ingebouwde (baby-step-giant-step/Pohlig-Hellman)
    discrete-log-oplosser -- veel sneller dan pure brute force,
    werkt voor middelgrote p (tot een stuk of 60-80 bits, afhankelijk
    van hoe "glad" p-1 is -- hoe meer kleine factoren, hoe sneller)."""
    return discrete_log(p, A, g)


def check_smoothness(p: int):
    """Kijk of p-1 veel kleine priemfactoren heeft (small subgroup risico)."""
    factors = factorint(p - 1)
    print(f"p-1 = {p-1} heeft factoren: {factors}")
    max_factor = max(factors.keys())
    print(f"Grootste priemfactor: {max_factor} ({max_factor.bit_length()} bits)")
    if max_factor.bit_length() < 40:
        print("[!] p-1 is 'glad' (smooth) -> discrete log is waarschijnlijk haalbaar!")
    return factors


if __name__ == "__main__":
    # TODO: vul de echte DH-parameters in
    g = 2       # TODO
    p = 0       # TODO: de modulus
    A = 0       # TODO: de publieke sleutel van de andere partij (g^a mod p)

    check_smoothness(p)

    try:
        a = discrete_log_sympy(g, A, p)
        print("Geheime exponent a =", a)
        # Als je ook B (de publieke sleutel van de AANDERE partij) hebt:
        # shared_secret = pow(B, a, p)
    except Exception as e:
        print("sympy discrete_log faalde:", e)
        print("Probeer bruteforce_discrete_log() als p echt klein is, of")
        print("zoek de ECHTE p op -- mogelijk is het een bekende, zwakke,")
        print("gestandaardiseerde DH-groep (zie Logjam: https://weakdh.org/)")
