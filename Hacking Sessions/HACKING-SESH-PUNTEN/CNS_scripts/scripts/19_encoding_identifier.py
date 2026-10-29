"""
ENCODING/OBFUSCATIE HERKENNEN EN DECODEREN
===============================================
WANNEER GEBRUIKEN?
  - Je krijgt een onherkenbare tekst-blob en weet niet of het "echte"
    crypto is, of gewoon een encoding-laag (base64/hex/rot13/...).
  - Test dit ALTIJD EERST voor je aan complexere crypto-aanvallen begint!
"""
import base64
import codecs
import urllib.parse


def guess_decode(s: str):
    """Probeert een reeks veelvoorkomende encodings, print wat werkt."""
    results = {}

    # Hex
    try:
        results["hex"] = bytes.fromhex(s)
    except Exception:
        pass

    # Base64 (standaard)
    try:
        results["base64"] = base64.b64decode(s)
    except Exception:
        pass

    # Base64 URL-safe
    try:
        padded = s + "=" * (-len(s) % 4)
        results["base64url"] = base64.urlsafe_b64decode(padded)
    except Exception:
        pass

    # Base32
    try:
        results["base32"] = base64.b32decode(s)
    except Exception:
        pass

    # Base85/Ascii85
    try:
        results["base85"] = base64.a85decode(s)
    except Exception:
        pass

    # URL-encoding
    try:
        decoded = urllib.parse.unquote(s)
        if decoded != s:
            results["urlencode"] = decoded
    except Exception:
        pass

    # ROT13 (en elke andere Caesar-shift)
    try:
        results["rot13"] = codecs.decode(s, "rot_13")
    except Exception:
        pass

    for shift in range(1, 26):
        shifted = caesar_shift(s, shift)
        # alleen tonen als het er "leesbaar" uitziet (bevat spaties/veelvoorkomende woorden)
        if looks_like_english(shifted):
            results[f"caesar_shift_{shift}"] = shifted

    return results


def caesar_shift(s: str, shift: int) -> str:
    out = []
    for c in s:
        if c.isupper():
            out.append(chr((ord(c) - ord('A') + shift) % 26 + ord('A')))
        elif c.islower():
            out.append(chr((ord(c) - ord('a') + shift) % 26 + ord('a')))
        else:
            out.append(c)
    return "".join(out)


def looks_like_english(s: str) -> bool:
    common_words = (" the ", " and ", " is ", " of ", " cns{", "flag")
    lower = s.lower()
    return any(w in lower for w in common_words)


def recursive_decode(s: str, max_depth: int = 5):
    """Probeert meerdere encoding-lagen na elkaar te pellen (bv. base64(hex(...)))."""
    current = s
    for depth in range(max_depth):
        decoded_any = False
        for name, fn in [
            ("hex", lambda x: bytes.fromhex(x).decode()),
            ("base64", lambda x: base64.b64decode(x).decode()),
        ]:
            try:
                nxt = fn(current)
                print(f"[diepte {depth}] {name}: {nxt!r}")
                current = nxt
                decoded_any = True
                break
            except Exception:
                continue
        if not decoded_any:
            break
    return current


if __name__ == "__main__":
    # TODO: vul de onherkenbare blob in
    blob = "VGhpcyBpcyBhIHRlc3Q="
    for name, value in guess_decode(blob).items():
        print(f"{name}: {value!r}")
