"""
HASH CHAIN VOORSPELLEN
==========================
WANNEER GEBRUIKEN?
  - Een server toont een "CURRENT CODE" (lange hex-string) en vraagt je
    de VOLGENDE code te voorspellen voordat die verstuurd wordt.

CRUCIALE VALKUIL:
  Een hash chain hasht typisch de RUWE BYTES van de vorige hash, NIET de
  leesbare hex-tekst ervan!
    FOUT:  hashlib.sha256(code_string.encode()).hexdigest()
    GOED:  hashlib.sha256(bytes.fromhex(code_string)).hexdigest()

NETWERK-VALKUIL:
  TCP is een stream -- banner en code kunnen in aparte pakketjes toekomen.
  Blijf lezen tot je de code ECHT binnen hebt (zie recv_until hieronder).

VOORBEELD WAAR DIT OP TOEGEPAST WERD: "Space Race 1".
"""
import socket
import hashlib

HOST = "cns-test.idlab.uantwerpen.be"   # TODO
PORT = 50006                             # TODO


def recv_until(sock: socket.socket, marker: str, bufsize: int = 4096) -> str:
    data = ""
    while marker not in data:
        chunk = sock.recv(bufsize)
        if not chunk:
            break
        data += chunk.decode("utf-8", errors="replace")
    return data


if __name__ == "__main__":
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))

        greeting = recv_until(s, "CURRENT CODE: ")   # TODO: pas marker aan
        print(greeting)

        huidige_code = greeting.split("CURRENT CODE: ")[1].split("\n")[0].strip()
        print("Huidige code:", huidige_code)

        # DE CRUCIALE STAP: hash de RUWE BYTES, niet de hex-string als tekst
        ruwe_bytes = bytes.fromhex(huidige_code)
        voorspelling = hashlib.sha256(ruwe_bytes).hexdigest()
        print("Mijn voorspelling:", voorspelling)

        s.sendall((voorspelling + "\n").encode("utf-8"))
        antwoord = recv_until(s, "\n")   # of gewoon s.recv(4096)
        print("\n--- SERVER ANTWOORD ---")
        print(antwoord)

        # Als "Wrong prediction": probeer varianten, bv.
        #   - hashlib.sha256(huidige_code.encode()).hexdigest()  (als tekst, voor de zekerheid)
        #   - md5 / sha1 i.p.v. sha256 (check de lengte van de hex-string: 32=MD5,40=SHA1,64=SHA256)
        #   - misschien is de input niet de code zelf maar code + een salt/timestamp
