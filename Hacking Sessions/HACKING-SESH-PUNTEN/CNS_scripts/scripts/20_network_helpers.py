"""
HERBRUIKBARE NETWERK-HELPERS VOOR TCP-SOCKET-OPGAVES
=========================================================
Generieke bouwstenen die in bijna ELKE "nc <host> <port>"-opgave terugkomen.
Kopieer de functies die je nodig hebt naar je eigen script.
"""
import socket
import re


def recv_until(sock: socket.socket, marker: str, bufsize: int = 4096) -> str:
    """Blijft lezen tot 'marker' in de ontvangen data zit. Nodig omdat TCP
    een stream is -- data kan in willekeurige stukjes toekomen."""
    data = ""
    while marker not in data:
        chunk = sock.recv(bufsize)
        if not chunk:
            break
        data += chunk.decode("utf-8", errors="replace")
    return data


def recv_all_available(sock: socket.socket, timeout: float = 1.0) -> bytes:
    """Leest alles wat beschikbaar is binnen een timeout (handig als je niet
    weet op welke exacte marker je moet wachten)."""
    sock.settimeout(timeout)
    data = b""
    try:
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
    except socket.timeout:
        pass
    finally:
        sock.settimeout(None)
    return data


def extract_hex_blob(text: str, min_length: int = 16) -> str | None:
    """Haalt de langste hex-string uit een stuk tekst (handig om ciphertext
    uit een banner/prompt te plukken zonder exacte positie te kennen)."""
    matches = re.findall(r"[0-9a-fA-F]{%d,}" % min_length, text)
    if not matches:
        return None
    return max(matches, key=len)


def simple_session(host: str, port: int, send_after_marker: str, to_send: bytes):
    """Generiek sjabloon: verbind, wacht tot een marker, stuur iets, lees antwoord."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, port))
        greeting = recv_until(s, send_after_marker)
        print("--- GREETING ---")
        print(greeting)

        s.sendall(to_send)

        response = recv_all_available(s, timeout=2.0)
        print("--- RESPONSE ---")
        print(response.decode(errors="replace"))
        return response


if __name__ == "__main__":
    # TODO: pas aan naar de specifieke opgave
    HOST = "cns-test.idlab.uantwerpen.be"
    PORT = 50001
    simple_session(HOST, PORT, send_after_marker="\n", to_send=b"test\n")
