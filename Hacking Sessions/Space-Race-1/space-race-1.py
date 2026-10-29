import socket, hashlib, json, time
from dataclasses import replace

HOST = 'cns-test.idlab.uantwerpen.be'
PORT = 50006

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))

    greeting = ""
    # s.recv(4096).decode('utf-8', errors="replace")
    # print(greeting.encode("utf-8", errors="replace"), end="")

    while "CURRENT CODE: " not in greeting:
        print("Waiting for CURRENT CODE...")
        stukje_data = s.recv(4096).decode('utf-8', errors="replace")
        greeting += stukje_data

    print(greeting)
    huidige_code = greeting.split("CURRENT CODE: ")[1].split("\n")[0].strip()
    print(huidige_code)
    raw = bytes.fromhex(huidige_code)

    berekende_hash = hashlib.sha256(raw).hexdigest()

    s.sendall(berekende_hash.encode('utf-8'))

    antwoord = s.recv(4096)
    print(antwoord)
