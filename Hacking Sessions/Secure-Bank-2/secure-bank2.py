import random
import socket,json, time
import string
from datetime import datetime, timezone
import hashlib
"""
reference; String; 1–128 characters
from_account; String; Must start with SIM-
to_account; String; Must start with SIM- (different from source)
amount; Number; Must equal 10
currency; String; Must be EUR
timestamp; String; Valid ISO 8601 timestamp
"""

HOST = "cns-test.idlab.uantwerpen.be"
PORT = 50003

def canonicalize(payment):
    return json.dumps(
        payment,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")

rec1 = {
    "reference": "rfieaxwxpa",
    "from_account": "SIM-111",
    "to_account": "SIM-222",
    "amount": 10,
    "currency": "EUR",
    "timestamp": datetime.now(timezone.utc).isoformat(),
}

rec2 = {
    "reference": "rtiqfixdee",
    "from_account": "SIM-111",
    "to_account": "SIM-222",
    "amount": 10,
    "currency": "EUR",
    "timestamp": datetime.now(timezone.utc).isoformat(),
}

def vind_collisie():
    gevonden = {}
    tijd = datetime.now(timezone.utc).isoformat()
    basis_rec = {
        "from_account": "SIM-111",
        "to_account": "SIM-222",
        "amount": 10,
        "currency": "EUR",
        "timestamp": tijd,
    }
    while True:
        huidige_rec = basis_rec.copy()
        huidige_rec["reference"] = "".join(random.choices(string.ascii_lowercase, k=10))
        data = canonicalize(huidige_rec)
        afgekapte_hash = hashlib.sha256(data).digest()[:4]
        if afgekapte_hash in gevonden:
            print("COLLISIE GEVONDEN!")
            print(gevonden[afgekapte_hash])
            print(huidige_rec)
            print(afgekapte_hash.hex())
            return gevonden[afgekapte_hash], huidige_rec
        else:
            gevonden[afgekapte_hash] = huidige_rec

record1, record2 = vind_collisie()
print('DIT IS RECORD 1\n', record1)
print('DIT IS RECORD 2\n', record2)


with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    time.sleep(0.5) # banner
    s.recv(4096)

    time.sleep(0.5)
    s.sendall((json.dumps(record1) + "\n").encode())
    s.recv(4096)

    time.sleep(0.5)
    s.sendall((json.dumps(record2) + "\n").encode())
    s.recv(4096)

    print(s.recv(4096).decode(errors="replace"))