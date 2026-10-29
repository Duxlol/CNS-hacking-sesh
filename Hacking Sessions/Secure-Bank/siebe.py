import socket
import json

HOST = 'cns-test.idlab.uantwerpen.be'
PORT = 50001

message = {
    "from": "user1",
    "to": "user2",
    "amount": "50",
}

with socket.socket(socket.AF_INET, SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    greeting = s.recv(2048)
    print(greeting.decode("utf-8", errors="replace"), end="")
    s.sendall(json.dumps(message).encode("utf-8"))
    data = s.recv(2048)

print(data.decode("utf-8", errors="replace"))