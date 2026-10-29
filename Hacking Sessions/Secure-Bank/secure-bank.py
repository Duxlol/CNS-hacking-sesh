import socket
import json
HOST = 'cns-test.idlab.uantwerpen.be'
PORT = 50001
message = {
    "from": "Alice",
    "to": "Bob",
    "amount": "100",
}

raw = bytes.fromhex("3b17e45a2ba19f8dde298e6e1980c9d83f5caa34c414323e946d7b1ccb9e70242e7c6ad4ee1e19ac4ac1cc44fde882654c0eca02a3")
nonce = raw[:8]
ciphertext = raw[8:]
known_plaintext = b'{"from":"alice","to":"bob","amount": "000010"}'
keystream = bytes(c ^ p for c,p in zip(ciphertext, known_plaintext))

new_plaintext = b'{"from":"alice","to":"bob","amount": "100000"}'
new_ciphertext = bytes(c^k for c,k in zip(keystream, new_plaintext))
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    greeting = s.recv(2048)
    print(greeting.decode("utf-8", errors="replace"), end="")
    s.sendall((nonce+new_ciphertext).hex().encode("utf-8"))
    data = s.recv(2048)
    data2 = s.recv(2048)
print(data.decode("utf-8", errors="replace"))
print(data2.decode("utf-8", errors="replace"))