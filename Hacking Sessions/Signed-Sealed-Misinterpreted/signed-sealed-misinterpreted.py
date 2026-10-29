import requests,json
HOST = 'http://cns-test.idlab.uantwerpen.be:50007/vault'
PORT = 50007

message = {
    "action": "view",
    "role": "admin",
    "role": "user"}
headers = {
    "X-Signature" : "817e86132b480782043d61602c1843100dc8002186502619e802913d918a0f69"
}

r = requests.post(HOST, headers=headers,data='{"action": "view", "role": "admin","role": "user"}')
print(r.json())