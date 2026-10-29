import hashlib
with open("rockyou.txt", errors='replace') as file:
    passwords = file.read().splitlines()

username = "user"
realm = "PythonRTSP"
nonce="4874a055c3f4390506d99e6c51a9e3e360cbef8a62abd7079e11faddcb70a38c"
uri="rtsp://cns-test.idlab.uantwerpen.be:50002/video"
response="b3539154c5b784bba2c47a1a6c7c4ab0"
algorithm="MD5"
method="DESCRIBE"

# hash1 = (username:realm:password)
# hash2 = (method:uri)
# response = (HA1:nonce:HA2)
hash2 = hashlib.md5(f"{method}:{uri}".encode('utf-8')).hexdigest()
for password in passwords:
    hash1 = hashlib.md5(f"{username}:{realm}:{password}".encode('utf-8')).hexdigest()
    response2 = hashlib.md5(f"{hash1}:{nonce}:{hash2}".encode('utf-8')).hexdigest()
    # print(f"Trying password: {password} -> Response: {response2}")
    if response2 == response:
        print("Password found!", password, response2, response, "\n")
        break

# 143.169.150.173