from Crypto.Cipher import DES
string = "{ \"namespace\": \"IOTDEV\", \"message\": \"74eb40cf03b84d0bc4cd2c6e0fe97fb4e70546d3e09c530d35b344e530351bac\" }"
key = "IOTDEV"
message = "74eb40cf03b84d0bc4cd2c6e0fe97fb4e70546d3e09c530d35b344e530351bac"
alphabet = "abcdef0123456789"

for char in alphabet:
    for char2 in alphabet:
        test_key = key+char+char2
        test_key_bytes = test_key.encode('utf-8')
        while True:
            a = DES.new(test_key_bytes, DES.MODE_ECB).decrypt(bytes.fromhex(message))
            print(a)
