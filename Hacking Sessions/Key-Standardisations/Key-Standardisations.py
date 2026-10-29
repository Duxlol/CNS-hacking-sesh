from Crypto.Cipher import DES


key = "IOTDEV"

message = "74eb40cf03b84d0bc4cd2c6e0fe97fb4e70546d3e09c530d35b344e530351bac"

alphabet = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

for char1 in alphabet:
    for char2 in alphabet:
        test_key = key + char1 + char2
        test_key_bytes = test_key.encode('utf-8')
        try:
            cipher = DES.new(test_key_bytes, DES.MODE_ECB)
            decrypted = cipher.decrypt(bytes.fromhex(message))
            if b"cns" in decrypted:
                print({test_key})
                print({decrypted})
        except:
            continue

