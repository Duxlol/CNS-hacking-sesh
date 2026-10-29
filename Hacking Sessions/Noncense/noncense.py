from Crypto.Cipher import AES
from Crypto.Util import Counter

ciphertext_flag = "def52b3b54f25097f0d90ff8356ba757801d10e63dcb0f190eccfac3ce23bd5a5bd306cb5c"
ciphertext_known = "fcf83b2f47f34aa6f48d09c87b65a558c5290cec3fd64a2a06c8d687c02bfa5e5fd512cc4854686920f59867edc05aaf9a21560e359928e343cdd4b6ea3ce69267e267a51b2b25522a83d210ca3fc89a684f399e6a"
known_message = "According to all known laws of aviation, there is no way a bee should be able to fly."

known_message_bytes = bytes(known_message, 'utf-8')

ciphertext_flag_bytes = bytes.fromhex(ciphertext_flag)
ciphertext_known_bytes = bytes.fromhex(ciphertext_known)

keystream = bytes([b1 ^ b2 for b1, b2 in zip(known_message_bytes, ciphertext_known_bytes)])
flag_bytes = bytes([b1 ^ b2 for b1, b2 in zip(ciphertext_flag_bytes, keystream)])
print(flag_bytes)

