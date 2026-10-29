# Script-index — CNS Hacking Session

Elk script is **standalone** en herbruikbaar: kopieer de relevante functie(s)
naar je eigen oplossing en vul de `# TODO`-plekken in met de echte waarden
van de opgave die je voor je hebt. Elk script begint met een uitleg-docstring
(waarom/wanneer gebruiken, het principe) en bevat commentaar bij de niet-
triviale regels.

✅ = bevestigd gewerkt op jullie eigen opgaves · 📘 = algemene, publiek
gedocumenteerde techniek, nog niet getest op deze specifieke server.

| # | Bestand | Techniek | Status |
|---|---|---|---|
| 01 | `01_two_time_pad.py` | Keystream/nonce-hergebruik (two-time pad) | ✅ Replanting, Noncense |
| 02 | `02_lcg_state_recovery.py` | Zwakke PRNG (custom LCG) state recovery + keystream verlengen | ✅ Replanting |
| 03 | `03_bitflipping_malleability.py` | Bit-flipping bij encryptie zonder MAC | ✅ Secure Bank 1 |
| 04 | `04_weak_key_bruteforce.py` | Brute force kleine/voorspelbare sleutelruimte (DES/AES) | ✅ Key Standardisation |
| 05 | `05_meet_in_the_middle.py` | Meet-in-the-Middle op dubbele encryptie | 📘 AES 2 demo (methodologie klaar, bestand niet bevestigd) |
| 06 | `06_mode_detection_and_ecb_patterns.py` | ECB/CBC/CTR-mode herkennen | 📘 algemeen |
| 07 | `07_padding_oracle.py` | CBC padding oracle attack | 📘 algemeen, nog niet gezien |
| 08 | `08_custom_hash_reversal_template.py` | Zelfgeschreven hash omkeren (stap-voor-stap inverteren) | ✅ Better Hash |
| 09 | `09_birthday_collision.py` | Birthday-attack op afgekapte hash | ✅ Secure Bank 2 |
| 10 | `10_hash_chain_predict.py` | Hash chain voorspellen (raw bytes!) | ✅ Space Race 1 |
| 11 | `11_hash_length_extension.py` | Hash length-extension attack (`hashpumpy`) | 📘 algemeen, nog niet gezien — **test vooraf of hashpumpy lokaal installeert!** |
| 12 | `12_digest_auth_cracker.py` | HTTP/RTSP Digest auth offline dictionary attack | ✅ Security Cam |
| 13 | `13_jwt_attacks.py` | JWT `alg=none`, secret-bruteforce | ✅ Token of Trust |
| 14 | `14_hmac_json_key_confusion.py` | HMAC/signature-hergebruik via duplicate JSON-keys | ✅ Signed, Sealed, Misinterpreted |
| 15 | `15_rsa_attacks.py` | RSA: cube-root, common modulus, Fermat, Wiener, Hastad | 📘 algemeen, nog niet gezien — **alle functies individueel getest, kloppen wiskundig** |
| 16 | `16_diffie_hellman_discrete_log.py` | Diffie-Hellman: discrete log bij kleine/gladde p | 📘 algemeen, nog niet gezien — **getest, klopt** |
| 17 | `17_ecdsa_nonce_reuse.py` | ECDSA private key recovery bij nonce-hergebruik | 📘 algemeen, nog niet gezien |
| 18 | `18_custom_rotor_cipher_enigma.py` | Custom rotor-/Enigma-achtige cijfers (generiek raamwerk + varianten) | ✅ My First Enigma Machine |
| 19 | `19_encoding_identifier.py` | Encoding/obfuscatie herkennen (base64/hex/rot13/...) | 📘 algemeen |
| 20 | `20_network_helpers.py` | Herbruikbare TCP-socket-helpers (recv_until, enz.) | 📘 algemeen, gebruikt in meerdere opgaves |
| 21 | `21_web_vuln_payloads.py` | Snelle testpayloads (SQLi, path traversal, SSRF, ...) | 📘 algemeen |

## Vooraf installeren (test dit THUIS, niet pas tijdens de sessie!)

```bash
pip install pycryptodome sympy requests --break-system-packages
pip install hashpumpy --break-system-packages   # voor script 11, vraagt een build-stap
```

Zie de hoofdcheatsheet (`CNS_Hacking_Session_Cheatsheet.md`) voor de volledige
uitleg, herkenningssignalen en bronnen per techniek.
