# Computer & Network Security — Hacking Session Cheatsheet (uitgebreide versie)
*Gebaseerd op jullie opgeloste oefeningen + algemene/aanpalende technieken voor varianten
die nog niet aan bod kwamen (RSA, Diffie-Hellman, web-kwetsbaarheden, encodings, tooling).*

> **Leeswijzer:** ✅ = bevestigd door jullie eigen testen. 📘 = algemene, publiek
> gedocumenteerde techniek (nog niet zelf getest op deze specifieke server) —
> betrouwbare theorie, maar verifieer de details live. Secties zijn zo opgebouwd dat
> je op "herkenning" kan zoeken (Ctrl+F) als je een opgavetekst voor je hebt.

---

## 0. De meta-methodologie — stel dit jezelf bij ELKE opgave

1. **Categorie op de site?** (Stream Ciphers / Block Ciphers / Hashing / HMAC / Public-Key / Web...) → beperkt meteen de mogelijke aanvallen.
2. **Wordt een sleutel/nonce/seed/IV hergebruikt** tussen twee berichten? → **two-time pad**.
3. **Encryptie zonder authenticatie** (geen MAC/HMAC/signature)? → **bit-flipping / malleability**.
4. **Kleine of voorspelbare sleutelruimte** expliciet vermeld (bv. "20-bit", "standardised keys", "short password")? → **brute force** of **meet-in-the-middle**.
5. **Zelfgeschreven/"home-made" hash of cipher** (geen AES/SHA uit een standaardbibliotheek)? → waarschijnlijk **omkeerbaar** (XOR/shift/rotate zijn allemaal inverteerbaar).
6. **Fingerprint/hash "afgekapt" of goedkoop opgeslagen** ("we don't have enough space/money to store the full X")? → **birthday-attack / collision**.
7. **Een JWT** (drie base64url-delen, gescheiden door punten)? → decodeer, kijk naar `alg`, probeer `alg=none` of zwak secret.
8. **Een signature/HMAC-header bij JSON**? → kijk naar **canonicalisatie/parsing-mismatch** (dubbele keys, volgorde, witruimte, encoding).
9. **Server vraagt je een "volgende code" te voorspellen**? → **hash chain**, en let op raw bytes vs hex-string!
10. **RSA-achtige getallen** (`n`, `e`, `d`, grote priemgetallen, modulus)? → zie §5 (RSA-aanvallen): kijk eerst naar de grootte van `e` en of `n` factoriseerbaar is.
11. **Diffie-Hellman-parameters** (`g`, `p`, publieke sleutels `A`/`B`)? → zie §5.2: is `p` klein/standaard? Is de subgroep klein?
12. **Een URL met een parameter die een ID/pad/URL bevat**, of een inlog-/sessiesysteem? → denk web-kwetsbaarheden (§6): IDOR, SSRF, path traversal, SQLi, open redirect.
13. **Een onherkenbare blob tekst** (letters+cijfers, of enkel hex, of `==` op het einde)? → zie §7 (encoding-herkenning) vóór je aan "echte crypto" denkt — soms is het gewoon base64/hex/rot13.
14. **Timing-gevoelige foutmeldingen** ("invalid password" vs "invalid username", of merkbaar tragere responses)? → denk aan **timing attacks** / **oracle-aanvallen** (§2.4, §6).

---

## 1. Stream Cipher aanvallen

### 1.1 Keystream/seed hergebruik → Two-time pad ✅
**Herkenning:** twee berichten versleuteld met "dezelfde configuratie/seed/nonce".
```python
keystream = bytes(c ^ p for c, p in zip(ciphertext_known, plaintext_known))
flag = bytes(c ^ k for c, k in zip(ciphertext_secret, keystream))
```
Toegepast op: **Replanting**, **Noncense**.

**Variant — N berichten, allemaal met dezelfde keystream (klassiek "many-time pad"):** 📘
Als je 3+ ciphertexts met dezelfde keystream hebt zonder een volledig known-plaintext, kan je per bytepositie met frequentie-analyse werken: XOR elk paar ciphertexts (`c1^c2 = p1^p2`), en gok dat één van de plaintexts op die positie een spatie (`0x20`) is — spaties XOR'en met letters geven herkenbare patronen (hoofdletter↔kleine letter verschuiving). Tool: `python3 -m venv` + `xortool`, of het CTF-klassieke "crib dragging".

### 1.2 Zwakke PRNG / state recovery (custom LCG, enz.) ✅
Zie je eigen uitgewerkte voorbeeld (Replanting). Generaliseer: elke keer dat je een **custom RNG** ziet met gekende formule (`next = (A*state + C) mod M`, of een LFSR, of Mersenne Twister met voorspelbare seed zoals `time.time()`), probeer de **interne state te reconstrueren** uit gedeeltelijke output.
- **Mersenne Twister (Python's `random`)**: als je 624 opeenvolgende 32-bit outputs ziet, kan je de volledige interne state klonen met tools als `randcrack` (`pip install randcrack`) en daarna toekomstige "willekeurige" waarden perfect voorspellen.
- **Geseed met tijd** (`random.seed(int(time.time()))`): brute force de seed over een klein tijdvenster rond het moment van de request.

### 1.3 Malleability / bit-flipping (geen MAC) ✅
Zie uitgewerkt voorbeeld (Secure Bank 1). Kernformule:
```python
keystream = bytes(c ^ p for c, p in zip(ciphertext, known_plaintext))
new_ciphertext = bytes(k ^ p for k, p in zip(keystream, new_desired_plaintext))
```
**Let op:** keystream hangt af van nonce — blijf binnen dezelfde sessie werken.

**Variant — CTR-counter manipulatie:** 📘 bij AES-CTR kan je, als je de counter/nonce-opbouw kent, ook **blokken van positie laten wisselen** door de counter-waarde in de ciphertext-aanvraag te forceren naar een waarde die al elders gebruikt is (vergelijkbaar met nonce-reuse, maar dan actief uitgelokt in plaats van toevallig).

### 1.4 RC4-specifieke zwaktes 📘
Als je ooit RC4 tegenkomt: de eerste paar keystream-bytes zijn statistisch **niet** uniform willekeurig (bekende bias in byte 0 en 1). Bij hergebruikte/voorspelbare sleutels (WEP-stijl) kan je met voldoende samples de sleutel herleiden (FMS-attack, KoreK-attacks). Tool: `aircrack-ng` als het om WEP gaat.

---

## 2. Block Cipher aanvallen

### 2.1 Kleine/voorspelbare sleutelruimte → brute force ✅
Zie Key Standardisation. Probeer sleutels afgeleid van bekende strings (naam, namespace, bedrijfsnaam), met padding-varianten (nullen vooraan/achteraan, herhaling, hoofdletters/kleine letters), en brute force resterende onbekende tekens als die beperkt zijn.

### 2.2 Double/meervoudige encryptie → Meet-in-the-Middle ✅
Zie AES 2 demo. `Enc(K1,P) = Dec(K2,C)` → bouw een hashtabel voor alle K1, zoek voor elke K2.
```python
table = {}
for k1 in range(2**20):
    table[AES_encrypt(make_key(k1), P)] = k1
for k2 in range(2**20):
    mid = AES_decrypt(make_key(k2), C)
    if mid in table:
        print("K1 =", table[mid], "K2 =", k2)
```
Vereist een bekend (plaintext-blok, ciphertext-blok)-paar van hetzelfde blok (bestandsheaders zijn goud: BMP `"BM"`, PNG `\x89PNG`, JPEG `\xFF\xD8\xFF`, ZIP `PK\x03\x04`, PDF `%PDF-`, GIF `GIF89a`).

### 2.3 Mode-herkenning (ECB vs CBC vs CTR/stream) 📘
| Signaal | Betekent |
|---|---|
| Identieke 16-byte blokken verschijnen herhaaldelijk in de ciphertext | **ECB** — patronen in plaintext blijven zichtbaar |
| Afbeelding versleuteld met ECB blijft "herkenbaar" (vormen zichtbaar) | **ECB** — klassieke demo: het Linux-pinguïn-voorbeeld |
| Lengte van ciphertext = lengte plaintext + een veelvoud van blokgrootte (padding) | Blockmode met padding (CBC meestal) |
| Lengte ciphertext ≈ lengte plaintext + vaste kleine offset (8 of 12-16 bytes) | **Stream-achtige mode (CTR/GCM/stream cipher)** met nonce/IV ervoor |
| Wijziging van 1 ciphertext-byte verandert **1 hele blok** willekeurig bij decryptie, en de rest blijft normaal, maar het **volgende** blok krijgt exact diezelfde bit-flip | **CBC** (bit-flip propageert typisch) |
| Wijziging van 1 ciphertext-byte verandert **slechts dat ene byte** bij decryptie | **Stream cipher / CTR / OFB** (XOR-gebaseerd, malleable — zie §1.3) |

### 2.4 CBC Padding Oracle Attack 📘
**Herkenning:** CBC-mode, en de server geeft een **ander soort foutmelding** (of merkbaar ander gedrag/timing) bij "invalid padding" versus "valid padding maar ongeldige data".

**Principe (kort):** PKCS#7-padding betekent dat de laatste bytes van het plaintext aangeven hoeveel paddingbytes er zijn (bv. laatste byte `0x04` → de laatste 4 bytes moeten allemaal `0x04` zijn). Door **de voorlaatste ciphertext-blok byte per byte te wijzigen** en te kijken of de server "padding OK" of "padding FOUT" zegt, kan je **elke byte van het plaintext** achterhalen — zonder de sleutel te kennen, puur via dat ja/nee-signaal. Je werkt van de laatste byte van een blok naar de eerste.
```python
# Zeer vereenvoudigd skelet — pas de oracle-functie aan je server aan
def padding_oracle(iv_block, cipher_block):
    # stuur iv_block + cipher_block naar de server, return True als "padding valid"
    ...

def decrypt_block(prev_block, target_block):
    intermediate = bytearray(16)
    plaintext = bytearray(16)
    for pad_val in range(1, 17):
        pos = 16 - pad_val
        fake_prev = bytearray(16)
        for i in range(pos+1, 16):
            fake_prev[i] = intermediate[i] ^ pad_val
        for guess in range(256):
            fake_prev[pos] = guess
            if padding_oracle(bytes(fake_prev), target_block):
                intermediate[pos] = guess ^ pad_val
                plaintext[pos] = intermediate[pos] ^ prev_block[pos]
                break
    return bytes(plaintext)
```
**Bron:** https://robertheaton.com/2013/07/29/padding-oracle-attack/ · tool: `padbuster`.

### 2.5 Related-key / weak-key varianten (DES-specifiek) 📘
DES heeft 4 bekende **zwakke sleutels** (en 12 semi-zwakke) waarbij encryptie = decryptie (self-inverse). Als een opgave specifiek over "DES weak keys" gaat: zoek op *"DES weak keys list"* — er zijn er maar 4, triviaal te proberen.

---

## 3. Hash-functie aanvallen

### 3.1 Zelfgeschreven ("home-made") hash → omkeren ✅
Zie Better Hash. Keer rondevolgorde + stapvolgorde om, vervang elke operatie door haar inverse (XOR↔XOR, rol↔ror, prefix-XOR-ketting loop je van hoog naar laag, lijstrotatie omgekeerd).

### 3.2 Afgekapte hash / fingerprint → Birthday-attack ✅
Zie Secure Bank 2. Met *n*-bit afgekapte hash vind je een collision in ~2^(n/2) pogingen i.p.v. 2^n.
**Vuistregel-tabel:**
| Fingerprint-lengte | Collision na ongeveer |
|---|---|
| 16 bits (4 hex) | ~256 pogingen |
| 24 bits (6 hex) | ~4.096 pogingen |
| 32 bits (8 hex) | ~65.536 pogingen |
| 40 bits (10 hex) | ~1M pogingen |
| 48 bits (12 hex) | ~16M pogingen (nog steeds seconden-minuten) |

### 3.3 Hash chain voorspellen ✅
Zie Space Race 1. **Hash de ruwe bytes**, niet de hex-tekst: `bytes.fromhex(code)`, niet `code.encode()`.

### 3.4 Hash length-extension attack 📘
**Herkenning:** een MAC geconstrueerd als `hash(secret || message)` (géén echte HMAC) met MD5/SHA-1/SHA-256 (Merkle–Damgård-constructies zijn hier kwetsbaar aan, SHA-3/BLAKE2 niet). Je kent `hash(secret||message)` en de lengte van `message`, maar niet `secret` zelf — en je wil data **achteraan toevoegen** met een geldige nieuwe hash.
```bash
pip install hlextend --break-system-packages
```
```python
import hlextend
sha = hlextend.new('sha256')  # of 'sha1', 'md5'
new_hash = sha.extend(
    data=b";admin=true",          # wat je wil toevoegen
    secret=b"origineel_bericht",  # het bericht zoals jij het kent (zonder secret)
    secret_length=16,             # GOK/brute-force de lengte van de geheime sleutel (probeer 1..64)
    hexdigest="originele_mac_hex"
)
new_message = sha.hexdigest()     # dit stuur je ipv het origineel, met new_hash als MAC
```
**Belangrijkste denkstap:** als je de secret-lengte niet kent, loop je gewoon over een plausibel bereik (1 t.e.m. 32 of 64 bytes) en probeer je elke `new_message`/`new_hash`-combinatie tot de server er één accepteert.
**Bron:** https://en.wikipedia.org/wiki/Length_extension_attack · CLI-tool: `hashpump` (https://github.com/bwall/HashPump)

### 3.5 Hash-identificatie op lengte 📘
| Hex-lengte | Bits | Waarschijnlijk algoritme |
|---|---|---|
| 32 | 128 | MD5 |
| 40 | 160 | SHA-1 |
| 56 | 224 | SHA-224 |
| 64 | 256 | SHA-256 |
| 96 | 384 | SHA-384 |
| 128 | 512 | SHA-512 |
| variabel, `$`-gescheiden | — | bcrypt/scrypt/argon2 (herkenbaar aan prefix `$2b$`, `$argon2id$`, enz.) |

### 3.6 Known collision-tools voor MD5/SHA-1 📘
Als een opgave vraagt om **twee verschillende bestanden/berichten met dezelfde volle MD5 of SHA-1** te maken (niet afgekapt): gebruik bestaande, publiek beschikbare collision-generators — zelf zoeken naar een collision is onbegonnen werk.
- MD5: https://github.com/corkami/collisions (kant-en-klare MD5-collision-paren en -tools)
- SHA-1: "SHAttered" PDF-collisie-aanpak: https://shattered.io/

---

## 4. Authenticatie-protocollen & MAC's

### 4.1 HTTP/RTSP Digest Authentication — offline dictionary attack ✅
Zie Security Cam. RFC 2069 (geen `qop`): `response = MD5(MD5(user:realm:pass):nonce:MD5(method:uri))`.
Geen `print()` per poging in de loop — dat maakt het uren trager.

### 4.2 JWT-aanvallen — `alg: none` ✅
Zie Token of Trust: decodeer header+payload, `alg`→`none`, rechten verhogen, her-encoderen, signature-deel leeg laten, versturen als `Authorization: Bearer <token>`.

**Andere JWT-varianten om te proberen als `alg=none` niet werkt:** 📘
- Zwak/geraden `HS256`-secret → `jwt_tool` of `hashcat -m 16500 -a 0 token.txt rockyou.txt`.
- `kid`-header injectie / algorithm confusion (RS256→HS256) als de server per ongeluk een publieke sleutel als HMAC-secret hergebruikt.
- Ontbrekende `exp`-check → een oud/verlopen token blijft gewoon geldig.
- `jku`/`x5u`-header die naar een URL wijst die jij kan controleren (server haalt daar de verificatiesleutel op).

### 4.3 HMAC / signature-aanvallen op JSON — duplicate-key confusion ✅
Zie Signed, Sealed, Misinterpreted: hergebruik een legitieme signature, stuur een **rauwe string** (geen Python-dict, want die kan geen dubbele keys hebben) met een key (bv. `"role"`) **twee keer**, in de hoop dat de signature-check en de autorisatielogica elk een andere van de twee waarden gebruiken.

**Generaliseer naar andere parsing-mismatches:** 📘
- **Unicode-tricks**: `"r\u006fle"` (unicode-escape voor 'o') kan door de ene parser anders behandeld worden dan door de andere.
- **Extra/onverwachte velden**: soms valideert de signature-check enkel een subset van velden, en kan je extra velden toevoegen die de autorisatielogica wel leest.
- **Content-Type verwarring**: dezelfde data als `application/json` vs `application/x-www-form-urlencoded` versturen kan soms een andere parser triggeren aan de serverkant.
- **Timing-attack op MAC-vergelijking**: als een server MAC's vergelijkt met een niet-constant-time `==` (i.p.v. `hmac.compare_digest`), kan je in theorie byte per byte raden via responstijd — zelden praktisch haalbaar binnen een CTF-sessie, maar wel een herkenbaar concept.

---

## 5. Public-key cryptografie (RSA, Diffie-Hellman, ECC) 📘

*(Nog niet gezien in jullie opgaves, maar hoort standaard bij dit vak — hieronder de meest voorkomende CTF-klassiekers.)*

### 5.1 RSA-aanvallen
RSA: publieke sleutel `(n, e)`, privé `d`, met `n = p*q` (2 grote priemgetallen). Versleutelen: `c = m^e mod n`. Herken welke situatie van toepassing is:

| Signaal | Aanval |
|---|---|
| `e = 3` (of een andere kleine exponent) en bericht is kort t.o.v. `n` | **Cube-root attack**: als `m^3 < n`, dan is `c` gewoon `m^3` zonder modulo-wrap → `m = round(c ** (1/3))` (met `gmpy2.iroot` voor exacte integer-cube-root bij grote getallen) |
| Hetzelfde bericht verstuurd naar **3+ ontvangers** met verschillende `n`'s, zelfde kleine `e` | **Håstad's broadcast attack** — Chinese Reststelling (CRT) combineren en dan e-de-machtswortel nemen |
| Twee verschillende ciphertexts met **dezelfde modulus `n`**, verschillende `e1`/`e2` (vaak co-priem) | **Common modulus attack** — met extended Euclidean algorithm `a*e1 + b*e2 = 1` vinden, dan `m = c1^a * c2^b mod n` |
| `p` en `q` liggen **dicht bij elkaar** (beide rond √n) | **Fermat-factorisatie**: `a = ceil(sqrt(n))`, test of `a² - n` een perfect kwadraat is, verhoog `a` tot dat zo is |
| `d` (privésleutel) is **klein** t.o.v. `n` | **Wiener's attack** — kettingbreuk-expansie van `e/n` vindt `d` |
| Je kent **één van de priemfactoren** (`p` of `q`) al, of ze zijn klein genoeg | Factoriseer `n` direct (`sympy.factorint(n)`, of http://factordb.com — **eerst opzoeken of `n` al gefactoriseerd in een database staat, zeer vaak het geval in CTF's!**) |
| `n` is heel klein (< ~100 bits) | Brute-force factoriseren met Pollard's rho (`sympy.factorint`) |
| Padding-oracle op RSA (PKCS#1 v1.5), server lekt "valid/invalid padding" | **Bleichenbacher's attack** — complex, zoek op *"Bleichenbacher attack RSA PKCS1"* |

**Praktisch startpunt voor élke RSA-opgave:**
```python
# 1. Probeer eerst factordb.com — vaak is n al bekend/gefactoriseerd
# 2. Zo niet, test de signalen hierboven in volgorde (klein e → common modulus → Fermat → Wiener)
from sympy import factorint
n = ...  # de modulus
factors = factorint(n)  # werkt enkel voor kleine/kwetsbare n, anders time-out
```
**Tool die alles hierboven automatiseert:** **RsaCtfTool** — https://github.com/Ganapati/RsaCtfTool
```bash
python3 RsaCtfTool.py --publickey key.pem --uncipherfile ciphertext.bin
```

### 5.2 Diffie-Hellman-aanvallen
Standaard DH: beide partijen kiezen geheim `a`/`b`, delen `A = g^a mod p`, `B = g^b mod p`, gedeelde sleutel `g^(ab) mod p`.
- **Kleine of bekende `p`**: als `p` klein genoeg is (< ~60 bits), is het discrete-log-probleem (`a` vinden uit `A = g^a mod p`) gewoon brute-forceerbaar of met Pollard's rho / baby-step-giant-step op te lossen (`sympy.discrete_log(p, A, g)`).
- **Kleine subgroep-aanval**: als `p-1` veel kleine priemfactoren heeft, kan de geheime exponent `mod` die kleine factoren gelekt worden (Pohlig-Hellman-algoritme).
- **Logjam-stijl aanval** (bekende/herbruikte standaard-`p`-waarden van 512-1024 bit): zoek op *"logjam attack precomputation"*.
- **MITM zonder authenticatie**: als DH niet aan een signature/certificaat gekoppeld is, kan een attacker tussen beide partijen eigen `g^x`-waarden insturen.

### 5.3 ECDSA / digitale handtekeningen — nonce-hergebruik
Als twee verschillende berichten **dezelfde "random" nonce `k`** gebruiken bij ECDSA-signing (klassieke implementatiefout, net als bij stream ciphers!), kan je daaruit de **privésleutel** herleiden met simpele modulaire rekenkunde. Herkenning: twee signatures met dezelfde `r`-waarde. Zoek op *"ECDSA nonce reuse attack"* — exact dezelfde "hergebruik-logica" als jullie stream cipher-opgaves, maar dan op een ander wiskundig niveau.

---

## 6. Web / API-kwetsbaarheden 📘

*(Relevant als een opgave een HTTP-endpoint geeft i.p.v. een raw TCP-socket — zoals Token of Trust / Signed Sealed Misinterpreted.)*

| Kwetsbaarheid | Herkenning | Snelle test |
|---|---|---|
| **IDOR** (Insecure Direct Object Reference) | URL/body met een ID (`/user/1234`, `"account_id":5`) | Verhoog/verlaag het ID, kijk of je andermans data ziet |
| **SQL-injectie** | Een inputveld voedt vermoedelijk een databasequery | Probeer `' OR '1'='1`, `'; --`, en kijk naar foutmeldingen die SQL-syntax verraden |
| **SSRF** (Server-Side Request Forgery) | De server haalt zelf een URL op die jij (deels) controleert | Geef `http://localhost/...` of `http://169.254.169.254/...` (cloud-metadata) als URL-parameter |
| **Path traversal** | Een bestandsnaam/pad als parameter | Probeer `../../../../etc/passwd` of URL-encoded varianten `%2e%2e%2f` |
| **Command injection** | De server lijkt een shell-commando te bouwen met jouw input | Probeer `; whoami`, `` `id` ``, `$(whoami)` |
| **Open redirect** | Een `redirect=` of `next=`-parameter | Zet 'm op een externe URL, kijk of de server zonder validatie doorstuurt |
| **CSRF** | Een actie met side-effects zonder anti-CSRF-token | Maak een auto-submit HTML-formulier dat de actie namens een ingelogde gebruiker uitvoert |
| **Insecure Deserialization** | Een geserialiseerd object (pickle, Java-serialized, PHP `O:`) als input | Zoek naar bekende gadget chains voor dat framework (bv. `ysoserial` voor Java) |
| **Verbose errors / stack traces** | Elke foutmelding bekijken, ook "onbelangrijke" | Soms lekt een stack trace paden, library-versies, of zelfs secrets |

**Algemene tip:** kijk altijd naar **response headers** (`Server:`, `X-Powered-By:`) — die verraden vaak het framework, wat je meteen naar bekende CVE's/kwetsbaarheden voor die specifieke versie kan leiden (zoek op *"<framework> <versie> CVE"*).

---

## 7. Encoding & obfuscatie herkennen (vóór je aan "echte crypto" denkt) 📘

| Signaal | Waarschijnlijk | Decodeer met |
|---|---|---|
| Enkel `0-9a-f`, even aantal karakters | Hex | `bytes.fromhex(s)` |
| Letters+cijfers+`+`/`/`, eindigt op `=` of `==` | Base64 | `base64.b64decode(s)` |
| Zoals base64 maar met `-`/`_` i.p.v. `+`/`/` | Base64 **URL-safe** | `base64.urlsafe_b64decode(s)` |
| Enkel hoofdletters A-Z en cijfers 2-7 | Base32 | `base64.b32decode(s)` |
| `%XX`-patronen | URL-encoding | `urllib.parse.unquote(s)` |
| Tekst blijft leesbaar maar letters lijken verschoven | Caesar/ROT13 | `codecs.decode(s, 'rot13')`, of brute force alle 25 shifts |
| Drie delen gescheiden door punten, elk base64url | **JWT** | zie §4.2 |
| Lijkt op binaire data met leesbare stukjes ertussen | Mogelijk een serialisatieformaat (pickle, protobuf) of gewoon ruwe bytes | `file <bestand>`, `xxd <bestand> \| head` |
| Herhaalde groepjes van exact dezelfde lengte | Mogelijk Base85/Ascii85 | `base64.a85decode(s)` |

**CyberChef** (https://gchq.github.io/CyberChef/) is de snelste manier om snel door meerdere encoding-lagen te "Magic"-detecteren zonder zelf Python te moeten schrijven — gebruik de **Magic**-operator als je geen idee hebt wat voor encoding iets is.

---

## 8. Netwerkanalyse / Wireshark / tshark snelreferentie

```bash
# Toon TCP-conversaties (snel zien welke poort/host relevant is)
tshark -r capture.pcapng -q -z conv,tcp

# Decodeer een niet-standaardpoort als een specifiek protocol
tshark -r capture.pcapng -d tcp.port==50002,rtsp -Y rtsp

# Volledige inhoud van één frame (headers, alles)
tshark -r capture.pcapng -Y 'frame.number==10' -O rtsp

# Extract ruwe payload-bytes van een specifiek frame
tshark -r capture.pcapng -Y 'frame.number==10' -T fields -e tcp.payload

# HTTP-requests/responses snel overzien
tshark -r capture.pcapng -Y http -T fields -e http.request.full_uri -e http.response.code

# Bestanden/objecten die over HTTP zijn verstuurd uitpakken
tshark -r capture.pcapng --export-objects http,/tmp/extracted/

# "Follow TCP stream" equivalent in tshark
tshark -r capture.pcapng -q -z follow,tcp,ascii,0
```
In Wireshark zelf: rechtermuisklik pakket → **Decode As...**, of permanent via **Edit → Preferences → Protocols → <PROTOCOL> → TCP port(s)**.

---

## 9. Nuttige Python-snippets

```python
# Veilig blijven lezen van een TCP-socket tot je een bepaalde marker ziet
def recv_until(sock, marker: str, bufsize=4096) -> str:
    data = ""
    while marker not in data:
        data += sock.recv(bufsize).decode("utf-8", errors="replace")
    return data

# XOR van twee byte-reeksen (kortste lengte wint)
def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

# rockyou.txt robuust inlezen (bevat niet-UTF8 troep) zonder alles in het geheugen te laden
with open("rockyou.txt", encoding="utf-8", errors="ignore") as f:
    passwords = (line.rstrip("\n") for line in f)   # generator!

# Snel een onbekende blob proberen te identificeren/decoderen
import base64, binascii
def guess_decode(s: str):
    for name, fn in [
        ("hex", lambda x: bytes.fromhex(x)),
        ("base64", lambda x: base64.b64decode(x)),
        ("base64url", lambda x: base64.urlsafe_b64decode(x + "=" * (-len(x) % 4))),
        ("base32", lambda x: base64.b32decode(x)),
    ]:
        try:
            print(name, "->", fn(s))
        except Exception:
            pass
```

---

## 10. Tooling-cheatsheet

| Taak | Tool / commando |
|---|---|
| Wachtwoord-hash kraken (algemeen, GPU-versneld) | `hashcat -m <mode> -a 0 hash.txt rockyou.txt` — mode 0=MD5, 100=SHA1, 1400=SHA256, 16500=JWT HS256 |
| Wachtwoord-hash kraken (CPU, flexibel) | `john --wordlist=rockyou.txt hash.txt` |
| JWT-aanvallen automatiseren | `jwt_tool` — https://github.com/ticarpi/jwt_tool |
| RSA-aanvallen automatiseren | `RsaCtfTool` — https://github.com/Ganapati/RsaCtfTool |
| Gefactoriseerde/bekende RSA-moduli opzoeken | https://factordb.com |
| Encoding/crypto snel uitproberen in de browser | https://gchq.github.io/CyberChef/ |
| Algemene decoder (Caesar, Vigenère, enz.) | https://www.dcode.fr/ |
| OpenSSL — certificaat/sleutel inspecteren | `openssl x509 -in cert.pem -text -noout` |
| OpenSSL — RSA-sleutel info | `openssl rsa -in key.pem -text -noout` |
| OpenSSL — snel AES/DES encrypt/decrypt testen | `openssl enc -aes-128-ecb -d -K <hexkey> -in ct.bin -out pt.bin` |
| Padding-oracle automatiseren | `padbuster` |
| Hash length-extension automatiseren | `hashpump` — https://github.com/bwall/HashPump |
| Python length-extension library | `pip install hlextend` |
| Mersenne Twister state recovery | `pip install randcrack` |

---

## 11. Bronnen om snel te doorzoeken tijdens de sessie

| Onderwerp | Bron |
|---|---|
| JWT uitleg + live decoder | https://jwt.io/introduction |
| JWT/HMAC/algemene web-labs, stap-voor-stap | https://pentesterlab.com/exercises |
| Web-kwetsbaarheden algemeen (IDOR, SSRF, SQLi...) | https://portswigger.net/web-security |
| Digest Authentication (RFC's) | https://en.wikipedia.org/wiki/Digest_access_authentication |
| Padding Oracle (CBC) | https://robertheaton.com/2013/07/29/padding-oracle-attack/ |
| Length-extension attack | https://en.wikipedia.org/wiki/Length_extension_attack |
| Meet-in-the-Middle (2DES voorbeeld) | https://en.wikipedia.org/wiki/Meet-in-the-middle_attack |
| Birthday attack / collision | https://en.wikipedia.org/wiki/Birthday_attack |
| RSA-aanvallen overzicht | https://github.com/Ganapati/RsaCtfTool (README geeft goed overzicht van alle aanvalstypes) |
| Wiener's attack uitleg | zoek *"Wiener's attack RSA continued fraction"* |
| Diffie-Hellman / Logjam | https://weakdh.org/ |
| ECDSA nonce reuse | zoek *"ECDSA nonce reuse attack explained"* |
| AES/GF(2⁸) theorie | eigen cursusslides (Stallings, hoofdstuk 5) |
| CyberChef | https://gchq.github.io/CyberChef/ |
| MD5-collisies kant-en-klaar | https://github.com/corkami/collisions |

---

## 12. Nog openstaand / expliciet onzeker

- **AES 2 demo version**: methodologie (MITM, §2.2) staat klaar, maar ik heb nooit het echte `enc.bmp`-bestand gezien, dus ik weet niet of het known-plaintext-blok (BMP-header) klopte of wat de uiteindelijke flag was.
- **Secure Bank 1 — exacte eindflag**: de bit-flip-methode werkt bevestigd (`Transfer of X EUR to bob processed`), maar check zelf of een bedrag als "100000" een foutmelding geeft (validatie-bereik) en pas zo nodig aan.
- **§5, §6, §7 zijn algemene/aanpalende theorie**, niet getest op jullie specifieke challenge-server — behandel ze als "waar te beginnen zoeken" als je zoiets tegenkomt, niet als kant-en-klare oplossing.

**Succes morgen!** Bij twijfel: terug naar §0, en vraag je af welk vakje het best past bij wat de opgavetekst je vertelt.
