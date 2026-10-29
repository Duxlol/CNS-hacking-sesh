# Stream Ciphers & Bit-Flipping Cheat Sheet

## Basisprincipes van Stream Ciphers (XOR Regels)
Een stream cipher genereert een pseudo-willekeurige stroom van bits (de **Keystream**) op basis van een sleutel (en vaak een Nonce/IV). De versleuteling gebeurt door de Keystream te XOR'en met de Plaintext.

*   **Versleutelen:** $Ciphertext = Plaintext \oplus Keystream$
*   **Ontsleutelen:** $Plaintext = Ciphertext \oplus Keystream$
*   **Keystream achterhalen (Known-Plaintext):** $Keystream = Ciphertext \oplus Plaintext$

## De Wiskunde van een Bit-Flipping Aanval
Als je de originele plaintext kent (of deels kan raden), kan je de ciphertext manipuleren zodat deze na ontsleuteling door de server in jouw gewenste tekst verandert, zonder dat je de geheime sleutel nodig hebt.

### Methode 1: Via de Keystream (2 stappen)
Dit is de methode die in je script werkte.
1.  **Vind de Keystream:** XOR de originele ciphertext met de bekende originele plaintext.
    $K = C \oplus P_{oud}$
2.  **Maak de nieuwe Ciphertext:** XOR jouw nieuwe (vervalste) plaintext met de gevonden Keystream.
    $C_{nieuw} = P_{nieuw} \oplus K$

### Methode 2: Directe XOR (1 stap)
Omdat XOR associatief en commutatief is, kan je de bovenstaande stappen ook combineren tot één formule:
*   $C_{nieuw} = C \oplus P_{oud} \oplus P_{nieuw}$

*(In Python: `bytes(c ^ p_old ^ p_new for c, p_old, p_new in zip(ciphertext, old_plaintext, new_plaintext))`)*

## Eigenschappen van XOR (Waarom dit werkt)
*   $A \oplus A = 0$ (Iets XOR'en met zichzelf is nul)
*   $A \oplus 0 = A$ (Iets XOR'en met nul verandert niets)
*   $A \oplus B \oplus A = B$ (Als je twee keer met hetzelfde XOR't, hef je het op)

## Cruciale Aandachtspunten voor Oefeningen
*   **Exacte lengte:** XOR werkt bit per bit. Jouw $P_{oud}$ en $P_{nieuw}$ moeten **exact even lang** zijn in bytes.
*   **Data formaten:** Let goed op verborgen spaties of tekens. Bij JSON voegt Python's `json.dumps()` vaak een spatie toe na een dubbele punt (`"amount": "100"` in plaats van `"amount":"100"`). Eén byte verschil verschuift de hele berekening.
*   **Nonce/IV:** Vaak worden de eerste bytes van de raw data gebruikt als Nonce of Initialization Vector. Deze mag je niet mee-XOR'en in je bit-flipping berekening, maar moet je wel ongewijzigd terugsturen voor de gemanipuleerde ciphertext.
*   **Byte manipulatie in Python:** Gebruik `zip()` correct. Zorg dat je iterators even lang zijn en dat je bytes met bytes XOR't. Gebruik `bytes.fromhex()` en `.hex().encode()` om te wisselen tussen netwerkpayloads en wiskundige bewerkingen.