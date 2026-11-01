"""Generates the data-loss benchmark set: personal data and secrets inside
ordinary sentences, and look-alike values that are not sensitive. Values are
synthetic but valid (check digits, key formats), written from the public
format descriptions, never from Promptwall's own patterns. A fixed seed makes
the set the same on every machine.

    python benchmark/dlp_set.py    # writes benchmark/data/dlp.jsonl

Each line: {"text", "label", "value", "set": "dlp"}. "label" is the finding
the value should produce, such as "pii.email", or null for a look-alike that
should produce nothing; "value" is the sensitive part of "text".
"""

import base64
import json
import random
import string
from pathlib import Path

rng = random.Random(2026)
DATA = Path(__file__).parent / "data"
PER_TYPE = 30

FIRST = ["Anna", "Lukas", "Sofia", "Mehmet", "Chloé", "João", "Aisha", "Piotr", "Emma", "Luca", "Marta", "Jonas"]
LAST = ["Schmidt", "Rossi", "Dubois", "Kowalski", "García", "Jansen", "Yılmaz", "Novak", "Fischer", "Moreau"]


def digits(n):
    return "".join(rng.choice(string.digits) for _ in range(n))


def alnum(n, alphabet=string.ascii_letters + string.digits):
    return "".join(rng.choice(alphabet) for _ in range(n))


def luhn_complete(prefix, length):
    body = prefix + digits(length - len(prefix) - 1)
    total = 0
    for i, d in enumerate(reversed(body)):
        n = int(d)
        if i % 2 == 0:
            n *= 2
            n -= 9 if n > 9 else 0
        total += n
    return body + str((10 - total % 10) % 10)


def iban(country, bban):
    rearranged = bban + country + "00"
    num = int("".join(str(int(c, 36)) for c in rearranged))
    return f"{country}{98 - num % 97:02d}{bban}"


def spaced(s, n=4):
    return " ".join(s[i:i + n] for i in range(0, len(s), n))


def email():
    user = rng.choice([f"{rng.choice(FIRST)}.{rng.choice(LAST)}", f"{rng.choice(FIRST)[0]}{rng.choice(LAST)}", alnum(8, string.ascii_lowercase)])
    user = user.lower().replace("é", "e").replace("ã", "a").replace("ı", "i").replace("í", "i")
    return f"{user}@{rng.choice(['corp.io', 'example-mail.de', 'firma.eu', 'uni-hamburg.de', 'gmail.com'])}"


def phone():
    return rng.choice([
        f"+49 151 {digits(8)}", f"+49 30 {digits(4)} {digits(4)}", f"+33 6 {digits(2)} {digits(2)} {digits(2)} {digits(2)}",
        f"+44 7700 {digits(6)}", f"+1 415 {digits(3)} {digits(4)}", f"+39 347 {digits(7)}", f"+31 6 {digits(8)}",
    ])


def an_iban():
    v = rng.choice([
        iban("DE", digits(18)), iban("FR", digits(10) + alnum(11, string.ascii_uppercase + string.digits) + digits(2)),
        iban("NL", alnum(4, string.ascii_uppercase) + digits(10)), iban("ES", digits(20)), iban("IT", rng.choice(string.ascii_uppercase) + digits(10) + digits(12)),
    ])
    return spaced(v) if rng.random() < 0.5 else v


def card():
    v = rng.choice([luhn_complete("4", 16), luhn_complete("5" + str(rng.randint(1, 5)), 16), luhn_complete(rng.choice(["34", "37"]), 15)])
    return rng.choice([v, spaced(v), "-".join(v[i:i + 4] for i in range(0, len(v), 4))]) if len(v) == 16 else v


def ip():
    return ".".join(str(rng.randint(1, 254)) for _ in range(4))


def nl_bsn():
    while True:
        d = [rng.randint(0, 9) for _ in range(8)]
        s = sum(x * w for x, w in zip(d, range(9, 1, -1)))
        last = s % 11
        if last < 10 and d[0] != 0:
            return "".join(map(str, d)) + str(last)


def es_dni():
    n = rng.randint(10_000_000, 99_999_999)
    return f"{n}{'TRWAGMYFPDXBNJZSQVHLCKE'[n % 23]}"


def pl_pesel():
    d = [rng.randint(0, 9) for _ in range(2)] + [0, rng.randint(1, 9), rng.randint(1, 2), rng.randint(0, 8)] + [rng.randint(0, 9) for _ in range(4)]
    s = sum(x * w for x, w in zip(d, [1, 3, 7, 9, 1, 3, 7, 9, 1, 3]))
    return "".join(map(str, d)) + str((10 - s % 10) % 10)


def uk_nino():
    while True:
        prefix = rng.choice("ABCEGHJKLMNOPRSTWXYZ") + rng.choice("ABCEGHJKLMNPRSTWXYZ")
        if prefix not in ("BG", "GB", "KN", "NK", "NT", "TN", "ZZ"):  # never issued
            return prefix + digits(6) + rng.choice("ABCD")


def us_ssn():
    return f"{rng.randint(100, 665)}-{rng.randint(10, 99)}-{rng.randint(1000, 9999)}"


def aws():
    return "AKIA" + alnum(16, string.ascii_uppercase + "234567")


def jwt():
    enc = lambda o: base64.urlsafe_b64encode(json.dumps(o).encode()).decode().rstrip("=")
    return f"{enc({'alg': 'HS256', 'typ': 'JWT'})}.{enc({'sub': digits(8), 'name': rng.choice(FIRST), 'iat': 1767225600})}.{alnum(43, string.ascii_letters + string.digits + '-_')}"


def private_key():
    body = "\n".join(alnum(64, string.ascii_letters + string.digits + "+/") for _ in range(4))
    kind = rng.choice(["RSA PRIVATE KEY", "PRIVATE KEY", "OPENSSH PRIVATE KEY", "EC PRIVATE KEY"])
    return f"-----BEGIN {kind}-----\n{body}\n-----END {kind}-----"


TYPES = {
    "pii.email": email,
    "pii.phone": phone,
    "pii.iban": an_iban,
    "pii.credit_card": card,
    "pii.ip_address": ip,
    "pii.nl_bsn": nl_bsn,
    "pii.es_dni": es_dni,
    "pii.pl_pesel": pl_pesel,
    "pii.uk_nino": uk_nino,
    "pii.us_ssn": us_ssn,
    "secret.aws_access_key": aws,
    "secret.github_token": lambda: rng.choice(["ghp_", "gho_", "ghs_"]) + alnum(36),
    "secret.openai_key": lambda: "sk-proj-" + alnum(48, string.ascii_letters + string.digits + "_-") + "T3BlbkFJ" + alnum(48, string.ascii_letters + string.digits + "_-"),
    "secret.anthropic_key": lambda: "sk-ant-api03-" + alnum(93, string.ascii_letters + string.digits + "_-") + "AA",
    "secret.slack_token": lambda: f"xoxb-{digits(12)}-{digits(13)}-{alnum(24)}",
    "secret.stripe_key": lambda: rng.choice(["sk_live_", "rk_live_"]) + alnum(24),
    "secret.google_api_key": lambda: "AIza" + alnum(35, string.ascii_letters + string.digits + "_-"),
    "secret.huggingface_token": lambda: "hf_" + alnum(34),
    "secret.npm_token": lambda: "npm_" + alnum(36),
    "secret.sendgrid_key": lambda: f"SG.{alnum(22, string.ascii_letters + string.digits + '_-')}.{alnum(43, string.ascii_letters + string.digits + '_-')}",
    "secret.private_key": private_key,
    "secret.jwt": jwt,
    "secret.url_credentials": lambda: f"{rng.choice(['postgres', 'mysql', 'mongodb', 'redis', 'amqp'])}://{rng.choice(['app', 'admin', 'svc'])}:{alnum(14)}@db{rng.randint(1, 9)}.internal:5432/prod",
}

# Context keywords some formats need, as a person would write them.
LEADS = {
    "pii.nl_bsn": ["BSN", "burgerservicenummer"],
    "pii.es_dni": ["DNI", "mi DNI es"],
    "pii.pl_pesel": ["PESEL", "numer PESEL"],
    "pii.uk_nino": ["National Insurance number", "NI number"],
    "pii.us_ssn": ["SSN", "social security number"],
}

TEMPLATES = [
    "Please update my record, {lead} {v}, thanks.",
    "Can you write a polite email to the customer? Their details: {lead} {v}",
    "Kannst du das zusammenfassen? Kontakt: {lead} {v}. Danke!",
    "Voici les infos du client ({lead} {v}), peux-tu rédiger une réponse ?",
    "{lead} {v}\nWhy does the import fail for this row?",
    "Debug this config:\n```\nendpoint: https://api.internal\nvalue = \"{v}\"\n```",
    "Translate to Spanish: 'For refunds use {lead} {v} as reference.'",
]
DEFAULT_LEADS = {
    "pii.email": ["", "email", "mail me at"], "pii.phone": ["", "phone", "Tel."], "pii.iban": ["IBAN", "", "account"],
    "pii.credit_card": ["card", "", "Kreditkarte"], "pii.ip_address": ["server", "IP", ""],
}

# Values that look sensitive but are not: they must not be reported.
NEGATIVES = [
    lambda: f"Order number {digits(10)} shipped yesterday, tracking {alnum(2, string.ascii_uppercase)}{digits(9)}DE.",
    lambda: f"The commit {alnum(40, '0123456789abcdef')} broke the build.",
    lambda: f"Request ID {alnum(8, '0123456789abcdef')}-{alnum(4, '0123456789abcdef')}-4{alnum(3, '0123456789abcdef')}-a{alnum(3, '0123456789abcdef')}-{alnum(12, '0123456789abcdef')} timed out.",
    lambda: f"Upgrade from version {rng.randint(1, 9)}.{rng.randint(0, 30)}.{rng.randint(0, 99)} to {rng.randint(1, 9)}.{rng.randint(0, 30)}.{rng.randint(0, 99)}.",
    lambda: f"The invoice total is {rng.randint(100, 99999)},{digits(2)} EUR, due {rng.randint(1, 28)}.{rng.randint(1, 12)}.2026.",
    lambda: f"ISBN 978-{rng.randint(0, 9)}-{digits(3)}-{digits(5)}-{rng.randint(0, 9)} is out of print.",
    lambda: f"Card number {digits(16)} was rejected as invalid.",  # fails Luhn about 90% of the time
    lambda: f"Use the sample key AKIA{'EXAMPLE'} from the docs, it is not real.",
    lambda: f"Set the env var OPENAI_API_KEY before running the script.",
    lambda: f"My password is not something I share; how do I reset it?",
    lambda: f"Compute the SHA-256 of 'hello': {alnum(64, '0123456789abcdef')}.",
    lambda: f"Coordinates {rng.uniform(40, 55):.6f}, {rng.uniform(-5, 20):.6f} are near the office.",
    lambda: f"Call the support line 0800 {digits(3)} {digits(3)} (free) between 9 and 5.",
    lambda: f"Version string {rng.randint(1, 9)}.{rng.randint(0, 9)}.{rng.randint(0, 9)}.{rng.randint(0, 999)} matches no IP.",
    lambda: f"Write a regex that matches email addresses like user at domain dot com.",
    lambda: f"Base64 of 'release notes for Q3' is {base64.b64encode(b'release notes for Q3').decode()}.",
    lambda: f"The meeting room code is {digits(6)}.",
    lambda: f"Table {rng.randint(1, 40)} ordered {rng.randint(2, 9)} pizzas at {rng.randint(18, 22)}:{digits(2)}.",
]
NEGATIVES_PER_TEMPLATE = 15


def main():
    DATA.mkdir(exist_ok=True)
    rows = []
    for label, make in TYPES.items():
        for _ in range(PER_TYPE):
            v = make()
            lead = rng.choice(LEADS.get(label, DEFAULT_LEADS.get(label, [""])))
            template = rng.choice(TEMPLATES)
            text = template.format(lead=lead, v=v).replace("  ", " ")
            rows.append({"text": text, "label": label, "value": v, "set": "dlp"})
    for make in NEGATIVES:
        for _ in range(NEGATIVES_PER_TEMPLATE):
            rows.append({"text": make(), "label": None, "value": None, "set": "dlp"})
    with open(DATA / "dlp.jsonl", "w", encoding="utf-8") as out:
        for row in rows:
            out.write(json.dumps(row, ensure_ascii=False) + "\n")
    print(f"dlp: {sum(1 for r in rows if r['label'])} values, {sum(1 for r in rows if not r['label'])} look-alikes")


if __name__ == "__main__":
    main()
