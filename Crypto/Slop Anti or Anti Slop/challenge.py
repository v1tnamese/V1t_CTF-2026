import base64
import hashlib
import re
from decimal import Decimal

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


F = b"v1t{REDACTED}"
A = b"v1t::RSA_NoHashInHere_PoW_OTP::r1muru"


def P(x, coffee):
    s = Decimal(0)
    t = Decimal(1)
    for v in coffee:
        s += Decimal(v) * t
        t *= x
    return s


def R(sugar, z, n):
    for _ in range(z):
        sugar = (sugar * sugar) % n
    return sugar


def I(v, m):
    s = 0
    for i, (x, y) in enumerate(v):
        a = 1
        b = 1
        for j, (u, _) in enumerate(v):
            if i == j:
                continue
            a = (a * (-u)) % m
            b = (b * (x - u)) % m
        s = (s + y * a * pow(b, -1, m)) % m
    return s


def H(x):
    return hashlib.sha256(x).digest()


def K(coffee, cream, sugar):
    x = ",".join(map(str, coffee)).encode()
    return hashlib.sha256(
        b"coffee"
        + H(x)
        + b"cream"
        + H(str(cream).encode())
        + b"sugar"
        + H(str(sugar).encode())
    ).digest()


def E(f, coffee, cream, sugar):
    x = ",".join(map(str, coffee)).encode()
    y = hashlib.sha256(b"drip" + H(x) + b"cream" + H(str(cream).encode())).digest()[:12]
    return base64.b64encode(y + AESGCM(K(coffee, cream, sugar)).encrypt(y, f, A)).decode()


def M(coffee, v, m):
    a = v[10]
    xs = v[4:7]
    ids = v[7:10]
    bs = v[11:14]
    return [(x, (a * coffee[i] + y) % m) for x, i, y in zip(xs, ids, bs)]


def main():
    z = open("output.txt", encoding="utf-8").read()

    def q(*p):
        for x in p:
            y = re.search(rf"^{x} = (.+)$", z, re.M)
            if y:
                return y.group(1).strip()
        raise SystemExit(7)

    cup = base64.b64decode(q("c"))
    bean = [int(x) for x in q("v").split(",")]
    roast = [(Decimal(x), Decimal(y)) for x, y in re.findall(r"^o\d+: ([^,]+), (.+)$", z, re.M)]
    foam = int(q("m"))
    sugar = int(q("r"))
    pour = int(q("z"))
    kettle = int(q("n"))
    steam = q("a").encode()
    if steam != A:
        raise SystemExit(13)

    blend = [bean[0], bean[2], len(roast), len(cup), foam.bit_length()]
    aroma = hashlib.sha256(
        b"|".join(
            [
                H(cup),
                H(",".join(map(str, bean)).encode()),
                H(str(sugar ^ pour ^ kettle.bit_length()).encode()),
            ]
        )
    ).hexdigest()
    print("coffee =", ":".join(map(str, blend)))
    print("sugar =", aroma[:32])


if __name__ == "__main__":
    main()
