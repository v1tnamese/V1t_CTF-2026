from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util import number
from math import gcd, isqrt, log
from random import SystemRandom


rng = SystemRandom()
BITS = 640
SMOOTH_BOUND = 2**15
E = 65537


def hnorm(z):
    x, y = z
    return x*x - x*y + y*y


def hmul(z, w):
    x, y = z
    u, v = w
    return (x*u - y*v, x*v + y*u - y*v)


def small_hex(v):
    lim = isqrt(4*v // 3 + 16) + 8
    for x in range(-lim, lim + 1):
        for y in range(-lim, lim + 1):
            if hnorm((x, y)) == v:
                return (x, y)
    raise ValueError("not represented")


def primes_upto(n):
    sieve = [True] * (n + 1)
    sieve[0] = sieve[1] = False
    for i in range(2, isqrt(n) + 1):
        if sieve[i]:
            for j in range(i*i, n + 1, i):
                sieve[j] = False
    return [i for i in range(2, n + 1) if sieve[i]]


UNITS = [(1, 0), (-1, 0), (0, 1), (0, -1), (-1, -1), (1, 1)]


def build_bag(bound):
    bag = []
    for p in primes_upto(bound):
        if p == 2:
            continue
        if p == 3:
            z = (1, -1)
            count = int(log(bound, p))
        elif p % 3 == 1:
            z = small_hex(p)
            count = int(log(bound, p))
        else:
            z = (p, 0)
            count = int(log(bound, p)) // 2

        bag.extend([z] * count)
    return bag


def random_assoc(z):
    x, y = z
    if rng.randrange(2):
        z = (x - y, -y)
    return hmul(z, rng.choice(UNITS))


def smooth_hex(bits, bag):
    bag = bag[:]
    z = (1, 0)
    m = 1
    while m.bit_length() < bits:
        i = rng.randrange(len(bag))
        t = random_assoc(bag.pop(i))
        z = hmul(z, t)
        m *= hnorm(t)
    return hmul(z, rng.choice(UNITS)), m


def special_prime(bits, bound):
    bag = build_bag(bound)
    while True:
        z, m = smooth_hex(bits, bag)
        x, y = z
        p = hnorm((x - 1, y))
        assert hnorm(z) == m
        if p.bit_length() == bits and number.isPrime(p):
            return p


p = special_prime(BITS, SMOOTH_BOUND)
q = number.getPrime(BITS)
n = p * q
phi = (p - 1) * (q - 1)

assert gcd(E, phi) == 1
d = pow(E, -1, phi)

key = RSA.construct((n, E, d, p, q))
cipher = PKCS1_OAEP.new(key)

with open("flag.txt", "rb") as f:
    flag = f.read().strip()

print(f"n = {n}")
print(f"e = {E}")
print(f"c = {cipher.encrypt(flag).hex()}")

