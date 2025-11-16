import random, math
from math import isqrt

# ---------- basic number theory helpers ----------

def is_probable_prime(n, k=20):
    """Miller–Rabin primality test."""
    if n < 2:
        return False
    # small primes to quickly filter
    small_primes = [2,3,5,7,11,13,17,19,23,29]
    if n in small_primes:
        return True
    for p in small_primes:
        if n % p == 0:
            return False
    # write n-1 as 2^r * d
    r = 0
    d = n - 1
    while d % 2 == 0:
        r += 1
        d //= 2
    # witness loop
    for _ in range(k):
        a = random.randrange(2, n - 2)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def gen_prime(bits):
    """Generate a probable prime of given bit length."""
    while True:
        n = random.getrandbits(bits)
        n |= 1                      # make odd
        n |= (1 << (bits - 1))      # ensure correct bit length
        if is_probable_prime(n):
            return n

def egcd(a, b):
    """Extended GCD: returns (x, y, gcd) such that ax + by = gcd."""
    if b == 0:
        return (1, 0, a)
    x, y, g = egcd(b, a % b)
    return (y, x - (a // b) * y, g)

def modinv(a, m):
    """Modular inverse of a modulo m."""
    x, y, g = egcd(a, m)
    if g != 1:
        raise ValueError("no modular inverse exists")
    return x % m

# ---------- RSA key generation ----------

def gen_weak_rsa(bits=512, d_bits=64):
    """Generate RSA key where private exponent d is deliberately small."""
    p = gen_prime(bits // 2)
    q = gen_prime(bits // 2)
    N = p * q
    phi = (p - 1) * (q - 1)
    # choose small odd d that is coprime with phi
    d = random.getrandbits(d_bits) | 1
    while math.gcd(d, phi) != 1:
        d = random.getrandbits(d_bits) | 1
    e = modinv(d, phi)
    return (N, e, d, p, q)

def gen_rsa(bits=512):
    """Generate a 'normal' RSA key (no forced weakness)."""
    p = gen_prime(bits // 2)
    q = gen_prime(bits // 2)
    N = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    if math.gcd(e, phi) != 1:
        e = 3
        while math.gcd(e, phi) != 1:
            e += 2
    d = modinv(e, phi)
    return (N, e, d, p, q)

# ---------- Wiener small-d attack ----------

def cont_frac(num, den):
    """Simple continued fraction of num/den."""
    cf = []
    while den:
        q = num // den
        cf.append(q)
        num, den = den, num - q * den
    return cf

def convergents(cf):
    """Generate convergents from a continued fraction."""
    conv = []
    num1, den1 = 1, 0
    num2, den2 = cf[0], 1
    conv.append((num2, den2))
    for a in cf[1:]:
        num1, den1, num2, den2 = num2, den2, a * num2 + num1, a * den2 + den1
        conv.append((num2, den2))
    return conv

def wiener_attack(N, e):
    """Attempt Wiener attack. Returns (d, p, q) or None."""
    cf = cont_frac(e, N)
    conv = convergents(cf)
    for k, d in conv:
        if k == 0:
            continue
        # (ed - 1) must be divisible by k to give integer phi
        if (e * d - 1) % k != 0:
            continue
        phi = (e * d - 1) // k
        # Solve x^2 - (N - phi + 1)x + N = 0 for p, q
        s = N - phi + 1
        disc = s * s - 4 * N
        if disc < 0:
            continue
        t = isqrt(disc)
        if t * t != disc:
            continue
        p = (s + t) // 2
        q = (s - t) // 2
        if p * q == N and p > 1 and q > 1:
            return d, p, q
    return None


def demo_wiener():
    print("=== Demo: Wiener small-d attack on RSA ===")
    N, e, d, p, q = gen_weak_rsa(bits=512, d_bits=64)
    print("Generated weak RSA key:")
    print(f"  N (bits): {N.bit_length()}")
    print(f"  e: {e}")
    print(f"  d (bits): {d.bit_length()}  <-- deliberately small\n")

    # encrypt a small message
    message = 42
    c = pow(message, e, N)
    print(f"Encrypting message m = {message}")
    print(f"Ciphertext c = m^e mod N = {c}\n")

    # attacker sees only (N,e)
    print("Running Wiener attack with only (N, e)...")
    res = wiener_attack(N, e)
    if res is None:
        print("Wiener attack failed (this should not happen with our weak key).")
        return
    d_rec, p_rec, q_rec = res
    print("\nRecovered parameters:")
    print(f"  d' = {d_rec}")
    print(f"  p' = {p_rec}")
    print(f"  q' = {q_rec}")
    print(f"\nCorrect d? {d_rec == d}")

    # decrypt with recovered d
    m_rec = pow(c, d_rec, N)
    print(f"Decrypting with recovered d': m' = c^d' mod N = {m_rec}")
    print(f"Successful decryption? {m_rec == message}\n")

if __name__ == "__main__":
    demo_wiener()