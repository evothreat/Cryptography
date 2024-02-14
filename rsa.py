"""
RSA Algorithm:

1. Key Generation:
   - Choose two large prime numbers p and q.
   - Calculate n = p * q.
   - Calculate totient φ(n) = (p-1) * (q-1).
      - φ(x) is the number of integers in the range [1, x-1] that are co-prime with x.
      - φ(x) = x - 1 if x is prime.
   - Choose an integer e such that 1 < e < φ and gcd(e, φ) = 1.
   - Calculate the modular multiplicative inverse d of e (mod φ).

2. Public Key (Encryption):
   - Public key is (n, e).
   - To encrypt a message M, calculate C ≡ M^e (mod n).

3. Private Key (Decryption):
   - Private key is (n, d).
   - To decrypt the ciphertext C, calculate M ≡ C^d (mod n).

4. Correctness:
   - Decryption of an encrypted message yields the original message:
     M ≡ (C^d) ≡ ((M^e)^d) ≡ M^(e*d) (mod n).
   - Proof:
       - Rules:
           - Euler's Theorem: a^φ(n) ≡ 1 (mod n) if gcd(a, n) = 1.
               - Fermat's Little Theorem:
                   1. a^p ≡ a (mod p) if p is prime.
                   2. a^(p-1) ≡ 1 (mod p) if p is prime and gcd(a, p) = 1.
               - Since φ(p) = p - 1, Euler's Theorem is a generalization of Fermat's Little Theorem.
           - Chinese Remainder Theorem (CRT):
               - Given a system of congruences:
                   x ≡ a_1 (mod m_1)
                   x ≡ a_2 (mod m_2)
                   ...
                   x ≡ a_n (mod m_n)
               - If gcd(m_i, m_j) = 1 for all i ≠ j, then the system has a unique solution for x mod (m_1 * m_2 * ... * m_n).
       - Since d is the modular multiplicative inverse of e (mod φ(n)), it follows that: (e * d) ≡ 1 (mod φ(n))
           - Can be written as: (e * d) = k * φ(n) + 1 for some integer k.
       - M^(e*d) (mod n) = M^(k*φ(n) + 1) (mod n) = (M^(φ(n))^k) * M (mod n)
       - Different cases:
           - If gcd(M, n) = 1, then M^(φ(n)) ≡ 1 (mod n) by Euler's Theorem.
               - M^(e*d) (mod n) = (M^(φ(n))^k) * M (mod n) = 1^k * M (mod n) = M (mod n).
           - If gcd(M, n) ≠ 1
               - Since p and q are co-prime, we can apply CRT to the system:
                   - M ≡ M^(e*d) (mod p)
                       - e*d = k*φ(n) + 1 = k*(p-1)*(q-1) + 1
                       - M^(e*d) (mod p) ≡ M^(k*(p-1)*(q-1) + 1) (mod p)
                                         ≡ ((M^(p-1))^(k*(q-1)) * M (mod p)
                                         ≡ 1^(k*(q-1)) * M (mod p)
                                         ≡ 1 * M (mod p)
                                         ≡ M (mod p)
                       - M ≡ M (mod p)
                       - For M = 0, the proof is trivial, since 0 = 0^(e*d) (mod p) = 0 (mod p).
                   - M ≡ M^(e*d) (mod q)
                       - The proof is similar to the one above.
           - Therefore, M^(e*d) (mod n) = M (mod n) for all M in Z_n.
"""
import random
import sys

from utils import bytes2int, int2bytes, random_nonzero_bytes

sys.setrecursionlimit(5000)

KEY_SIZE = 1024
BLOCK_SIZE = KEY_SIZE // 8
PADDING_SIZE = 11
PAYLOAD_SIZE = BLOCK_SIZE - PADDING_SIZE


def sqr_mult(b, e, m):
    res = 1
    for i in range(e.bit_length() - 1, -1, -1):
        res = (res * res) % m
        if (e >> i) & 1:
            res = (res * b) % m
    return res


def is_prime(num, k=5):
    if num <= 1:
        return False
    if num == 2 or num == 3:
        return True
    if num % 2 == 0:
        return False

    # Miller-Rabin primality test
    s, d = 0, num - 1
    while d % 2 == 0:
        s += 1
        d //= 2

    for _ in range(k):
        a = random.randint(2, num - 2)
        x = sqr_mult(a, d, num)
        if x == 1 or x == num - 1:
            continue
        for _ in range(s - 1):
            x = sqr_mult(x, 2, num)
            if x == num - 1:
                break
        else:
            return False

    return True


def extended_gcd(a, b):
    if a == 0:
        return b, 0, 1
    else:
        g, x, y = extended_gcd(b % a, a)
        return g, y - (b // a) * x, x


def mod_inverse(a, m):
    g, x, _ = extended_gcd(a, m)
    if g != 1:
        raise ValueError("The modular inverse does not exist.")
    else:
        return x % m


def generate_keypair(bits):
    p = generate_prime(bits)
    q = generate_prime(bits)

    n = p * q

    # Euler's totient function (φ)
    totient = (p - 1) * (q - 1)

    e = random.randrange(2, totient)
    while gcd(e, totient) != 1:
        e = random.randrange(2, totient)

    d = mod_inverse(e, totient)

    public_key = (n, e)
    private_key = (n, d)

    return public_key, private_key


def generate_prime(bits):
    while True:
        num = random.getrandbits(bits)
        if is_prime(num):
            return num


def gcd(a, b):
    while b:
        a, b = b, a % b
    return a


def pkcs1v15_pad(m, block_size):
    padding_size = block_size - len(m) - 3
    padding = random_nonzero_bytes(padding_size)
    return b'\x00\x02' + padding + b'\x00' + m


def pkcs1v15_unpad(m):
    if m.startswith(b'\x00\x02'):
        return m[m.index(b'\x00', 2) + 1:]
    return m


def encrypt(message, public_key):
    n, e = public_key
    ciphertext = []
    for i in range(0, len(message), PAYLOAD_SIZE):
        block = pkcs1v15_pad(message[i:i + PAYLOAD_SIZE], BLOCK_SIZE)
        byte_block = bytes2int(block)
        encrypted_block = sqr_mult(byte_block, e, n)
        ciphertext.append(encrypted_block)

    return ciphertext


def decrypt(ciphertext, private_key):
    n, d = private_key
    decrypted_text = []

    for encrypted_block in ciphertext:
        decrypted_block = sqr_mult(encrypted_block, d, n)
        byte_block = int2bytes(decrypted_block, BLOCK_SIZE)
        decrypted_text.extend(pkcs1v15_unpad(byte_block))

    return bytes(decrypted_text)


def main():
    public_key, private_key = generate_keypair(KEY_SIZE)

    message = "Hello, my name is RSA!"
    ciphertext = encrypt(message.encode(), public_key)
    decrypted = decrypt(ciphertext, private_key).decode()

    print("Plaintext:", message)
    print("Ciphertext:", ciphertext)
    print("Decrypted:", decrypted)


if __name__ == "__main__":
    main()
