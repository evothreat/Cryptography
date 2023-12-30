import os
from enum import Enum

from utils import pkcs7_pad_bytes, pkcs7_unpad_bytes, xor_arrays

S_BOX = [
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
]

INV_S_BOX = [
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D,
]


def x_times(a):
    """
    Calculates the product of the polynomial p(x) and x in GF(2^8).
    Through recursion, we can compute the product of p(x) and x^n in GF(2^8) for any n.
    For example:
    - p(x) * x = x_times(p(x))
    - p(x) * x^2 = x_times(x_times(p(x)))
    - p(x) * x^3 = x_times(x_times(x_times(p(x)))

    The elements of GF(2^8) are represented as polynomials of degree 7 or lower:
        a(x) = a7 * x^7 + a6 * x^6 + ... + a1 * x + a0.
    However, the product of p(x) and x can result in a polynomial of degree 8 or higher.
    To ensure the result remains within the field, reduction is performed by taking
    the modulo operation with an irreducible polynomial x^8 + x^4 + x^3 + x + 1.
    """
    # Check if the MSB is set
    if a & 0x80:
        # If the MSB is 1, the left shift leads to an overflow, so we have to perform a reduction
        return ((a << 1) ^ 0x11B) & 0xFF
    else:
        # If the MSB is 0, a simple left shift is sufficient
        return a << 1


# Calculates the product of two polynomials in GF(2^8) using the Russian Peasant Multiplication algorithm.
def g_mult(a, b):
    # Initialize the product to 0
    p = 0
    # Perform Galois Field (GF) multiplication for 8 bits
    for _ in range(8):
        # If the LSB of b is 1
        if b & 1:
            # Add a to the result
            p ^= a
        # Divide b by 2
        b >>= 1
        # Multiply a by 2 in GF(2^8)
        a = x_times(a)
    # Return the final product
    return p


def _sub_bytes(state, s_box):
    for i in range(4):
        for j in range(4):
            state[i][j] = s_box[state[i][j]]


def sub_bytes(state):
    return _sub_bytes(state, S_BOX)


def inv_sub_bytes(state):
    return _sub_bytes(state, INV_S_BOX)


def shift_rows(state):
    for i in range(1, 4):
        state[i] = state[i][i:] + state[i][:i]


def inv_shift_rows(state):
    for i in range(1, 4):
        state[i] = state[i][-i:] + state[i][:-i]


def mix_columns(state):
    for i in range(4):
        col = [state[j][i] for j in range(4)]
        state[0][i] = g_mult(col[0], 2) ^ g_mult(col[1], 3) ^ col[2] ^ col[3]  # 2 * a0 + 3 * a1 + 1 * a2 + 1 * a3
        state[1][i] = col[0] ^ g_mult(col[1], 2) ^ g_mult(col[2], 3) ^ col[3]  # 1 * a0 + 2 * a1 + 3 * a2 + 1 * a3
        state[2][i] = col[0] ^ col[1] ^ g_mult(col[2], 2) ^ g_mult(col[3], 3)  # 1 * a0 + 1 * a1 + 2 * a2 + 3 * a3
        state[3][i] = g_mult(col[0], 3) ^ col[1] ^ col[2] ^ g_mult(col[3], 2)  # 3 * a0 + 1 * a1 + 1 * a2 + 2 * a3


def inv_mix_columns(state):
    for i in range(4):
        col = [state[j][i] for j in range(4)]
        state[0][i] = g_mult(col[0], 14) ^ g_mult(col[1], 11) ^ g_mult(col[2], 13) ^ g_mult(col[3], 9)
        state[1][i] = g_mult(col[0], 9) ^ g_mult(col[1], 14) ^ g_mult(col[2], 11) ^ g_mult(col[3], 13)
        state[2][i] = g_mult(col[0], 13) ^ g_mult(col[1], 9) ^ g_mult(col[2], 14) ^ g_mult(col[3], 11)
        state[3][i] = g_mult(col[0], 11) ^ g_mult(col[1], 13) ^ g_mult(col[2], 9) ^ g_mult(col[3], 14)


def add_round_key(state, round_key):
    for i in range(4):
        for j in range(4):
            # Since round_key is a list of columns, we need to transpose it by swapping i and j
            state[i][j] ^= round_key[j][i]


def rot_word(word):
    return word[1:] + word[:1]


def sub_word(word):
    return [S_BOX[b] for b in word]


def key_expansion(key):
    rcon = [1, 2, 4, 8, 16, 32, 64, 128, 27, 54]

    # Break the key into 4-byte words
    w = [key[i:i + 4] for i in range(0, len(key), 4)]

    for i in range(4, 44):
        temp = w[i - 1]

        if i % 4 == 0:
            temp = sub_word(rot_word(temp))
            temp[0] ^= rcon[i // 4 - 1]

        w_i = [w[i - 4][j] ^ temp[j] for j in range(4)]
        w.append(w_i)

    return [w[i:i + 4] for i in range(0, len(w), 4)]


# AES-128 operates on a 4x4 matrix of bytes in column-major order (also known as state matrix).
# For example, if we have a 16-byte array: b = [b0, b1, ..., b15]
# The state matrix is then:
# S = [[b0, b4, b8, b12],
#      [b1, b5, b9, b13],
#      [b2, b6, b10, b14],
#      [b3, b7, b11, b15]]
def array2matrix(arr):
    return [
        [arr[i], arr[i + 4], arr[i + 8], arr[i + 12]] for i in range(0, 4)
    ]


def matrix2array(mx):
    return [mx[i][j] for j in range(4) for i in range(4)]


def aes_encrypt_block(block, round_keys):
    # Create a 4x4 matrix from the block
    state = array2matrix(block)

    add_round_key(state, round_keys[0])

    for i in range(1, len(round_keys) - 1):
        sub_bytes(state)
        shift_rows(state)
        mix_columns(state)
        add_round_key(state, round_keys[i])

    # Final round without mix_columns
    sub_bytes(state)
    shift_rows(state)
    add_round_key(state, round_keys[-1])

    # Flatten the state matrix into a list
    return matrix2array(state)


def aes_decrypt_block(block, round_keys):
    state = array2matrix(block)

    add_round_key(state, round_keys[-1])
    inv_shift_rows(state)
    inv_sub_bytes(state)

    for i in range(len(round_keys) - 2, 0, -1):
        add_round_key(state, round_keys[i])
        inv_mix_columns(state)
        inv_shift_rows(state)
        inv_sub_bytes(state)

    add_round_key(state, round_keys[0])

    return matrix2array(state)


class ModeOfOperation(Enum):
    ECB = 0
    CBC = 1
    CFB = 2
    OFB = 3
    CTR = 4


class AES:
    def __init__(self, key, mode=ModeOfOperation.ECB):
        self.key = key
        self.round_keys = key_expansion(key)
        self.mode = mode

        self.encrypt_fn = getattr(self, f'encrypt_{mode.name.lower()}')
        self.decrypt_fn = getattr(self, f'decrypt_{mode.name.lower()}')

    def encrypt_ecb(self, plaintext):
        """
        Electronic Codebook (ECB) mode encrypts each plaintext block independently using the same key.

        Encryption of each block: C_i = E_K(P_i)
        """
        ciphertext = []

        for i in range(0, len(plaintext), 16):
            block = plaintext[i:i + 16]
            encrypted_block = aes_encrypt_block(block, self.round_keys)
            ciphertext.extend(encrypted_block)

        return bytes(ciphertext)

    def decrypt_ecb(self, ciphertext):
        plaintext = []

        for i in range(0, len(ciphertext), 16):
            block = ciphertext[i:i + 16]
            decrypted_block = aes_decrypt_block(block, self.round_keys)
            plaintext.extend(decrypted_block)

        return bytes(plaintext)

    def encrypt_cbc(self, plaintext):
        """
        Cipher Block Chaining (CBC) mode encrypts each plaintext block by XORing it with
        the previous ciphertext block before encryption.

        Encryption of first block: C_0 = E_K(P_0 XOR IV)
        Encryption of subsequent blocks: C_i = E_K(P_i XOR C_{i-1})
        """
        prev_block = os.urandom(16)
        ciphertext = [*prev_block]

        for i in range(0, len(plaintext), 16):
            block = plaintext[i:i + 16]
            block = xor_arrays(block, prev_block)
            encrypted_block = aes_encrypt_block(block, self.round_keys)
            ciphertext.extend(encrypted_block)
            prev_block = encrypted_block

        return bytes(ciphertext)

    def decrypt_cbc(self, ciphertext):
        """
        Decryption of first block: P_0 = D_K(C_0) XOR IV
        Decryption of subsequent blocks: P_i = D_K(C_i) XOR C_{i-1}
        """
        plaintext = []
        prev_block, ciphertext = ciphertext[:16], ciphertext[16:]

        for i in range(0, len(ciphertext), 16):
            block = ciphertext[i:i + 16]
            decrypted_block = xor_arrays(
                aes_decrypt_block(block, self.round_keys),
                prev_block
            )
            plaintext.extend(decrypted_block)
            prev_block = block

        return bytes(plaintext)

    def _process_cfb(self, text, prev_block):
        ciphertext = []

        for i in range(0, len(text), 16):
            block = text[i:i + 16]
            encrypted_block = xor_arrays(
                block,
                aes_encrypt_block(prev_block, self.round_keys)
            )
            ciphertext.extend(encrypted_block)
            prev_block = encrypted_block

        return bytes(ciphertext)

    def encrypt_cfb(self, plaintext):
        """
        Cipher Feedback (CFB) mode encrypts each plaintext block by XORing it with
        the previous ciphertext block after encryption.

        Encryption of first block: C_0 = P_0 XOR E_K(IV)
        Encryption of subsequent blocks: C_i = P_i XOR E_K(C_{i-1})
        """
        iv = os.urandom(16)
        ciphertext = self._process_cfb(plaintext, iv)
        return iv + ciphertext

    def decrypt_cfb(self, ciphertext):
        """
        Decryption of first block: P_0 = C_0 XOR E_K(IV)
        Decryption of subsequent blocks: P_i = C_i XOR E_K(C_{i-1})
        """
        iv, ciphertext = ciphertext[:16], ciphertext[16:]
        plaintext = self._process_cfb(ciphertext, iv)
        return plaintext

    def _process_ofb(self, text, prev_block):
        ciphertext = []

        for i in range(0, len(text), 16):
            block = text[i:i + 16]
            stream_block = aes_encrypt_block(prev_block, self.round_keys)
            encrypted_block = xor_arrays(block, stream_block)
            ciphertext.extend(encrypted_block)
            prev_block = stream_block

        return bytes(ciphertext)

    def encrypt_ofb(self, plaintext):
        """
        Output Feedback (OFB) mode encrypts each plaintext block by XORing it with
        the previous ciphertext block after encryption.
        The difference between CFB and OFB is that OFB uses the output of the block cipher
        as the keystream without XORing it with the plaintext (synchronous stream cipher).

        Encryption of first block:
        S_0 = E_K(IV)
        C_0 = P_0 XOR S_0

        Encryption of subsequent blocks:
        S_i = E_K(S_{i-1})
        C_i = P_i XOR S_i
        """
        iv = os.urandom(16)
        ciphertext = self._process_ofb(plaintext, iv)
        return iv + ciphertext

    def decrypt_ofb(self, ciphertext):
        """
        Decryption of first block:
        S_0 = E_K(IV)
        P_0 = C_0 XOR S_0

        Decryption of subsequent blocks:
        S_i = E_K(S_{i-1})
        P_i = C_i XOR S_i
        """
        iv, ciphertext = ciphertext[:16], ciphertext[16:]
        plaintext = self._process_ofb(ciphertext, iv)
        return plaintext

    def _process_ctr(self, plaintext, nonce):
        ciphertext = []
        counter = 0

        for i in range(0, len(plaintext), 16):
            block = plaintext[i:i + 16]
            stream_block = aes_encrypt_block(nonce + int.to_bytes(counter, 8, 'big'), self.round_keys)
            encrypted_block = xor_arrays(block, stream_block)
            ciphertext.extend(encrypted_block)
            counter += 1

        return bytes(ciphertext)

    def encrypt_ctr(self, plaintext):
        """
        Counter (CTR) mode encrypts each plaintext block by XORing it with
        the output of a block cipher encryption function.

        Encryption of first block:
        S_0 = E_K(IV || 0)
        C_0 = P_0 XOR S_0

        Encryption of subsequent blocks:
        S_i = E_K(IV || i)
        C_i = P_i XOR S_i
        """
        nonce = os.urandom(8)
        ciphertext = self._process_ctr(plaintext, nonce)
        return nonce + ciphertext

    def decrypt_ctr(self, ciphertext):
        """
        Decryption of first block:
        S_0 = E_K(IV || 0)
        P_0 = C_0 XOR S_0

        Decryption of subsequent blocks:
        S_i = E_K(IV || i)
        P_i = C_i XOR S_i
        """
        nonce, ciphertext = ciphertext[:8], ciphertext[8:]
        plaintext = self._process_ctr(ciphertext, nonce)
        return plaintext

    def encrypt(self, plaintext):
        return self.encrypt_fn(pkcs7_pad_bytes(plaintext, 16))

    def decrypt(self, ciphertext):
        return pkcs7_unpad_bytes(self.decrypt_fn(ciphertext))


class TestAES:
    def __init__(self, key=os.urandom(16), plaintext=os.urandom(16)):
        self.key = key
        self.plaintext = plaintext

    def test_ecb(self):
        aes = AES(self.key, ModeOfOperation.ECB)

        ciphertext = aes.encrypt(self.plaintext)
        decrypted = aes.decrypt(ciphertext)

        assert self.plaintext == decrypted
        print("ECB test passed")

    def test_cbc(self):
        aes = AES(self.key, ModeOfOperation.CBC)

        ciphertext = aes.encrypt(self.plaintext)
        decrypted = aes.decrypt(ciphertext)

        assert self.plaintext == decrypted
        print("CBC test passed")

    def test_cfb(self):
        aes = AES(self.key, ModeOfOperation.CFB)

        ciphertext = aes.encrypt(self.plaintext)
        decrypted = aes.decrypt(ciphertext)

        assert self.plaintext == decrypted
        print("CFB test passed")

    def test_ofb(self):
        aes = AES(self.key, ModeOfOperation.OFB)

        ciphertext = aes.encrypt(self.plaintext)
        decrypted = aes.decrypt(ciphertext)

        assert self.plaintext == decrypted
        print("OFB test passed")

    def test_ctr(self):
        aes = AES(self.key, ModeOfOperation.CTR)

        ciphertext = aes.encrypt(self.plaintext)
        decrypted = aes.decrypt(ciphertext)

        assert self.plaintext == decrypted
        print("CTR test passed")

    def run(self):
        self.test_ecb()
        self.test_cbc()
        self.test_cfb()
        self.test_ofb()
        self.test_ctr()


def main():
    test_aes = TestAES()
    test_aes.run()


if __name__ == "__main__":
    main()
