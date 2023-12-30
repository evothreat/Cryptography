import os
from enum import Enum

from aes_utils import key_expansion, aes_encrypt_block, aes_decrypt_block
from utils import xor_arrays, pkcs7_unpad_bytes, pkcs7_pad_bytes


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
        iv = prev_block = os.urandom(16)
        ciphertext = []

        for i in range(0, len(plaintext), 16):
            block = plaintext[i:i + 16]
            block = xor_arrays(block, prev_block)
            encrypted_block = aes_encrypt_block(block, self.round_keys)
            ciphertext.extend(encrypted_block)
            prev_block = encrypted_block

        return iv + bytes(ciphertext)

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

    def encrypt_cfb(self, plaintext):
        """
        Cipher Feedback (CFB) mode encrypts each plaintext block by XORing it with
        the previous ciphertext block after encryption.

        Encryption of first block: C_0 = P_0 XOR E_K(IV)
        Encryption of subsequent blocks: C_i = P_i XOR E_K(C_{i-1})
        """
        iv = prev_block = os.urandom(16)
        ciphertext = []

        for i in range(0, len(plaintext), 16):
            block = plaintext[i:i + 16]
            encrypted_block = xor_arrays(
                block,
                aes_encrypt_block(prev_block, self.round_keys)
            )
            ciphertext.extend(encrypted_block)
            prev_block = encrypted_block

        return iv + bytes(ciphertext)

    def decrypt_cfb(self, ciphertext):
        """
        Decryption of first block: P_0 = C_0 XOR E_K(IV)
        Decryption of subsequent blocks: P_i = C_i XOR E_K(C_{i-1})
        """
        prev_block, ciphertext = ciphertext[:16], ciphertext[16:]
        plaintext = []

        for i in range(0, len(ciphertext), 16):
            block = ciphertext[i:i + 16]
            decrypted_block = xor_arrays(
                block,
                aes_encrypt_block(prev_block, self.round_keys)
            )
            plaintext.extend(decrypted_block)
            prev_block = block

        return bytes(plaintext)

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
