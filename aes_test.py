import os

from aes import AES, ModeOfOperation


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
