from random import randbytes, randrange
import pytest
from aes.aes import AES, ModeOfOperation


class TestAesOpModes:
    @staticmethod
    @pytest.fixture(scope="class")
    def setup():
        key = randbytes(16)
        plaintext = randbytes(randrange(1, 1024))
        return key, plaintext

    @staticmethod
    def test_ecb(setup):
        key, plaintext = setup
        aes = AES(key, ModeOfOperation.ECB)

        ciphertext = aes.encrypt(plaintext)
        decrypted = aes.decrypt(ciphertext)

        assert plaintext == decrypted

    @staticmethod
    def test_cbc(setup):
        key, plaintext = setup
        aes = AES(key, ModeOfOperation.CBC)

        ciphertext = aes.encrypt(plaintext)
        decrypted = aes.decrypt(ciphertext)

        assert plaintext == decrypted

    @staticmethod
    def test_cfb(setup):
        key, plaintext = setup
        aes = AES(key, ModeOfOperation.CFB)

        ciphertext = aes.encrypt(plaintext)
        decrypted = aes.decrypt(ciphertext)

        assert plaintext == decrypted

    @staticmethod
    def test_ofb(setup):
        key, plaintext = setup
        aes = AES(key, ModeOfOperation.OFB)

        ciphertext = aes.encrypt(plaintext)
        decrypted = aes.decrypt(ciphertext)

        assert plaintext == decrypted

    @staticmethod
    def test_ctr(setup):
        key, plaintext = setup
        aes = AES(key, ModeOfOperation.CTR)

        ciphertext = aes.encrypt(plaintext)
        decrypted = aes.decrypt(ciphertext)

        assert plaintext == decrypted
