import os

import pytest

from aes.aes import AES, ModeOfOperation


class TestAesOpModes:
    @staticmethod
    @pytest.fixture
    def setup():
        key = os.urandom(16)
        plaintext = os.urandom(1234)
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
