import secrets

IV_SIZE = 80
KEY_SIZE = 80


def ascii_to_binary(input_str):
    binary_list = []
    for char in input_str:
        bin_char = format(ord(char), '08b')
        binary_list.extend(map(int, bin_char))
    return binary_list


def binary_to_ascii(binary_list):
    ascii_str = ""
    for i in range(0, len(binary_list), 8):
        bin_char = ''.join(map(str, binary_list[i:i + 8]))
        ascii_str += chr(int(bin_char, 2))
    return ascii_str


def random_bits(n):
    return [secrets.choice((0, 1)) for _ in range(n)]


class TriviumCipher:
    def __init__(self, key, iv):
        if len(key) != KEY_SIZE or len(iv) != IV_SIZE:
            raise ValueError("Key and IV must be 80 bits long")

        self.register_a = None
        self.register_b = None
        self.register_c = None
        self.key = key
        self.iv = iv

    def reset_state(self):
        self.register_a = self.iv + [0] * 13  # 93 bits
        self.register_b = self.key + [0] * 4  # 84 bits
        self.register_c = [0] * 108 + [1] * 3  # 111 bits

        for _ in range(4 * 288):
            self.clock()

    def clock(self):
        output_a = self.register_a[65] ^ self.register_a[92]
        output_b = self.register_b[68] ^ self.register_b[83]
        output_c = self.register_c[65] ^ self.register_c[110]

        input_a = self.register_a[68] ^ (self.register_c[108] & self.register_c[109]) ^ output_c
        input_b = self.register_b[77] ^ (self.register_a[90] & self.register_a[91]) ^ output_a
        input_c = self.register_c[86] ^ (self.register_b[81] & self.register_b[82]) ^ output_b

        self.register_a = [input_a] + self.register_a[:-1]
        self.register_b = [input_b] + self.register_b[:-1]
        self.register_c = [input_c] + self.register_c[:-1]

        return output_a ^ output_b ^ output_c

    def generate_keystream(self, n):
        for _ in range(n):
            yield self.clock()

    def encrypt(self, plaintext):
        self.reset_state()
        ciphertext = []
        for bit, key_bit in zip(plaintext, self.generate_keystream(len(plaintext))):
            ciphertext.append(bit ^ key_bit)
        return ciphertext

    def decrypt(self, ciphertext):
        return self.encrypt(ciphertext)


def main():
    key = random_bits(KEY_SIZE)
    iv = random_bits(IV_SIZE)
    trivium = TriviumCipher(key, iv)

    plaintext = "Hello, my name is Trivium!"
    ciphertext = trivium.encrypt(ascii_to_binary(plaintext))
    decrypted = binary_to_ascii(trivium.decrypt(ciphertext))

    print("Plaintext:", plaintext)
    print("Ciphertext:", ''.join(str(b) for b in ciphertext))
    print("Decrypted:", decrypted)


if __name__ == "__main__":
    main()
