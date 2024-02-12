import struct


def lrot(n, b):
    return ((n << b) | (n >> (32 - b))) & 0xFFFFFFFF


def padding(message):
    ml = len(message) * 8
    message += b'\x80'  # Represents 0b10000000
    message += b'\x00' * ((56 - len(message) % 64) % 64)
    message += struct.pack('>Q', ml)
    return message


class SHA1:
    def __init__(self, message):
        self.h = [
            0x67452301,
            0xEFCDAB89,
            0x98BADCFE,
            0x10325476,
            0xC3D2E1F0
        ]
        self.hash_message(message)

    def compress(self, block):
        ws = list(struct.unpack('>16I', block)) + [0] * 64

        for i in range(16, 80):
            ws[i] = lrot(ws[i - 3] ^ ws[i - 8] ^ ws[i - 14] ^ ws[i - 16], 1)

        a, b, c, d, e = self.h

        for i in range(80):
            # Level 1
            if i < 20:
                f_out = (b & c) | ((~b) & d)
                k = 0x5A827999
            # Level 2
            elif i < 40:
                f_out = b ^ c ^ d
                k = 0x6ED9EBA1
            # Level 3
            elif i < 60:
                f_out = (b & c) | (b & d) | (c & d)
                k = 0x8F1BBCDC
            # Level 4
            else:
                f_out = b ^ c ^ d
                k = 0xCA62C1D6

            a, b, c, d, e = (
                (lrot(a, 5) + f_out + e + k + ws[i]) & 0xFFFFFFFF,
                a,
                lrot(b, 30),
                c,
                d
            )

        self.h[0] = (self.h[0] + a) & 0xFFFFFFFF
        self.h[1] = (self.h[1] + b) & 0xFFFFFFFF
        self.h[2] = (self.h[2] + c) & 0xFFFFFFFF
        self.h[3] = (self.h[3] + d) & 0xFFFFFFFF
        self.h[4] = (self.h[4] + e) & 0xFFFFFFFF

    def hash_message(self, message):
        message = padding(message)
        blocks = [message[i:i + 64] for i in range(0, len(message), 64)]

        for block in blocks:
            self.compress(block)

    def hexdigest(self):
        return '%08x%08x%08x%08x%08x' % tuple(self.h)


def main():
    message = b'Hello, my name is SHA-1!'
    sha1 = SHA1(message)
    print("SHA-1 hash:", sha1.hexdigest())


if __name__ == '__main__':
    main()
