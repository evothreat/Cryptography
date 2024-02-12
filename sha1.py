import struct

INITIAL_H = [
    0x67452301,
    0xEFCDAB89,
    0x98BADCFE,
    0x10325476,
    0xC3D2E1F0
]


def rotl(n, b):
    return ((n << b) | (n >> (32 - b))) & 0xFFFFFFFF


def pad(message):
    ml = len(message) * 8
    message += b'\x80'  # Represents 0b10000000
    message += b'\x00' * ((56 - len(message) % 64) % 64)
    message += struct.pack('>Q', ml)
    return message


def compress(block, h):
    ws = list(struct.unpack('>16I', block)) + [0] * 64

    for i in range(16, 80):
        ws[i] = rotl(ws[i - 3] ^ ws[i - 8] ^ ws[i - 14] ^ ws[i - 16], 1)

    a, b, c, d, e = h

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
            (rotl(a, 5) + f_out + e + k + ws[i]) & 0xFFFFFFFF,
            a,
            rotl(b, 30),
            c,
            d
        )

    return [
        (x + y) & 0xFFFFFFFF for x, y in zip(h, [a, b, c, d, e])
    ]


def sha1(message):
    message = pad(message)
    blocks = [message[i:i + 64] for i in range(0, len(message), 64)]
    last_hash = INITIAL_H

    for block in blocks:
        last_hash = compress(block, last_hash)

    return '%08x%08x%08x%08x%08x' % tuple(last_hash)


def main():
    sha1_hash = sha1(b'Hello, my name is SHA-1!')
    print("SHA-1:", sha1_hash)


if __name__ == '__main__':
    main()
