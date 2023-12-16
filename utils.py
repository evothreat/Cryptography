import secrets


def xor_arrays(a, b):
    return [x ^ y for x, y in zip(a, b)]


def bits_to_int(bits):
    return int(''.join(map(str, bits)), 2)


def int_to_bits(value, n):
    return list(map(int, format(value, '0{}b'.format(n))))


def ascii_to_bits(input_str):
    bits = []
    for char in input_str:
        bin_char = format(ord(char), '08b')
        bits.extend(map(int, bin_char))
    return bits


def bits_to_ascii(bits):
    ascii_str = ""
    for i in range(0, len(bits), 8):
        bin_char = ''.join(map(str, bits[i:i + 8]))
        ascii_str += chr(int(bin_char, 2))
    return ascii_str


def random_bits(n):
    return [secrets.choice((0, 1)) for _ in range(n)]


def pkcs7_bits_pad(bits, block_size):
    # Calculate the number of bits to pad
    padding_size = block_size - (len(bits) % block_size)
    if padding_size == 0:
        padding_size = block_size  # Pad a full block if no padding is needed

    # Assume that bits list is always a multiple of 8 bits
    padding_size //= 8
    padding_bits = [int(b) for b in format(padding_size, '08b') * padding_size]
    return bits + padding_bits


def pkcs7_bits_unpad(bits):
    padding_size = int(''.join(map(str, bits[-8:])), 2)
    return bits[:-padding_size * 8]


def add_parities(bits):
    # Add parity bits to each byte
    result = []
    for i in range(0, len(bits), 8):
        byte = bits[i:i + 8]
        parity = sum(byte) % 2
        result.extend(byte + [parity])
    return result
