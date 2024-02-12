import secrets


def xor_arrays(a, b):
    return [x ^ y for x, y in zip(a, b)]


def bits2int(bits):
    return int(''.join(map(str, bits)), 2)


def int2bits(value, min_size=8):
    bits = []
    while value or len(bits) < min_size:
        bits.append(value & 1)
        value >>= 1

    return bits[::-1]


def text2bits(input_str):
    res = []
    for byte in input_str.encode():
        res.extend(int2bits(byte))
    return res


def bits2text(bits):
    res = []
    for i in range(0, len(bits), 8):
        byte = bits[i:i + 8]
        res.append(bits2int(byte))

    return bytes(res).decode()


def random_bits(n):
    return [secrets.randbelow(2) for _ in range(n)]


def pkcs7_pad_bits(bits, block_size):
    # Calculate the number of bits to pad
    padding_size = block_size - (len(bits) % block_size)
    if padding_size == 0:
        padding_size = block_size  # Pad a full block if no padding is needed

    # Assume that bits list is always a multiple of 8 bits
    padding_size //= 8
    padding_bits = [int(b) for b in format(padding_size, '08b') * padding_size]
    return bits + padding_bits


def pkcs7_unpad_bits(bits):
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


def pkcs7_pad_bytes(byte_array, block_size):
    # Calculate the number of bytes to pad
    padding_size = block_size - (len(byte_array) % block_size)
    if padding_size == 0:
        padding_size = block_size  # Pad a full block if no padding is needed

    return byte_array + padding_size * bytes([padding_size])


def pkcs7_unpad_bytes(byte_array):
    padding_size = byte_array[-1]
    return byte_array[:-padding_size]


def bytes2int(byte_block):
    return int.from_bytes(byte_block, byteorder='big')


def int2bytes(integer, block_size):
    return integer.to_bytes(block_size, byteorder='big')
