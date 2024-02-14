RC = (
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A,
    0x8000000080008000, 0x000000000000808B, 0x0000000080000001,
    0x8000000080008081, 0x8000000000008009, 0x000000000000008A,
    0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
    0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
    0x000000000000800A, 0x800000008000000A, 0x8000000080008081,
    0x8000000000008080, 0x0000000080000001, 0x8000000080008008
)


def rotl(x, n):
    return (x << n) & (2 ** 64 - 1) | (x >> (64 - n))


def theta(state):
    c = [0] * 5
    d = [0] * 5

    for i in range(5):
        c[i] = state[i][0] ^ state[i][1] ^ state[i][2] ^ state[i][3] ^ state[i][4]

    for i in range(5):
        d[i] = c[(i - 1) % 5] ^ rotl(c[(i + 1) % 5], 1)
        for j in range(5):
            state[i][j] ^= d[i]

    return state


def rho_pi(state):
    x, y = 1, 0
    cur = state[x][y]
    for t in range(24):
        x, y = y, (2 * x + 3 * y) % 5
        cur, state[x][y] = state[x][y], rotl(cur, ((t + 1) * (t + 2) // 2) % 64)

    return state


def chi(state):
    new_state = [[0] * 5 for _ in range(5)]

    for i in range(5):
        for j in range(5):
            x = state[i][j]
            y = state[(i + 1) % 5][j]
            z = state[(i + 2) % 5][j]
            new_state[i][j] = x ^ ((~y) & z)

    return new_state


def iota(state, r_const):
    state[0][0] ^= r_const
    return state


def keccak_f(state):
    for i in range(24):
        state = theta(state)
        state = rho_pi(state)
        state = chi(state)
        state = iota(state, RC[i])

    return state


def absorb(state, m, r):
    w = 64
    # Go through the message in blocks of r bits
    for i in range(0, len(m), r // w * 8):
        # Go through the lanes of the state until capacity is reached
        for j in range(r // w):
            # Convert the block to a lane (64-bit integer)
            lane = int.from_bytes(m[i + j * 8:i + (j + 1) * 8], 'little')
            # XOR the lane with a lane of the state
            state[j % 5][j // 5] ^= lane
        # After processing a block, apply the permutation
        state = keccak_f(state)
    return state


def squeeze(state, r, outlen):
    z = b''
    while True:
        # Go through the bitrate part of the state
        for j in range(r // 64):
            # Convert the lane to bytes and append it to the output
            z += state[j % 5][j // 5].to_bytes(8, 'little')
        # If we have enough output, stop
        if len(z) >= outlen:
            break
        # Otherwise, apply the permutation and continue
        state = keccak_f(state)
    # Truncate the output to the desired length
    return z[:outlen]


def sponge(message, r, outlen):
    m = pad(message, r)
    state = [[0] * 5 for _ in range(5)]
    state = absorb(state, m, r)
    return squeeze(state, r, outlen)


def pad(m, r):
    # Add 0b10 (start of padding)
    m += b'\x06'
    # Add 0s until the message is a multiple of r bits
    m += b'\x00' * (r // 8 - len(m) % (r // 8) - 1)
    # Add 0b10000000 (end of padding)
    m += b'\x80'
    return m


def sha3_256(m):
    return sponge(m, 1088, 256 // 8)


def main():
    message = b'Hello, my name is SHA-3!'
    print(sha3_256(message).hex())


if __name__ == "__main__":
    main()
