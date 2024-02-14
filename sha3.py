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


def bytes2lane(bytes_):
    res = 0
    for i in range(8):
        res |= bytes_[i] << (8 * i)
    return res


def lane2bytes(l):
    res = b''
    for i in range(8):
        res += (l >> (8 * i) & 0xFF).to_bytes(1, 'big')
    return res


def absorb(state, m, r):
    w = 64
    for i in range(0, len(m), r // w * 8):
        for j in range(r // w):
            state[j % 5][j // 5] ^= bytes2lane(m[i + j * 8:i + (j + 1) * 8])
        state = keccak_f(state)
    return state


def squeeze(state, r, outlen):
    z = b''
    while True:
        for j in range(r // 64):
            z += lane2bytes(state[j % 5][j // 5])
        if len(z) >= outlen:
            break
        state = keccak_f(state)
    return z[:outlen]


def sponge(message, r, outlen):
    m = pad(message, r)
    state = [[0] * 5 for _ in range(5)]
    state = absorb(state, m, r)
    return squeeze(state, r, outlen)


def pad(m, r):
    m += b'\x06'
    m += b'\x00' * (r // 8 - len(m) % (r // 8) - 1)
    m += b'\x80'
    return m


def sha3_256(message):
    return sponge(message, 1088, 256 // 8)


def main():
    message = b'Hello, my name is SHA-3!'
    print(sha3_256(message).hex())


if __name__ == "__main__":
    main()
