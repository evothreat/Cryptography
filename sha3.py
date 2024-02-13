# Implemenation of the SHA-3 hash function
from utils import bytes2bits

RCONST = (
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
    return (x << n) | (x >> (64 - n))


def theta(state):
    c = [state[x][0] ^ state[x][1] ^ state[x][2] ^ state[x][3] ^ state[x][4] for x in range(5)]
    d = [c[(x + 1) % 5] ^ rotl(c[(x - 1) % 5], 1) for x in range(5)]
    for x in range(5):
        for y in range(5):
            state[x][y] ^= d[x]

    return state


def rho(state):
    for i in range(5):
        for j in range(5):
            state[i][j] = rotl(state[i][j], ((i * (i + 1)) // 2 + j) % 64)

    return state


def pi(state):
    new_state = [[0 for _ in range(5)] for _ in range(5)]
    for i in range(5):
        for j in range(5):
            new_state[i][j] = state[(i + 3 * j) % 5][i]

    return new_state


def chi(state):
    new_state = [[0 for _ in range(5)] for _ in range(5)]
    for i in range(5):
        for j in range(5):
            new_state[i][j] = state[i][j] ^ ((~state[(i + 1) % 5][j]) & state[(i + 2) % 5][j])

    return new_state


def iota(state, round_constant):
    state[0][0] ^= round_constant
    return state


# Correct
def keccak_f(state):
    for i in range(24):
        state = theta(state)
        state = rho(state)
        state = pi(state)
        state = chi(state)
        state = iota(state, RCONST[i])

    return state


def absorb(state, m, r):
    for i in range(0, len(m), r // 8):
        for j in range(r // 8):
            state[j // 5][j % 5] ^= m[i + j]
        state = keccak_f(state)
    return state


def squeeze(state, r, outlen):
    z = b''
    while len(z) < r // 8:
        state = keccak_f(state)
        for i in range(5):
            for j in range(5):
                z += state[j][i].to_bytes(8, 'big')
    return z[:outlen]


def sponge(message, r, c, outlen):
    # Padding the message
    m = bytes2bits(pad(message, r))
    # Initialize the state
    state = [[0 for _ in range(5)] for _ in range(5)]
    # Absorbing phase
    state = absorb(state, m, r)
    # Squeezing phase
    return squeeze(state, r, outlen)


def pad(m, r):
    m += b'\x01'
    m += b'\x00' * (r // 8 - len(m) % (r // 8) - 1)
    m += b'\x80'
    return m


def sha3_256(message):
    return sponge(message, 1088, 512, 256 // 8)


def main():
    message = b'Hello, my name is SHA-3!'
    print(sha3_256(message))


if __name__ == "__main__":
    main()