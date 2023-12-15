"""
Polynomial representation: P(x) = x^n + p_(n-1) * x^(n-1) + ... + p_1 * x^1 + p_0 * x^0
Here, n is the degree of the polynomial, and p_(n-1), p_(n-2), ..., p_1, p_0 are binary coefficients (0 or 1).
x represents the state of the LFSR, and each power of x corresponds to a tapped bit position in the state,
moving from left to right.
The longest possible cycle length is 2^n - 1.
Example: For n=8 and coefficients (p_7=0, p_6=0, p_5=0, p_4=1, p_3=1, p_2=1, p_1=0, p_0=1),
the corresponding polynomial is P(x) = x^8 + x^4 + x^3 + x^2 + 1
"""


class LFSR:
    def __init__(self, seed, taps):
        self.state = int(seed, 2)
        self.degree = len(seed)
        self.taps = taps

    def shift(self):
        feedback = self._calc_feedback()
        output = self._get_output_bit()
        self._update_state(feedback)
        return output

    def _calc_feedback(self):
        feedback = 0
        for tap in self.taps:
            feedback ^= (self.state >> (self.degree - tap)) & 1
        return feedback

    def _get_output_bit(self):
        return self.state & 1

    def _update_state(self, feedback):
        self.state = (self.state >> 1) | (feedback << (self.degree - 1))

    def calc_period(self):
        init_state = self.state
        period = 0
        while True:
            self.shift()
            period += 1
            if self.state == init_state:
                break
        return period

    def generate(self, n):
        bits = []
        for _ in range(n):
            bits.append(self.shift())
        return bits


def main():
    seed = "100101"
    taps = [6, 5]
    lfsr = LFSR(seed, taps)
    print("Period:", lfsr.calc_period())
    print("Output:", lfsr.generate(8))


if __name__ == "__main__":
    main()
