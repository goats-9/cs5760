"""
File        : recover.py
Author      : Gautam Singh
Date        : 2025-02-11
Description : Recover key for DES reduced to 6 rounds given black-box oracle 
              access.
"""

"""
Characteristic OMEGA_1:
L' = 00 00 04 00    R' = 00 00 00 20
A' = 00 00 04 00    a' = 00 00 00 20    wp 3/8
B' = 00 00 00 00    b' = 00 00 00 00    wp 1
C' = 00 00 04 00    c' = 00 00 00 20    wp 3/8

d' = 00 00 04 00
F' = c' ^ D' ^ l'

Except S6, input XOR to S boxes in fourth round are zero.

Characteristic OMEGA_2:
L' = 00 00 00 08    R' = 00 00 04 00
A' = 00 00 00 08    a' = 00 00 04 00    wp 11/32
B' = 00 00 00 00    b' = 00 00 00 00    wp 1
C' = 00 00 00 08    c' = 00 00 04 00    wp 11/32

d' = 00 00 00 08
F' = c' ^ D' ^ l'

Except S7, S8, input XOR to S boxes in fourth round are zero.
"""

# Imports
from util import *
from itertools import pairwise
from pydes import des

# Constants
ORACLE_URL="http://192.168.134.164:8000/"
OMEGA_1=0x00000400_00000020
OMEGA_2=0x00000008_00000400
NUM_PAIRS=100
NUM_TESTS=10

# Initialize ciphertext cache
cache = Cache(ORACLE_URL)

# Array of plaintext pairs (to be filtered after each step)
quartets = [Quartet(OMEGA_1, OMEGA_2) for _ in range(NUM_PAIRS)]

# Set of S boxes (0-indexed) having zero input/output XOR in fourth round
s1 = [0, 1, 2, 3, 4, 6, 7]
s2 = [0, 1, 2, 3, 4, 5]

# Master key
master_key = 0

# Final round subkey
k6 = 0

for i, c, s in ((0, OMEGA_1 & 0xffffffff, s1), (1, OMEGA_2 & 0xffffffff, s2)):
    # Counting for omega_i
    for a, b in pairwise(s):
        cnt = [0] * (1 << 12)
        for q in quartets:
            x0, x1, y0, y1 = q.get(i)
            # Have to analyze pairs (x0, x1), (y0, y1)
            for p0, p1 in ((x0, x1), (y0, y1)):
                # Get ciphertexts
                pc0 = cache.get(p0)
                pc1 = cache.get(p1)
                # Extract f, f^*
                f0 = pc0 & 0xffffffff
                f1 = pc1 & 0xffffffff
                # Get S_E and S_E^*
                se0 = permute(f0, E)
                se1 = permute(f1, E)
                # Extract l'
                l = (pc0 ^ pc1) >> 32 & 0xffffffff
                # Get F'. We need c' which we would get from a 
                # characteristic object. For now we will hardcode it.
                fo = l ^ c
                # Get S_O by applying inverse of P.
                so = permute(fo, PI)
                # Count for each pair of S boxes
                # Get S_Ea and S_Eb for f, f^*.
                sea0 = (se0 >> 6 * (7 - a)) & 0x3f
                sea1 = (se1 >> 6 * (7 - a)) & 0x3f
                seb0 = (se0 >> 6 * (7 - b)) & 0x3f
                seb1 = (se1 >> 6 * (7 - b)) & 0x3f
                # Get S_Oa and S_Ob, these are 4 bit outputs.
                soa = (so >> 4 * (7 - a)) & 0xf
                sob = (so >> 4 * (7 - a)) & 0xf
                # Go through all 2^12 combinations
                for k in range(1 << 12):
                    # Get S_Ka and S_Kb
                    ska = (k >> 6) & 0x3f
                    skb = k & 0x3f
                    # Perform the check
                    if S[a].get(sea0 ^ ska) ^ S[a].get(sea1 ^ ska) == soa and S[b].get(seb0 ^ skb) ^ S[b].get(seb1 ^ skb) == sob:
                        cnt[k] += 1
        # Take largest element
        k = max(enumerate(cnt), key=lambda x : x[1])[0]
        print(a, b, ":", k, cnt[k])
        # Get the 6 bit keys
        ka = k >> 6 & 0x3f
        kb = k & 0x3f
        k6 &= ~(0x3f << 6 * (7 - a))
        k6 &= ~(0x3f << 6 * (7 - b))
        k6 |= ka << 6 * (7 - a)
        k6 |= kb << 6 * (7 - b)

# K6 should be entirely found at this point. Let's add it to the key.

# Key bits of K6
K6 = [ 3, 44, 27, 17, 42, 10, 26, 50,
      60,  2, 41, 35, 25, 57, 19, 18, 
       1, 51, 52, 59, 58, 49, 11, 34,
      13, 23, 30, 45, 63, 62, 38, 21,
      31, 12, 14, 55, 20, 47, 29, 54,
       6, 15,  4,  5, 39, 53, 46, 22]

# Other key bits
other = []
for i in range(1, 65):
    if i not in K6 and i % 8 != 0:
        other.append(i)

for i, j in enumerate(K6):
    # master_key[K6[i]] = k6[i]
    master_key |= (k6 >> 63 - i & 1) << 64 - j

# We bruteforce the remaining eight master key bits and do trial encryption.

# Generate random plaintexts for trial encryption
test_pt = [random.randint(0, (1 << 64) - 1) for _ in range(NUM_TESTS)]

d = des()

for k in range(1 << 8):
    key = master_key
    for i, j in enumerate(other):
        key |= ((k >> i) & 1) << 64 - j
    # The actual key that will go into the DES encryption has every eighth bit
    # as a parity bit. So, construct it as such
    for i in range(8):
        # Take 8 bits at a time
        block = key >> 8 * i & 0xff
        key |= ((block.bit_count() & 1) ^ 1) << (8 * i + 7)
    # Perform trial encryption
    fl = True
    for p in test_pt:
        pb = p.to_bytes(8)
        cb = cache.get(p).to_bytes(8)
        fl = fl and d.encrypt(key.to_bytes(8), pb) == cb
    if fl:
        print(f"Cryptanalysis Successful!")
        print(f"Master key: {key}")
        exit(0)
print(f"Cryptanalysis Failed!")
exit(1)