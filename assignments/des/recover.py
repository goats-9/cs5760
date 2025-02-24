"""
OMEGA_1
L' = 00 00 04 00    R' = 00 00 00 20
A' = 00 00 04 00    a' = 00 00 00 20    wp 3/8
B' = 00 00 00 00    b' = 00 00 00 00    wp 1
C' = 00 00 04 00    c' = 00 00 00 20    wp 3/8
                    d' = 00 00 04 00

Except S6, all other S boxes have zero XOR input in the fourth round.

OMEGA_2
L' = 00 00 00 08    R' = 00 00 04 00
A' = 00 00 00 08    a' = 00 00 04 00    wp 11/32
B' = 00 00 00 00    b' = 00 00 00 00    wp 1
C' = 00 00 00 08    c' = 00 00 04 00    wp 11/32
                    d' = 00 00 00 08

Except S7 and S8, all other S boxes have zero XOR input in the fourth round.

F' = c' ^ D' ^ l'
When D' = 0, F' = c' ^ l'. Both are known values.
"""

# Imports
from util import *
from constants import *
from oracle.des import des_encrypt

random.seed(420)

# Constants
# Characteristic 1
OMEGA_1 = 0x00000400_00000020
S1 = [0, 1, 2, 3, 4, 6, 7]

# Characteristic 2
OMEGA_2 = 0x00000008_00000400
S2 = [0, 1, 2, 3, 4, 5]

ORACLE_URL='http://192.168.134.164:8000/'
# ORACLE_URL='http://127.0.0.1:5000/'
NUM_QUARTETS=50
NUM_TESTS=10

cache = Cache(ORACLE_URL)
q = Quartet(OMEGA_1, OMEGA_2, NUM_QUARTETS)

class Node:
    def __init__(self, mask: list[int]) -> None:
        self.mask = mask

def unite(a: Node, b: Node) -> Node:
    assert len(a.mask) == len(b.mask), f'Expected masks of same length, got {len(a.mask)} != {len(b.mask)}'
    return Node([am & bm for am, bm in zip(a.mask, b.mask)])

def max_clique(nodes: list[Node], n: Node, vis: int) -> int:
    if 0 in n.mask:
        return 0
    res = vis
    m = -1
    for i in range(len(nodes)):
        if vis & (1 << i):
            m = i
    for i in range(m + 1, len(nodes)):
        v = nodes[i]
        if vis & (1 << i):
            continue
        nn = unite(n, v)
        res = max(res, max_clique(nodes, nn, vis | (1 << i)), key=lambda x: x.bit_count())
    return res

k6 = [(1 << 64) - 1 for _ in range(8)]

for i, c, s in ((1, OMEGA_1 & 0xffffffff, S1), (2, OMEGA_2 & 0xffffffff, S2)):
    nodes = []
    for p0, p1 in q.get(i):
        c0 = transform(cache.get(transform(p0, FP)), IP)
        c1 = transform(cache.get(transform(p1, FP)), IP)
        f0 = c0 & 0xffffffff
        f1 = c1 & 0xffffffff
        se0 = transform(f0, E)
        se1 = transform(f1, E)
        l = (c0 ^ c1) >> 32 & 0xffffffff
        fo = c ^ l
        so = transform(fo, PI)
        mask = []
        for j in s:
            bm = 0
            sej0 = se0 >> 6 * (7 - j) & 0x3f
            sej1 = se1 >> 6 * (7 - j) & 0x3f
            soj = so >> 4 * (7 - j) & 0xf
            for k in range(1 << 6):
                if S[j].get(sej0 ^ k) ^ S[j].get(sej1 ^ k) == soj:
                    bm |= 1 << k
            mask.append(bm)
        nodes.append(Node(mask))
    start = Node([(1 << 64) - 1 for _ in s])
    cliq = max_clique(nodes, start, 0)
    for i in range(len(nodes)):
        if cliq & (1 << i):
            start = unite(start, nodes[i])
    for x, j in zip(start.mask, s):
        k6[j] &= x

subkey = 0

for x in k6:
    print(f'{x:064b}')

for x in k6:
    assert x.bit_count() == 1, f'Expected 1 suggested key, got {x.bit_count()}. Try again with another seed!'
    subkey <<= 6
    block = (x & -x).bit_length() - 1
    subkey |= block

other = []
for i in range(1, 65):
    if i not in K6 and i % 8:
        other.append(i)

master_key = list(x for x in f'{transform(subkey, K6I):064b}')

test_pt = [random.randint(0, (1 << 64) - 1) for _ in range(NUM_TESTS)]

# Brute force on remaining key bits
for k in range(1 << len(other)):
    key = master_key
    for i, j in enumerate(other):
        key[j - 1] = str(k >> i & 1)
    for i in range(8):
        sm = sum(ord(x) - ord('0') for x in key[8 * i: 8 * i + 7])
        key[8 * i + 7] = chr(ord('0') + ((sm + 1) & 1))
    fl = True
    for pt in test_pt:
        ct = cache.get(pt)
        test_ct = int(des_encrypt(f'{pt:064b}', ''.join(key)), 2)
        if ct != test_ct:
            fl = False
            break
    if fl:
        print(f'Key: {''.join(key)}')
        exit(0)
print('Cryptanalysis failed!')
exit(1)