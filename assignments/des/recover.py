"""
File        : recover.py
Author      : Gautam Singh
Date        : 2025-02-27
Description : Recover the master key used in DES reduced to 6 rounds using 
              differential cryptanalysis techniques described in BS91.
"""

"""
Characteristics Used
--------------------

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
from des import des_encrypt, generate_subkeys

# Set seeds for reproducibility
random.seed(42)

# Constants
# Characteristic 1
OMEGA_1 = 0x00000400_00000020
S1 = [0, 1, 2, 3, 4, 6, 7]

# Characteristic 2
OMEGA_2 = 0x00000008_00000400
S2 = [0, 1, 2, 3, 4, 5]

# URL at which oracle is available
ORACLE_URL='http://192.168.134.164:8000/'

# Number of quartets needed
NUM_QUARTETS=50

# Number of tests to verify correctness of key recovery
NUM_TESTS=20

# Cache to store encryption results
cache = Cache(ORACLE_URL)

# Quartets for cryptanalysis
q = Quartet(OMEGA_1, OMEGA_2, NUM_QUARTETS)

class Node:
    """
    An object holding information contained in a node (representing a pair of
    plaintexts) used for generating cliques. In the context of BS91, the node
    contains bitmasks to indicate key values suggested by the particular
    plaintext pair, one for each individual S box.
    """
    def __init__(self, mask: list[int]) -> None:
        """
        Create a node given a list of masks.
        
        Parameters
        ----------
        mask: list[int]
            Array containing bitmasks (represented as integers for faster bit
            manipulations), one for each S box.
        """
        self.mask = mask

# "Merge" two nodes by taking the bitwise AND of their respective masks
def unite(a: Node, b: Node) -> Node:
    assert len(a.mask) == len(b.mask), f'Expected masks of same length, got {len(a.mask)} != {len(b.mask)}'
    return Node([am & bm for am, bm in zip(a.mask, b.mask)])

def max_clique(nodes: list[Node], n: Node, vis: int) -> int:
    """
    Recursive implementation of the clique algorithm as described in BS91.
    Returns a bitmask describing the members of the maximal clique.
    
    Paramters
    ---------
    nodes: list[Node]
        List of nodes in the graph, along with their masks.
    n: Node
        Node containing the bitwise AND of all nodes considered so far.
    vis: int
        Bitmask denoting which vertices are visited. A set bit denotes a visited
        vertex.
    
    Returns
    -------
    An bitmask as an `int` denoting the maximal clique in the given graph.
    """
    # Check if the current mask is valid
    if 0 in n.mask:
        return 0
    res = vis
    m = -1
    for i in range(len(nodes)):
        if vis & (1 << i):
            m = i
    # Consider nodes after the largest selected node
    for i in range(m + 1, len(nodes)):
        # Add new node
        v = nodes[i]
        nn = unite(n, v)
        # Update maximal clique
        res = max(res, max_clique(nodes, nn, vis | (1 << i)), key=lambda x: x.bit_count())
    # Return maximal clique
    return res

# K6, represented as a list of 8 6-bit integers
k6 = [(1 << 64) - 1 for _ in range(8)]

# Analyze each characteristic
for i, c, s in ((1, OMEGA_1 & 0xffffffff, S1), (2, OMEGA_2 & 0xffffffff, S2)):
    # Create nodes
    nodes = []
    for p0, p1 in q.get(i):
        # Query ciphertexts
        c0 = transform(cache.get(transform(p0, FP)), IP)
        c1 = transform(cache.get(transform(p1, FP)), IP)
        # Get f, f*
        f0 = c0 & 0xffffffff
        f1 = c1 & 0xffffffff
        # Get S_E, S_E*
        se0 = transform(f0, E)
        se1 = transform(f1, E)
        # Compute left half
        l = (c0 ^ c1) >> 32 & 0xffffffff
        # Compute S_O
        fo = c ^ l
        so = transform(fo, PI)
        # Generate masks
        mask = []
        # Compute suggested keys for each S box
        for j in s:
            bm = 0
            sej0 = se0 >> 6 * (7 - j) & 0x3f
            sej1 = se1 >> 6 * (7 - j) & 0x3f
            soj = so >> 4 * (7 - j) & 0xf
            # Check for each 6-bit key
            for k in range(1 << 6):
                if S[j].get(sej0 ^ k) ^ S[j].get(sej1 ^ k) == soj:
                    bm |= 1 << k
            mask.append(bm)
        nodes.append(Node(mask))
    # Create starting node
    start = Node([(1 << 64) - 1 for _ in s])
    # Get maximum clique
    cliq = max_clique(nodes, start, 0)
    # Compute masks of maximal clique
    for i in range(len(nodes)):
        if cliq & (1 << i):
            start = unite(start, nodes[i])
    # Find common bits with already suggested values 
    # from other characteristic (or initial value if not suggested).
    for x, j in zip(start.mask, s):
        k6[j] &= x

subkey = 0

# Create K6 block by block
for x in k6:
    assert x.bit_count() == 1, f'Expected 1 suggested key, got {x.bit_count()}. Try again with another seed!'
    subkey <<= 6
    # Get position of least significant set bit
    block = (x & -x).bit_length() - 1
    subkey |= block

# Find other key bits (except parity bits) that are unused.
other = []
for i in range(1, 65):
    if i not in K6 and i % 8:
        other.append(i)

# Create master key from known key bits (unknown ones are set to zero for now).
master_key = transform(subkey, K6I)

# Create test plaintexts for verification
test_pt = [random.randint(0, (1 << 64) - 1) for _ in range(NUM_TESTS)]

# Brute force on remaining key bits
for k in range(1 << len(other)):
    key = master_key
    # Add in remaining key bits
    for i, j in enumerate(other):
        key |= (k >> i & 1) << 64 - j
    # Compute parity bits
    for i in range(8):
        blk = key >> 8 * i & 0xff
        b = (blk.bit_count() + 1) & 1
        key |= b << 8 * i
    # Verify key created
    fl = True
    for pt in test_pt:
        ct = cache.get(pt)
        test_ct = int(des_encrypt(f'{pt:064b}', f'{key:064b}'), 2)
        if ct != test_ct:
            fl = False
            break
    if fl:
        # Output key and subkeys in binary format
        print(f'Master key: {key:064b}')
        print('Round subkeys')
        round_subkeys = generate_subkeys(f'{key:064b}')
        for i, ki in enumerate(round_subkeys):
            print(f'\tK{i+1}: {''.join(ki)}')
        exit(0)
# Ideally we should never reach here
print('Cryptanalysis failed!')
exit(1)