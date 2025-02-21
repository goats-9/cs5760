import random
import requests
from bs4 import BeautifulSoup as BS

random.seed(0)

# S boxes
WEAK_S_BOXES = [
    [[14, 1, 6, 3, 8, 5, 7, 10, 13, 9, 15, 12, 2, 4, 11, 0], 
     [15, 14, 2, 3, 4, 5, 7, 8, 6, 9, 0, 11, 12, 13, 1, 10], 
     [15, 1, 5, 3, 7, 2, 8, 13, 4, 9, 6, 11, 14, 10, 12, 0], 
     [4, 1, 5, 3, 8, 2, 6, 7, 10, 9, 15, 11, 12, 13, 14, 0]],

    [[4, 12, 10, 3, 5, 1, 6, 2, 8, 9, 14, 11, 0, 13, 7, 15], 
     [12, 11, 9, 3, 14, 13, 6, 7, 8, 2, 10, 4, 0, 5, 1, 15], 
     [5, 14, 2, 13, 6, 4, 11, 15, 12, 9, 3, 0, 1, 10, 8, 7], 
     [1, 14, 2, 10, 7, 5, 6, 0, 8, 9, 12, 11, 4, 13, 3, 15]],

    [[14, 12, 6, 3, 4, 5, 2, 7, 8, 9, 15, 11, 0, 13, 1, 10], 
     [0, 1, 2, 8, 13, 9, 10, 7, 3, 6, 12, 11, 4, 5, 14, 15], 
     [4, 1, 5, 3, 13, 2, 11, 7, 15, 9, 12, 0, 6, 8, 14, 10], 
     [0, 6, 2, 3, 7, 15, 10, 4, 13, 9, 1, 11, 14, 8, 12, 5]],

    [[12, 1, 0, 14, 4, 5, 6, 3, 10, 9, 2, 13, 8, 11, 7, 15], 
     [0, 1, 2, 15, 4, 5, 8, 7, 9, 12, 10, 11, 3, 13, 14, 6], 
     [3, 1, 2, 0, 9, 5, 11, 7, 6, 4, 13, 15, 14, 10, 12, 8], 
     [0, 1, 9, 3, 4, 5, 2, 7, 11, 15, 10, 8, 13, 12, 6, 14]],

    [[14, 1, 7, 3, 8, 5, 6, 2, 4, 9, 10, 11, 0, 13, 12, 15], 
     [2, 5, 14, 3, 9, 4, 11, 7, 8, 1, 13, 6, 15, 10, 0, 12], 
     [0, 1, 5, 13, 7, 12, 10, 4, 3, 9, 2, 11, 14, 6, 8, 15], 
     [12, 1, 6, 9, 2, 5, 3, 8, 13, 7, 14, 0, 4, 11, 10, 15]],

    [[0, 5, 2, 3, 8, 1, 6, 7, 4, 9, 15, 11, 12, 13, 14, 10], 
     [0, 1, 14, 3, 4, 5, 11, 10, 12, 9, 7, 6, 8, 13, 2, 15], 
     [12, 1, 2, 3, 4, 0, 11, 7, 6, 9, 15, 8, 5, 13, 14, 10], 
     [6, 3, 2, 1, 4, 5, 10, 7, 8, 9, 14, 11, 15, 13, 0, 12]],

    [[2, 3, 1, 6, 5, 7, 4, 6, 9, 8, 11, 10, 13, 15, 14, 12], 
     [1, 0, 2, 3, 5, 4, 7, 6, 10, 11, 8, 9, 15, 12, 13, 14], 
     [1, 2, 3, 0, 4, 7, 5, 6, 8, 10, 9, 11, 12, 14, 15, 13], 
     [2, 1, 0, 3, 5, 7, 6, 4, 8, 10, 13, 9, 13, 14, 12, 15]],

    [[12, 14, 7, 3, 9, 5, 6, 2, 10, 4, 8, 11, 1, 13, 0, 15], 
     [0, 11, 7, 3, 15, 5, 6, 2, 8, 9, 10, 1, 12, 13, 14, 4], 
     [0, 1, 9, 14, 4, 2, 10, 5, 13, 7, 15, 11, 12, 8, 3, 6], 
     [0, 1, 2, 3, 7, 5, 6, 4, 14, 11, 13, 9, 8, 10, 12, 15]]  
]

# Initial permutation
IP = [58, 50, 42, 34, 26, 18, 10, 2,
      60, 52, 44, 36, 28, 20, 12, 4,
      62, 54, 46, 38, 30, 22, 14, 6,
      64, 56, 48, 40, 32, 24, 16, 8,
      57, 49, 41, 33, 25, 17,  9, 1,
      59, 51, 43, 35, 27, 19, 11, 3,
      61, 53, 45, 37, 29, 21, 13, 5,
      63, 55, 47, 39, 31, 23, 15, 7]

# Final permutation
FP = [40, 8, 48, 16, 56, 24, 64, 32,
      39, 7, 47, 15, 55, 23, 63, 31,
      38, 6, 46, 14, 54, 22, 62, 30,
      37, 5, 45, 13, 53, 21, 61, 29,
      36, 4, 44, 12, 52, 20, 60, 28,
      35, 3, 43, 11, 51, 19, 59, 27,
      34, 2, 42, 10, 50, 18, 58, 26,
      33, 1, 41,  9, 49, 17, 57, 25]

# Permutation made after each round
P = [16,  7, 20, 21, 29, 12, 28, 17,
      1, 15, 23, 26,  5, 18, 31, 10,
      2,  8, 24, 14, 32, 27,  3,  9,
     19, 13, 30,  6, 22, 11,  4, 25]

# Inverse of P
PI = [0] * 32
for i in range(32):
    PI[P[i] - 1] = i + 1

# Expansion matrix
E = [32,  1,  2,  3,  4,  5,
      4,  5,  6,  7,  8,  9,
      8,  9, 10, 11, 12, 13,
     12, 13, 14, 15, 16, 17,
     16, 17, 18, 19, 20, 21,
     20, 21, 22, 23, 24, 25,
     24, 25, 26, 27, 28, 29,
     28, 29, 30, 31, 32,  1]

# Apply permutation or any bitwise sequence (such as expansion)
def permute(x: int, p: list[int]) -> int:
    y = 0
    for j in reversed(p):
        y |= (x & 1) << j - 1
        x >>= 1
    return y

class Cache:
    def __init__(self, url: str) -> None:
        self.url = url
        self._cache: dict[int, int] = {}

    def encrypt(self, plaintext: int) -> int:
        """
        Query the black-box encryption oracle given a plaintext.
    
        Parameters
        ----------
        plaintext: int
            Plaintext for which corresponding ciphertext is required.
        url: str
            URL at which oracle is available.
    
        Returns
        -------
        Ciphertext corresponding to the queried plaintext.
        """
        print(f'Querying for {plaintext:016x}')
        # Convert plaintext to bitstring
        # Apply FP to get actual plaintext
        pt = f'{permute(plaintext, FP):064b}'
    
        # Make the request
        r = requests.post(url=self.url, data={
            'plaintext': pt,
        })
    
        # Parse the HTML response
        res = BS(r.text, features='lxml').find('p', {'class': ['alert-secondary']})

        # Ensure that the encrypted text exists
        if res is None:
            raise ValueError('Incorrect plaintext entered!')
    
        # Return the encrypted text, applying IP to undo FP
        ct = permute(int(res.text, 2), IP)
        return ct
    
    # def encrypt(self, plaintext: int) -> int:
    #     """
    #     Query the black-box encryption oracle given a plaintext.
    
    #     Parameters
    #     ----------
    #     plaintext: int
    #         Plaintext for which corresponding ciphertext is required.
    #     url: str
    #         URL at which oracle is available.
    
    #     Returns
    #     -------
    #     Ciphertext corresponding to the queried plaintext.
    #     """
    #     # Convert plaintext to bitstring
    #     # Apply FP to get actual plaintext
    #     pt = f'{permute(plaintext, FP):064b}'
    
    #     # Make the request
    #     r = requests.post(url=self.url, data={
    #         'plaintext': pt,
    #     })
    
    #     ct = r.json()["ciphertext"]
    #     assert len(ct) == 64, ValueError("Improper response!")
    #     return permute(int(ct, 2), IP)
    
    def insert(self, pt: int) -> None:
        if pt not in self._cache:
            self._cache[pt] = self.encrypt(pt)
    
    def get(self, pt: int) -> int:
        self.insert(pt)
        return self._cache[pt]

class Quartet:
    def __init__(self, a0: int, a1: int, p: int | None = None, block_size: int = 8) -> None:
        if p is None:
            p = random.randint(0, (1 << 8 * block_size) - 1)
        self.p = p
        self.a0 = a0
        self.a1 = a1

    def get(self, i: int) -> tuple[int, int, int, int]:
        if i not in [0, 1]:
            raise ValueError(f"Expected i to be either 0 or 1, got {i}.")
        if i == 0:
            return (self.p, self.p ^ self.a0, self.p ^ self.a1, self.p ^ self.a0 ^ self.a1)
        else:
            return (self.p, self.p ^ self.a1, self.p ^ self.a0, self.p ^ self.a0 ^ self.a1)

class SBoxDES:
    def __init__(self, s_box: list[list[int]]) -> None:
        """
        Create a 6-bit to 4-bit DES S box.
    
        Parameters
        ----------
        s_box: list[list[int]]
            4-by-16 list of outputs of the S box 
        """
        if len(s_box) != 4:
            raise ValueError('Incorrect dimensions for S box')
        for row in s_box:
            if len(row) != 16:
                raise ValueError('Incorrect dimensions for S box')
            for val in row:
                if val < 0 or val >= 16:
                    raise ValueError('Incorrect output for S box')
        self.s_box = s_box
    
    def get(self, index: int) -> int:
        """
        Function to get the output of the S box given the input.
        
        Parameters
        ----------
        index: int
            6-bit input to the S box
        
        Returns
        -------
        4-bit output of the S box for the given input.
        """
        # Get the first and last bits
        i = 2 * (index >> 5 & 1) + (index & 1)
        # Get the middle 4 bits
        j = index >> 1 & 0xf
        # Return the value
        return self.s_box[i][j]
    
    def ddt(self) -> list[list[int]]:
        """
        Calculates the differential distribution table (DDT) of the S box.

        Returns
        -------
        DDT as a `list[list[int]]`. For DES S boxes, the DDT has dimensions 64
        by 16.
        """
        ddt = [[0] * 16 for _ in range(64)]
        for i in range(64):
            for j in range(64):
                ddt[i ^ j][self.get(i) ^ self.get(j)] += 1
        return ddt

S = [SBoxDES(sbox) for sbox in WEAK_S_BOXES]
