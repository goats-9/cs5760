import constants
import random
import requests
from bs4 import BeautifulSoup as BS
from typing import Generator

# Apply a permutation on the bits of the input integer
def transform(x: int, p: list[int]) -> int:
    sx = f'{x:0{max(p)}b}'
    sy = ''.join(sx[j - 1] if j > 0 else '0' for j in p)
    return int(sy, 2)

class Quartet:
    """
    A class encapsulating multiple 64-bit quartets with the same fixed XORs.
    Given an arbitrary plaintext P with two fixed differences A and B, the
    4-tuple (P, P ^ A, P ^ B, P ^ A ^ B) forms a quartet.
    """
    def __init__(self, a1: int, a2: int, size: int) -> None:
        """
        Create a quartet given the fixed differences and size.

        Parameters
        ----------
        a1: int
            First fixed difference of the quartets
        a2: int
            Second fixed difference of the quartets
        size: int
            Number of quartets to be generated
        """
        # Ensure differences are valid
        assert a1 >= 0 and a1.bit_length() <= 64, f'Expected XOR to be in [0, 2 ** 64), got {a1}.'
        assert a2 >= 0 and a2.bit_length() <= 64, f'Expected XOR to be in [0, 2 ** 64), got {a2}.'
        # Generate random plaintexts, one for each quartet
        self.p = [random.randint(0, (1 << 64) - 1) for _ in range(size)]
        self.a1 = a1
        self.a2 = a2
    
    def get(self, i: int) -> Generator[tuple[int, int], int, None]:
        """
        Returns an iterator of pairs of plaintexts with a fixed XOR over all
        quartets.
        
        Paramters
        ---------
        i: int
            Indication of fixed XOR to be used (1 for a1, 2 for a2)
        
        Returns
        -------
        A `Generator` object that can be used to iterate over all desired
        plaintext pairs.    
        """
        assert i in [1, 2], f'Expected i to be either 1 or 2, got {i}.'
        x = self.a1
        y = self.a2
        if i == 2:
            x, y = y, x
        for pt in self.p:
            # Yield pairs to be iterated over
            yield pt, pt ^ x
            yield pt ^ y, pt ^ x ^ y

class Cache:
    """
    A cache that stores queries and corresponding responses from the oracle.
    """
    def __init__(self, url: str) -> None:
        """
        Initialize a cache.
        
        Parameters
        ----------
        url: str
            URL at which oracle is available
        """
        self.url = url
        self._cache: dict[int, int] = {}

    def _query(self, pt: int) -> int:
        """
        Method to actually query the oracle (and perform pre/post-processing if
        needed).
        
        Parameters
        ----------
        pt: int
            Plaintext to be encrypted by the oracle
        
        Returns
        -------
        The encryption of `pt` as an integer
        """
        # Convert plaintext to binary
        plaintext = f'{pt:064b}'
        
        # Make the query
        r = requests.post(self.url, data={
            "plaintext": plaintext,
        })
        
        # Get the result from the rendered page
        res = BS(r.text, features='lxml').find('p', {'class': ['alert-secondary']})
        
        assert res is not None, AssertionError('Oracle query unsuccessful!')

        # Convert binary string to integer
        ct = int(res.text, 2)
        
        # Print the query input and output in hex
        print(f'Plaintext: {pt:016x}\tCiphertext: {ct:016x}')
        
        # Return the result.
        return ct
    
    def insert(self, pt: int) -> None:
        """
        Insert a plaintext-ciphertext pair into the cache (if it has not already
        been inserted).

        Parameters
        ----------
        pt: int
            Plaintext to be inserted into the cache
        
        Returns
        -------
        None
        """
        if pt not in self._cache:
            self._cache[pt] = self._query(pt)
    
    def get(self, pt: int) -> int:
        """
        Cache and return the ciphertext corresponding to the given plaintext.
        
        Parameters
        ----------
        pt: int
            Plaintext to get the corresponding ciphertext for
        
        Returns
        -------
        The corresponding ciphertext of `pt` as an `int`.
        """
        self.insert(pt)
        return self._cache[pt]

class SBoxDES:
    """
    Object-oriented implementation of a DES S-box.
    """
    def __init__(self, s_box: list[list[int]]) -> None:
        """
        Instantiate a DES S-box.
        
        Parameters
        ----------
        s_box: list[list[int]]
            The 16-by-4 DES S box.
        """
        # Check dimensions and element ranges
        assert len(s_box) == 4, f'Expected 4 rows, got {len(s_box)}.'
        for row in s_box:
            assert len(row) == 16, f'Expected 16 entries in row, got {len(row)}.'
            for val in row:
                assert val >= 0 and val < 16, f'Expected value to be in [0, 16), got {val}.'
        self._s_box = s_box
    
    def get(self, index: int) -> int:
        """
        Get the output for a corresponding input to the S box

        Parameters
        ----------
        index: int
            An index in [0, 64) denoting the input to the S box.
        
        Returns
        -------
        The output from this S box corresponding to `index`.
        """
        # Check input range
        assert index >= 0 and index < 64, f'Expected input to be in [0, 64), got {index}.'
        # Extract first and last bit as row index
        x = ((index >> 5 & 1) << 1) | (index & 1)
        # Extract middle four bits as column index
        y = index >> 1 & 0xf
        # Index into the S box and return the value
        return self._s_box[x][y]
    
    def ddt(self, file: str) -> None:
        """
        Compute the differential distribution table for the given S box and
        write it to a text file.
        
        Parameters
        ----------
        file: str
            Location of file to write DDT to
        """
        # Create empty DDT
        diff_dist = [[0] * 16 for _ in range(64)]
        # Populate with all possible pairs of inputs
        for i in range(64):
            for j in range(64):
                diff_dist[i ^ j][self.get(i) ^ self.get(j)] += 1
        # Write to file with pretty printing
        with open(file, 'w') as fh:
            header = '   ' + ' '.join(f'{i:2x}' for i in range(16))
            fh.write(header + '\n')
            for i in range(64):
                fh.write(f'{i:02x} ' + ' '.join(f'{j:2}' for j in diff_dist[i]) + '\n')

# Create S box objects for all weak S boxes
S = [SBoxDES(s_box) for s_box in constants.WEAK_S_BOXES]
