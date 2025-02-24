import constants
import random
import requests
from bs4 import BeautifulSoup as BS

def transform(x: int, p: list[int]) -> int:
    sx = f'{x:0{max(p)}b}'
    sy = ''.join(sx[j - 1] if j > 0 else '0' for j in p)
    return int(sy, 2)

class Quartet:
    def __init__(self, a1: int, a2: int, size: int = 100) -> None:
        assert a1 >= 0 and a1.bit_length() <= 64, f'Expected XOR to be in [0, 2 ** 64), got {a1}.'
        assert a2 >= 0 and a2.bit_length() <= 64, f'Expected XOR to be in [0, 2 ** 64), got {a2}.'
        self.p = [random.randint(0, (1 << 64) - 1) for _ in range(size)]
        self.a1 = a1
        self.a2 = a2
    
    def get(self, i: int):
        assert i in [1, 2], f'Expected i to be either 1 or 2, got {i}.'
        x = self.a1
        y = self.a2
        if i == 2:
            x, y = y, x
        for pt in self.p:
            yield pt, pt ^ x
            yield pt ^ y, pt ^ x ^ y

class Cache:
    def __init__(self, url: str) -> None:
        self.url = url
        self._cache: dict[int, int] = {}

    def _query(self, pt: int) -> int:
        # Convert plaintext to binary
        plaintext = f'{pt:064b}'
        
        # Make the query
        r = requests.post(self.url, data={
            "plaintext": plaintext,
        })
        
        # Get the result from the rendered page
        res = BS(r.text, features='lxml').find('p', {'class': ['alert-secondary']})
        
        assert res is not None, AssertionError('Oracle query unsuccessful!')

        ct = int(res.text, 2)
        print(f'{pt:016x} ---> {ct:016x}')
        
        # Return the result.
        return ct
    
    # def _query(self, pt: int) -> int:
    #     # Apply FP to get actual plaintext
    #     # Convert plaintext to binary as well
    #     plaintext = f'{pt:064b}'
        
    #     # Make the query
    #     r = requests.post(self.url, data={
    #         "plaintext": plaintext,
    #     })
        
    #     # Get the result from the rendered page
    #     res = r.json()["ciphertext"]

    #     ct = int(res, 2)
    #     print(f'{pt:016x} ---> {ct:016x}')
        
    #     # Apply IP to reverse the effect of FP
    #     # and return the result.
    #     return ct
    
    def insert(self, pt: int) -> None:
        if pt not in self._cache:
            self._cache[pt] = self._query(pt)
    
    def get(self, pt: int) -> int:
        self.insert(pt)
        return self._cache[pt]

class SBoxDES:
    def __init__(self, s_box: list[list[int]]) -> None:
        assert len(s_box) == 4, f'Expected 4 rows, got {len(s_box)}.'
        for row in s_box:
            assert len(row) == 16, f'Expected 16 entries in row, got {len(row)}.'
            for val in row:
                assert val >= 0 and val < 16, f'Expected value to be in [0, 16), got {val}.'
        self._s_box = s_box
    
    def get(self, index: int) -> int:
        x = ((index >> 5 & 1) << 1) | (index & 1)
        y = index >> 1 & 0xf
        return self._s_box[x][y]
    
    def ddt(self, file: str) -> None:
        diff_dist = [[0] * 16 for _ in range(64)]
        for i in range(64):
            for j in range(64):
                diff_dist[i ^ j][self.get(i) ^ self.get(j)] += 1
        with open(file, 'w') as fh:
            header = '   ' + ' '.join(f'{i:2x}' for i in range(16))
            fh.write(header + '\n')
            for i in range(64):
                fh.write(f'{i:02x} ' + ' '.join(f'{j:2}' for j in diff_dist[i]) + '\n')
            
S = [SBoxDES(s_box) for s_box in constants.WEAK_S_BOXES]
