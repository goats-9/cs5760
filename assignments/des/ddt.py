import os
from util import *

os.makedirs('ddt', exist_ok=True)
for i in range(8):
    S[i].ddt(f'ddt/s{i + 1}.txt')
