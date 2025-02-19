"""
File        : sbox.py
Author      : Gautam Singh
Date        : 2025-02-07
Description : Calculation of pairs XOR distribution tables for S boxes.
"""

import os
import pandas as pd
from util import *

# Create directories for DDT outputs.
os.makedirs('ddt', exist_ok=True)

# Compute DDTs and output to files.
for i in range(8):
    df = pd.DataFrame(S[i].ddt())
    df.to_csv(f'ddt/s{i + 1}.csv', header=False, index=False)
