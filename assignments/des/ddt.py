"""
File        : ddt.py
Author      : Gautam Singh
Date        : 2025-02-27
Description : Compute the DDTs for each of the given weak S boxes.
"""

# Imports
import os
from util import *

# Create directory to store DDT files in
os.makedirs('ddt', exist_ok=True)
for i in range(8):
    # Write DDTs to file
    S[i].ddt(f'ddt/s{i + 1}.txt')
