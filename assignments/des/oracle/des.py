
# Weakened S-boxes
WEAK_S_BOXES = [
    # S1
    [[14, 1, 6, 3, 8, 5, 7, 10, 13, 9, 15, 12, 2, 4, 11, 0], 
     [15, 14, 2, 3, 4, 5, 7, 8, 6, 9, 0, 11, 12, 13, 1, 10], 
     [15, 1, 5, 3, 7, 2, 8, 13, 4, 9, 6, 11, 14, 10, 12, 0], 
     [4, 1, 5, 3, 8, 2, 6, 7, 10, 9, 15, 11, 12, 13, 14, 0]],

    # S2
    [[4, 12, 10, 3, 5, 1, 6, 2, 8, 9, 14, 11, 0, 13, 7, 15], 
     [12, 11, 9, 3, 14, 13, 6, 7, 8, 2, 10, 4, 0, 5, 1, 15], 
     [5, 14, 2, 13, 6, 4, 11, 15, 12, 9, 3, 0, 1, 10, 8, 7], 
     [1, 14, 2, 10, 7, 5, 6, 0, 8, 9, 12, 11, 4, 13, 3, 15]],

    # S3
    [[14, 12, 6, 3, 4, 5, 2, 7, 8, 9, 15, 11, 0, 13, 1, 10], 
     [0, 1, 2, 8, 13, 9, 10, 7, 3, 6, 12, 11, 4, 5, 14, 15], 
     [4, 1, 5, 3, 13, 2, 11, 7, 15, 9, 12, 0, 6, 8, 14, 10], 
     [0, 6, 2, 3, 7, 15, 10, 4, 13, 9, 1, 11, 14, 8, 12, 5]],

    # S4 
    [[12, 1, 0, 14, 4, 5, 6, 3, 10, 9, 2, 13, 8, 11, 7, 15], 
     [0, 1, 2, 15, 4, 5, 8, 7, 9, 12, 10, 11, 3, 13, 14, 6], 
     [3, 1, 2, 0, 9, 5, 11, 7, 6, 4, 13, 15, 14, 10, 12, 8], 
     [0, 1, 9, 3, 4, 5, 2, 7, 11, 15, 10, 8, 13, 12, 6, 14]],

    # S5
    [[14, 1, 7, 3, 8, 5, 6, 2, 4, 9, 10, 11, 0, 13, 12, 15], 
     [2, 5, 14, 3, 9, 4, 11, 7, 8, 1, 13, 6, 15, 10, 0, 12], 
     [0, 1, 5, 13, 7, 12, 10, 4, 3, 9, 2, 11, 14, 6, 8, 15], 
     [12, 1, 6, 9, 2, 5, 3, 8, 13, 7, 14, 0, 4, 11, 10, 15]],

    # S6
    [[0, 5, 2, 3, 8, 1, 6, 7, 4, 9, 15, 11, 12, 13, 14, 10], 
     [0, 1, 14, 3, 4, 5, 11, 10, 12, 9, 7, 6, 8, 13, 2, 15], 
     [12, 1, 2, 3, 4, 0, 11, 7, 6, 9, 15, 8, 5, 13, 14, 10], 
     [6, 3, 2, 1, 4, 5, 10, 7, 8, 9, 14, 11, 15, 13, 0, 12]],

    # S7
    [[2, 3, 1, 6, 5, 7, 4, 6, 9, 8, 11, 10, 13, 15, 14, 12], 
     [1, 0, 2, 3, 5, 4, 7, 6, 10, 11, 8, 9, 15, 12, 13, 14], 
     [1, 2, 3, 0, 4, 7, 5, 6, 8, 10, 9, 11, 12, 14, 15, 13], 
     [2, 1, 0, 3, 5, 7, 6, 4, 8, 10, 13, 9, 13, 14, 12, 15]],

    # S8
    [[12, 14, 7, 3, 9, 5, 6, 2, 10, 4, 8, 11, 1, 13, 0, 15], 
     [0, 11, 7, 3, 15, 5, 6, 2, 8, 9, 10, 1, 12, 13, 14, 4], 
     [0, 1, 9, 14, 4, 2, 10, 5, 13, 7, 15, 11, 12, 8, 3, 6], 
     [0, 1, 2, 3, 7, 5, 6, 4, 14, 11, 13, 9, 8, 10, 12, 15]]  

]

# Initial Permutation (IP) table
IP = [
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7
]

# Final Permutation (FP) table (inverse of IP)
FP = [
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41, 9, 49, 17, 57, 25
]

# Expansion Permutation (E) table
E = [
    32, 1, 2, 3, 4, 5,
    4, 5, 6, 7, 8, 9,
    8, 9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32, 1
]

# Permutation (P) table
P = [
    16, 7, 20, 21,
    29, 12, 28, 17,
    1, 15, 23, 26,
    5, 18, 31, 10,
    2, 8, 24, 14,
    32, 27, 3, 9, 
    19, 13, 30, 6, 
    22, 11, 4, 25
]

# Key Permutation (PC1) table
PC1 = [
    57, 49, 41, 33, 25, 17, 9,
    1, 58, 50, 42, 34, 26, 18,
    10, 2, 59, 51, 43, 35, 27,
    19, 11, 3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
    7, 62, 54, 46, 38, 30, 22,
    14, 6, 61, 53, 45, 37, 29,
    21, 13, 5, 28, 20, 12, 4
]

# Key Permutation (PC2) table
PC2 = [
    14, 17, 11, 24, 1, 5,
    3, 28, 15, 6, 21, 10,
    23, 19, 12, 4, 26, 8,
    16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32
]

# Number of left shifts for each round (6 rounds)
SHIFT_SCHEDULE = [1, 1, 2, 2, 2, 2]

# Convert a number to a binary string of a fixed length
def to_bin(n, length):
    return bin(n)[2:].zfill(length)

# Permute the input using the given permutation table
def permute(input_bits, table):
    return [input_bits[i - 1] for i in table]

# Perform a left shift on a list
def left_shift(bits, n):
    return bits[n:] + bits[:n]

def generate_subkeys(key):
    
    key_bits = permute(key, PC1)
    
    left = key_bits[:28]
    right = key_bits[28:]
    subkeys = []
    for shift in SHIFT_SCHEDULE:
        
        left = left_shift(left, shift)
        right = left_shift(right, shift)
        
        combined = left + right
        subkey = permute(combined, PC2)
        subkeys.append(subkey)
    return subkeys

def s_box_substitution(bits):
    result = []
    for i in range(8):
        # Extract 6 bits for the current S-box
        chunk = bits[i * 6:(i + 1) * 6]
        
        row = int(chunk[0] + chunk[5], 2)
        col = int(''.join(chunk[1:5]), 2)
        # Get the value from the S-box
        s_box_value = WEAK_S_BOXES[i][row][col]
        # Convert to 4 bits and append to result
        result.extend(list(to_bin(s_box_value, 4)))
    return result

# Perform the Feistel function
def feistel(right, subkey):
    # Expand the right half
    expanded = permute(right, E)
    # XOR with the subkey
    xor_result = [str(int(expanded[i]) ^ int(subkey[i])) for i in range(48)]

    substituted = s_box_substitution(xor_result)
    
    permuted = permute(substituted, P)
    return permuted

# Encrypt a block of data using 6-round DES
def des_encrypt(block, key):

    subkeys = generate_subkeys(key)
    
    block = permute(block, IP)

    left = block[:32]
    right = block[32:]
    
    for i in range(6):
        new_left = right
        new_right = [str(int(left[j]) ^ int(feistel(right, subkeys[i])[j])) for j in range(32)]
        left, right = new_left, new_right

    # Combine and apply final permutation
    combined = right + left
    ciphertext = permute(combined, FP)
    return ''.join(ciphertext)

# Decrypt a block of data using 6-round DES
def des_decrypt(block, key):
    
    subkeys = generate_subkeys(key)[::-1]
    
    block = permute(block, IP)
    
    left = block[:32]
    right = block[32:]
    
    for i in range(6):
        new_left = right
        new_right = [str(int(left[j]) ^ int(feistel(right, subkeys[i])[j])) for j in range(32)]
        left, right = new_left, new_right

    # Combine and apply final permutation
    combined = right + left
    plaintext = permute(combined, FP)
    return ''.join(plaintext)

if __name__ == "__main__":

    key = '0110100110101100011011101001111110010101011001110101001101001111'
    plaintext = '0110100110101100011011101001111110010101011001110101001101001111'

    # Encrypt
    ciphertext = des_encrypt(plaintext, key)
    print("Ciphertext:", ciphertext)

    # Decrypt
    decrypted = des_decrypt(list(ciphertext), key)
    print("Decrypted:", decrypted)
    
