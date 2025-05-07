import numpy as np
import galois
from .aes import AES
from .aes_constants import GF_

def simple_swap(x: galois.FieldArray, y: galois.FieldArray) -> tuple[galois.FieldArray, galois.FieldArray]:
    """
    Implements the SimpleSWAP algorithm described in Ronjom et. al.'s paper:
    https://www.iacr.org/archive/asiacrypt2017/106240276/106240276.pdf
    
    Parameters:
        x (galois.FieldArray): Word to swap.
        y (galois.FieldArray): Word to swap.
    
    Returns:
        tuple[galois.FieldArray, galois.FieldArray]: The words after applying 
        SimpleSWAP.
    """
    for i in range(4):
        # Find the first word that is unequal in x and y
        if (x[i] != y[i]).any():
            # Swap this word and return
            x[i], y[i] = y[i], x[i]
            return x, y
    raise ValueError(f"Inputs to SimpleSWAP must be different, got {x}, {y}.")

def yoyo_distinguisher_5rd(aes: AES) -> bool:
    """
    Implements the five round distinguisher for the AES cipher using the yoyo
    technique described in this paper:
    https://www.iacr.org/archive/asiacrypt2017/106240276/106240276.pdf
    
    Parameters:
        aes (AES): The AES cipher instance.
    
    Returns:
        bool: True if the cipher is AES, False otherwise.
    """
    # Ensure the AES instance has 5 rounds
    assert aes.num_rounds == 5, ValueError(f"AES instance must have 5 rounds, but got {aes.num_rounds}.")
    # Initialize limits
    CNT1 = 2 ** 13.4
    CNT2 = 2 ** 11.4
    # Initialize the first counter
    cnt1 = 0
    while cnt1 < CNT1:
        cnt1 += 1
        # Generate random 128-bit plaintext pairs which differ only in one word.
        # Here, we randomly generate one column for each plaintext and set the
        # other columns to zero.
        q0 = GF_.Zeros((4, 4))
        q1 = GF_.Zeros((4, 4))
        # Pick a random word that will differ
        col = np.random.randint(0, 4)
        q0[:, col] = GF_.Random(4)
        while True:
            q1[:, col] = GF_.Random(4)
            if (q0[:, col] != q1[:, col]).any():
                break
        # In the paper, the first SR is stripped, so we apply inverse SR to get
        # the real plaintexts that should go into the AES cipher.
        p0 = aes.shift_rows(q0, inv=True)
        p1 = aes.shift_rows(q1, inv=True)
        # Initialize second counter
        cnt2 = 0
        wrong_pair = False
        while cnt2 < CNT2 and wrong_pair == False:
            cnt2 += 1
            # Encrypt plaintexts
            d0 = aes.encrypt(p0)
            d1 = aes.encrypt(p1)
            # In the original paper, the last SR and MC are stripped, so we
            # apply inverse MC and SR to get the real ciphertexts that should be
            # compared. However, in an actual AES implementation, the last MC is
            # never applied, so we only need to apply inverse SR.
            c0 = aes.shift_rows(d0, inv=True)
            c1 = aes.shift_rows(d1, inv=True)
            # Perform the SimpleSWAP operation on the ciphertexts
            cc0, cc1 = simple_swap(c0, c1)
            # Perform decryption on the new ciphertexts to get friend pairs.
            qq0 = aes.decrypt(cc0)
            qq1 = aes.decrypt(cc1)
            # Apply SR to remove the last inverse SR. Again, the last MC is not
            # applied in this implementation.
            pp0 = aes.shift_rows(qq0)
            pp1 = aes.shift_rows(qq1)
            # Get the XOR of the two plaintexts
            p = pp0 + pp1
            # Check if there is a word with at least two zeros in the difference
            for i in range(4):
                zero_cnt = 0
                for j in range(4):
                    zero_cnt += p[j][i] == 0
                if zero_cnt >= 2:
                    # If there is, we have a wrong pair, so we break out of the loop
                    wrong_pair = True
                    break
            # Perform the yoyo by applying SimpleSWAP on the plaintexts
            p0, p1 = simple_swap(pp0, pp1)
        if wrong_pair == False:
            # This is AES
            return True
    return False
