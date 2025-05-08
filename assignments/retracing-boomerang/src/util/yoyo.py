import numpy as np
import galois
from .aes import AES
from .aes_constants import GF_, rng_

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
    assert x.shape == y.shape, ValueError(f"Shapes of x and y must be equal, got {x.shape} and {y.shape}.")
    assert x.ndim == 2, ValueError(f"x and y must be 2D arrays, got {x.ndim}D.")
    for i in range(x.shape[1]):
        # Find the first word that is unequal in x and y
        if (x[:, i] != y[:, i]).any():
            # Swap this word and return
            x[:, [i]], y[:, [i]] = y[:, [i]], x[:, [i]]
            return x, y
    raise ValueError(f"Inputs to SimpleSWAP must be different, got {x}, {y}.")

def yoyo_distinguisher_5rd(aes: AES) -> tuple[bool, galois.FieldArray, galois.FieldArray]:
    """
    Implements the five round distinguisher for the AES cipher using the yoyo
    technique described in this paper:
    https://www.iacr.org/archive/asiacrypt2017/106240276/106240276.pdf
    
    Parameters:
        aes (AES): The AES cipher instance.
    
    Returns:
        tuple[bool, galois.FieldArray, galois.FieldArray]: A tuple containing a
        boolean indicating if the yoyo distinguisher was successful, and the two
        plaintexts used in the yoyo operation.
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
        # Generate random 128-bit plaintext pairs which differ only in the first
        # word.
        p0 = GF_.Random((4, 4), seed=rng_)
        p1 = p0.copy()
        p1[:, 0] = GF_.Random(4, seed=rng_)
        # Save a copy of the initial plaintexts
        p0_init = p0.copy()
        p1_init = p1.copy()
        # Initialize second counter
        cnt2 = 0
        wrong_pair = False
        while cnt2 < CNT2 and wrong_pair == False:
            cnt2 += 1
            # In the original paper, the first SR is stripped, so to get the
            # actual plaintexts we apply inverse SR.
            q0 = aes.shift_rows(p0, inv=True)
            q1 = aes.shift_rows(p1, inv=True)
            # Encrypt plaintexts
            d0 = aes.encrypt_(q0)
            d1 = aes.encrypt_(q1)
            # In the original paper, the last SR and MC are stripped, so we
            # apply inverse MC and SR to get the real ciphertexts that should be
            # compared. However, in an actual AES implementation, the last MC is
            # never applied, so we only need to apply inverse SR.
            c0 = aes.shift_rows(d0, inv=True)
            c1 = aes.shift_rows(d1, inv=True)
            # Perform the SimpleSWAP operation on the ciphertexts
            cc0, cc1 = simple_swap(c0, c1)
            # The actual ciphertexts are obtained by applying the last SR.
            dd0 = aes.shift_rows(cc0)
            dd1 = aes.shift_rows(cc1)
            # Perform decryption on the new ciphertexts to get friend pairs.
            qq0 = aes.decrypt_(dd0)
            qq1 = aes.decrypt_(dd1)
            # Apply SR to remove the last inverse SR. Again, the last MC is not
            # applied in an AES implementation so we don't account for it.
            pp0 = aes.shift_rows(qq0)
            pp1 = aes.shift_rows(qq1)
            # Check if there is a word with at least two equal bytes
            if (np.sum(pp0 == pp1, axis = 0) >= 2).any():
                # If there is, we have a wrong pair, so we break out of the loop
                wrong_pair = True
                break
            # Perform the yoyo by applying SimpleSWAP on the plaintexts
            p0, p1 = simple_swap(pp0, pp1)
        if wrong_pair == False:
            # This is AES
            return True, p0_init, p1_init
    return False, GF_.Zeros((4, 4)), GF_.Zeros((4, 4))
