from .aes_types import AesStep, AesKeySchedule
from .aes_constants import *

class AES:
    """
    Instantiation of AES cipher from S box and MC.
    """
    def _check_state(self, state: galois.FieldArray) -> None:
        """
        Check if the provided state is a valid field element.
        
        Parameters:
            state (galois.FieldArray): The state to check.
        
        Raises:
            ValueError: If the state is not a valid field element.
        """
        if not isinstance(state, galois.FieldArray) or state.shape != (4, 4):
            raise ValueError(f"State {state} must be a galois.FieldArray of shape (4, 4).")
        if type(state) is not GF_:
            raise ValueError(f"State {state} must be in the same field as the AES instance.")
    
    def _step_wrapper(self, step: AesStep, state: galois.FieldArray, key: galois.FieldArray, round: int) -> galois.FieldArray:
        """
        Wrapper to apply an AES transformation to the state.
        
        Parameters:
            state (galois.FieldArray): The state to transform.
            key (galois.FieldArray): The key for the transformation.
            round (int): The round number.
        
        Returns:
            galois.FieldArray: The transformed state.
        """
        # Check if the state is a valid field element
        self._check_state(state)
        # Check if the key is a valid field element
        self._check_state(key)
        # Perform the transformation
        res = step(state, key, round)
        # Check if the result is a valid field element
        self._check_state(res)
        return res

    def s_box(self, state: galois.FieldArray, key: galois.FieldArray, round: int) -> galois.FieldArray:
        return self._step_wrapper(self.s_box_, state, key, round)
    
    def inv_s_box(self, state: galois.FieldArray, key: galois.FieldArray, round: int) -> galois.FieldArray:
        return self._step_wrapper(self.inv_s_box_, state, key, round)
    
    def mix_columns(self, state: galois.FieldArray, key: galois.FieldArray, round: int) -> galois.FieldArray:
        return self._step_wrapper(self.mix_columns_, state, key, round)
    
    def inv_mix_columns(self, state: galois.FieldArray, key: galois.FieldArray, round: int) -> galois.FieldArray:
        return self._step_wrapper(self.inv_mix_columns_, state, key, round)

    def shift_rows(self, state: galois.FieldArray, inv: bool = False) -> galois.FieldArray:
        """
        Shift Rows transformation for AES.
        
        Parameters:
            state (galois.FieldArray): The state to transform.
            inv (bool): If True, apply the inverse transformation.
        
        Returns:
            galois.FieldArray: The transformed state.
        """
        # Check if the state is a valid field element
        self._check_state(state)
        # Perform the transformation
        res = np.roll(state, 1 if inv else -1, axis=1)
        # Regain type annotation
        res = GF_(res)
        # Check if the result is a valid field element
        self._check_state(res)
        return res
    
    def __init__(self,
        s_box: AesStep = aes_s_box_,
        inv_s_box: AesStep = aes_inv_s_box_,
        mix_columns: AesStep = aes_mix_columns_,
        inv_mix_columns: AesStep = aes_inv_mix_columns_,
        key_schedule: AesKeySchedule = aes_key_schedule_,
        key: galois.FieldArray | None = None,
        num_rounds: int = 10
    ) -> None:
        self.s_box_ = s_box
        self.inv_s_box_ = inv_s_box
        self.mix_columns_ = mix_columns
        self.inv_mix_columns_ = inv_mix_columns
        if key is None:
            # Pick a random master key
            self.key = GF_.Random((4, 4))
        else:
            # Use the provided key
            self.key = key
        # Check if the key is a valid field element
        self._check_state(self.key)
        self.num_rounds = num_rounds
        self.key_schedule = key_schedule(self.key, self.num_rounds)
    
    def encrypt(self, plaintext: galois.FieldArray) -> galois.FieldArray:
        """
        Encrypt the plaintext using the AES cipher.
        
        Parameters:
            plaintext (galois.FieldArray): The plaintext to encrypt.
        
        Returns:
            galois.FieldArray: The ciphertext.
        """
        # Check if the plaintext is a valid field element
        self._check_state(plaintext)
        
        # Get whitening key
        whitening_key = self.key_schedule[0]
        # Apply whitening key to plaintext
        plaintext = plaintext + whitening_key
        
        # Do rounds 1 to n - 1
        for i in range(1, self.num_rounds - 1):
            round_key = self.key_schedule[i]
            # Apply S-Box transformation
            plaintext = self.s_box(plaintext, round_key, i)
            # Apply Shift Rows transformation
            plaintext = self.shift_rows(plaintext)
            # Apply Mix Columns transformation
            plaintext = self.mix_columns(plaintext, round_key, i)
            # Add round key
            plaintext = plaintext + round_key
        
        # Do the last round (no Mix Columns)
        round_key = self.key_schedule[-1]
        # Apply S-Box transformation
        plaintext = self.s_box(plaintext, round_key, self.num_rounds - 1)
        # Apply Shift Rows transformation
        plaintext = self.shift_rows(plaintext)
        # Add round key
        plaintext = plaintext + round_key
        # Return the ciphertext
        return plaintext

    def decrypt(self, ciphertext: galois.FieldArray) -> galois.FieldArray:
        """
        Decrypt the ciphertext using the AES cipher.
        
        Parameters:
            ciphertext (galois.FieldArray): The ciphertext to decrypt.
            rounds (int): The number of rounds to perform. Must be a positive
            integer.
        
        Returns:
            galois.FieldArray: The plaintext.
        """
        # Check if the ciphertext is a valid field element
        self._check_state(ciphertext)
        
        # Get whitening key
        whitening_key = self.key_schedule[0]
        # Apply whitening key to ciphertext
        ciphertext = ciphertext + whitening_key
        
        # Do rounds n - 1 to 1
        for i in range(self.num_rounds - 1, 0, -1):
            round_key = self.key_schedule[i]
            # Apply Inverse S-Box transformation
            ciphertext = self.inv_s_box(ciphertext, round_key, i)
            # Apply Inverse Shift Rows transformation
            ciphertext = self.shift_rows(ciphertext, inv=True)
            # Apply Inverse Mix Columns transformation
            ciphertext = self.inv_mix_columns(ciphertext, round_key, i)
            # Add round key
            ciphertext = ciphertext + round_key
        
        # Do the last round (no Inverse Mix Columns)
        round_key = self.key_schedule[0]
        # Apply Inverse S-Box transformation
        ciphertext = self.inv_s_box(ciphertext, round_key, 0)
        # Apply Inverse Shift Rows transformation
        ciphertext = self.shift_rows(ciphertext, inv=True)
        # Add round key
        ciphertext = ciphertext + round_key
        # Return the plaintext
        return ciphertext