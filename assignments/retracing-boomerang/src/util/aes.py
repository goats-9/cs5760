from .aes_types import AesStep, AesKeySchedule
from .aes_constants import *

class AES:
    """
    Instantiation of AES cipher from S box and MC.
    """
    def _check_state(self, state) -> None:
        """
        Check if the provided state is a valid field element.
        
        Parameters:
            state (galois.FieldArray): The state to check.
        
        Raises:
            ValueError: If the state is not a valid field element.
        """
        assert isinstance(state, galois.FieldArray) and state.shape == (4, 4), \
            ValueError(f"State {state} must be a galois.FieldArray of shape (4, 4).")
        assert isinstance(state, GF_), \
            ValueError(f"State {state} must be in the same field as the AES instance.")
    
    def _step_wrapper(self, step: AesStep, state: galois.FieldArray, key: galois.FieldArray, round: int) -> galois.FieldArray:
        """
        Wrapper to apply an AES transformation to the state.
        
        Parameters:
            step (AesStep): The transformation function to apply.
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

    def s_box(self, state: galois.FieldArray, round: int) -> galois.FieldArray:
        return self._step_wrapper(self.s_box_, state, self.key_schedule[round], round)
    
    def inv_s_box(self, state: galois.FieldArray, round: int) -> galois.FieldArray:
        return self._step_wrapper(self.inv_s_box_, state, self.key_schedule[round], round)
    
    def mix_columns(self, state: galois.FieldArray, round: int) -> galois.FieldArray:
        return self._step_wrapper(self.mix_columns_, state, self.key_schedule[round], round)
    
    def inv_mix_columns(self, state: galois.FieldArray, round: int) -> galois.FieldArray:
        return self._step_wrapper(self.inv_mix_columns_, state, self.key_schedule[round], round)

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
        res = state.copy()
        for i in range(4):
            res[i] = np.roll(res[i], i * (1 if inv else -1))
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
        key: galois.FieldArray | bytes | None = None,
        num_rounds: int = 10
    ) -> None:
        self.s_box_ = s_box
        self.inv_s_box_ = inv_s_box
        self.mix_columns_ = mix_columns
        self.inv_mix_columns_ = inv_mix_columns
        if key is None:
            # Pick a random master key
            self.key = GF_.Random((4, 4), seed=rng_)
        elif type(key) is bytes:
            # Convert bytes to field element
            self.key = GF_(np.frombuffer(key, dtype=np.uint8).reshape((4, 4), order='F'))
        elif type(key) is galois.FieldArray:
            # Use the provided key
            self.key = key
        # Check if the key is a valid field element
        self._check_state(self.key)
        self.num_rounds = num_rounds
        self.key_schedule = key_schedule(self.key, self.num_rounds)

    def encrypt_(self, pt: galois.FieldArray) -> galois.FieldArray:
        state = pt.copy()
        # Apply whitening key to plaintext
        state += self.key_schedule[0]
        
        # Do rounds 1 to n - 1
        for i in range(1, self.num_rounds):
            # Apply S-Box transformation
            state = self.s_box(state, i)
            # Apply Shift Rows transformation
            state = self.shift_rows(state)
            # Apply Mix Columns transformation
            state = self.mix_columns(state, i)
            # Add round key
            state += self.key_schedule[i]
        
        # Do the last round (no Mix Columns)
        # Apply S-Box transformation
        state = self.s_box(state, self.num_rounds - 1)
        # Apply Shift Rows transformation
        state = self.shift_rows(state)
        # Add round key
        state += self.key_schedule[-1]
        # Return the ciphertext
        return state
    
    def encrypt_ronjom_(self, pt: galois.FieldArray) -> galois.FieldArray:
        state = pt.copy()
        state += self.key_schedule[0]
        state = self.s_box(state, 0)
        state = self.mix_columns(state, 0)
        state += self.key_schedule[1]
        state = self.shift_rows(state)
        state = self.s_box(state, 1)
        state = self.mix_columns(state, 1)
        state += self.key_schedule[2]
        state = self.s_box(state, 2)
        state = self.mix_columns(state, 2)
        state += self.key_schedule[3]
        state = self.shift_rows(state)
        state = self.s_box(state, 3)
        state = self.mix_columns(state, 3)
        state += self.key_schedule[4]
        state = self.s_box(state, 4)
        state += self.key_schedule[5]
        return state
    
    def encrypt(self, plaintext: bytes) -> bytes:
        """
        Encrypt the plaintext using the AES cipher.
        
        Parameters:
            plaintext (galois.FieldArray): The plaintext to encrypt.
        
        Returns:
            galois.FieldArray: The ciphertext.
        """
        pt = GF_(np.frombuffer(plaintext, dtype=np.uint8).reshape((4, 4), order='F'))
        # Check if the plaintext is a valid field element
        self._check_state(pt)
        return self.encrypt_(pt).flatten(order='F').tobytes()

    def decrypt_(self, ct: galois.FieldArray) -> galois.FieldArray:
        state = ct.copy()
        # Apply whitening key to ct
        state += self.key_schedule[-1]
        
        # Do rounds n - 1 to 1
        for i in range(self.num_rounds - 1, 0, -1):
            # Apply Inverse Shift Rows transformation
            state = self.shift_rows(state, inv=True)
            # Apply Inverse S-Box transformation
            state = self.inv_s_box(state, i)
            # Add round key
            state += self.key_schedule[i]
            # Apply Inverse Mix Columns transformation
            state = self.inv_mix_columns(state, i - 1)
        
        # Do the last round (no Inverse Mix Columns)
        # Apply Inverse Shift Rows transformation
        state = self.shift_rows(state, inv=True)
        # Apply Inverse S-Box transformation
        state = self.inv_s_box(state, 0)
        # Add round key
        state += self.key_schedule[0]
        # Return the plaintext
        return state

    def decrypt_ronjom_(self, ct: galois.FieldArray) -> galois.FieldArray:
        state = ct.copy()
        state += self.key_schedule[5]
        state = self.inv_s_box(state, 4)
        state += self.key_schedule[4]
        state = self.inv_mix_columns(state, 3)
        state = self.inv_s_box(state, 3)
        state = self.shift_rows(state, inv=True)
        state += self.key_schedule[3]
        state = self.inv_mix_columns(state, 2)
        state = self.shift_rows(state, inv=True)
        state = self.inv_s_box(state, 2)
        state += self.key_schedule[2]
        state = self.inv_mix_columns(state, 1)
        state = self.inv_s_box(state, 1)
        state = self.shift_rows(state, inv=True)
        state += self.key_schedule[1]
        state = self.inv_mix_columns(state, 0)
        state = self.inv_s_box(state, 0)
        state += self.key_schedule[0]
        return state

    def decrypt(self, ciphertext: bytes) -> bytes:
        """
        Decrypt the ciphertext using the AES cipher.
        
        Parameters:
            ciphertext (galois.FieldArray): The ciphertext to decrypt.
            rounds (int): The number of rounds to perform. Must be a positive
            integer.
        
        Returns:
            galois.FieldArray: The plaintext.
        """
        ct = GF_(np.frombuffer(ciphertext, dtype=np.uint8).reshape((4, 4), order='F'))
        # Check if the ciphertext is a valid field element
        self._check_state(ct)
        return self.decrypt_(ct).flatten(order='F').tobytes()