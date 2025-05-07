import galois
from typing import Callable

AesStep = Callable[[galois.FieldArray, galois.FieldArray, int], galois.FieldArray]
AesKeySchedule = Callable[[galois.FieldArray, int], list[galois.FieldArray]]
