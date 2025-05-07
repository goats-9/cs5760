import pytest
from .aes import AES
from .aes_constants import GF_
from .yoyo import yoyo_distinguisher_5rd, simple_swap

class TestYoyoClass:
    def test_simple_swap(self):
        # Test the simple swap function with two different words
        x = GF_([1, 2, 3, 4])
        y = GF_([5, 6, 7, 8])
        swapped_x, swapped_y = simple_swap(x, y)
        assert (swapped_x == GF_([5, 2, 3, 4])).all()
        assert (swapped_y == GF_([1, 6, 7, 8])).all()
    
    def test_simple_swap_same(self):
        with pytest.raises(ValueError):
            # Test the simple swap function with two identical words
            x = GF_([1, 2, 3, 4])
            y = GF_([1, 2, 3, 4])
            simple_swap(x, y)
    
    @pytest.mark.repeat(10)
    def test_yoyo_distinguisher_5rd(self):
        aes = AES(num_rounds=5)
        result = yoyo_distinguisher_5rd(aes)
        assert result is True, "Yoyo distinguisher failed for 5 rounds."