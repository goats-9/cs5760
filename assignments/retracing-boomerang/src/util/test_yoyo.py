import pytest
from .aes import AES
from .aes_constants import GF_
from .yoyo import yoyo_distinguisher_5rd, simple_swap

class TestYoyoClass:
    def test_simple_swap(self):
        # Test the simple swap function with two different states
        x = GF_([[1, 2], [3, 4]])
        y = GF_([[5, 6], [7, 8]])
        x_swapped, y_swapped = simple_swap(x, y)
        assert (x_swapped == GF_([[5, 2], [7, 4]])).all(), "Simple swap failed for x."
        assert (y_swapped == GF_([[1, 6], [3, 8]])).all(), "Simple swap failed for y."
    
    def test_simple_swap_same(self):
        with pytest.raises(ValueError):
            # Test the simple swap function with two identical states
            x = GF_([[1, 2], [3, 4]])
            y = GF_([[1, 2], [3, 4]])
            simple_swap(x, y)
    
    @pytest.mark.repeat(10)
    def test_yoyo_distinguisher_5rd(self):
        aes = AES(num_rounds=5)
        result = yoyo_distinguisher_5rd(aes)
        assert result is True, "Yoyo distinguisher failed for 5 rounds."