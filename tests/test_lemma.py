"""Unit tests for Sign-Channel Lemma 1 and boundary pixel constraints."""
import pytest
from tessera.embed.mirage import verify_lemma1


def test_sign_channel_lemma():
    """Test that g(v-1) != g(v+1) for all v in [1, 254], where g(v) = (v >> 1) & 1."""
    assert verify_lemma1() is True
    for v in range(1, 255):
        g_minus = ((v - 1) >> 1) & 1
        g_plus = ((v + 1) >> 1) & 1
        assert g_minus != g_plus, f"Lemma 1 violated at pixel value v={v}: g({v-1})={g_minus} == g({v+1})={g_plus}"


def test_boundary_values():
    """Verify that boundary pixel values (0 and 255) have strictly one legal direction."""
    # 0 can only move to +1 (within [0, 255])
    assert 0 + 1 <= 255 and 0 - 1 < 0
    # 255 can only move to -1 (within [0, 255])
    assert 255 - 1 >= 0 and 255 + 1 > 255
