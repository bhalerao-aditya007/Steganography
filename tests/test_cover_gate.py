"""Unit tests for Cover Image Gate."""
import numpy as np
import pytest
from tessera.embed.cover_gate import check_cover


def test_cover_gate_valid():
    """Verify that a natural image passes the cover gate."""
    rng = np.random.default_rng(42)
    # Simulated natural texture
    img = np.clip(rng.normal(128, 25, size=(512, 512)), 1, 254).astype(np.uint8)
    ok, msg, metrics = check_cover(img)
    assert ok is True
    assert "passed" in msg.lower()


def test_cover_gate_saturated_fail():
    """Verify that an image with excessive 0 or 255 values is rejected."""
    img = np.full((512, 512), 128, dtype=np.uint8)
    # Saturate 10% of pixels to 0
    img[:100, :262] = 0
    ok, msg, metrics = check_cover(img, max_boundary_fraction=0.05)
    assert ok is False
    assert "boundary" in msg.lower()


def test_cover_gate_flat_fail():
    """Verify that an image with excessive flat blocks is rejected."""
    # Completely flat image
    img = np.full((512, 512), 120, dtype=np.uint8)
    ok, msg, metrics = check_cover(img, max_flat_block_fraction=0.35)
    assert ok is False
    assert "flat" in msg.lower()
