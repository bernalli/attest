"""Timestamp bounds shared by receipt evidence producers and verifiers."""

from typing import Final

# 9999-12-31T23:59:59Z: the last whole Unix second Python's datetime can render.
# JavaScript Date reaches further; both cores use this common upper bound.
MAX_REPRESENTABLE_UNIX_SECONDS: Final = 253402300799
