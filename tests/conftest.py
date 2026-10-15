import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.pipeline import clear_all_caches  # noqa: E402


@pytest.fixture(autouse=True)
def _clean_caches():
    """Every test starts and ends with empty module-level caches."""
    clear_all_caches()
    yield
    clear_all_caches()
