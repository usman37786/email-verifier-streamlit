"""Core email-verifier engine (Python source of truth for the pipeline)."""
from .models import (  # noqa: F401
    ERROR_CODES,
    Result,
    Status,
    StopCause,
    result_from_code,
)
