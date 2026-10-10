"""Python bindings for the stixflayer STIX 2.1 engine.

Everything public is re-exported from the compiled Rust extension module
(``stixflayer.stixflayer``) so that ``import stixflayer`` exposes the full API.
"""

from stixflayer.stixflayer import *  # noqa: F403

# Re-export the structured exception hierarchy so callers can import them
# directly as ``stixflayer.ValidationError`` etc. The redundant aliases mark
# these names as intentional re-exports for linters and type checkers.
from stixflayer.stixflayer import (
    DeserializationError as DeserializationError,
    StixError as StixError,
    ValidationError as ValidationError,
)
