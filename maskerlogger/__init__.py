"""
Init file for oxformatter package.
"""

from maskerlogger.masker_formatter import (
    MaskerFormatter,
    MaskerFormatterJson,
    mask_string,
)

# Expose the classes and main function
__all__ = [
    "MaskerFormatter",
    "MaskerFormatterJson",
    "mask_string",
]

__version__ = "0.4.0-beta.1"
