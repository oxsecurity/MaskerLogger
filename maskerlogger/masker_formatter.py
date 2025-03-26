import logging
import os
import re
from abc import ABC
from typing import List, Optional

from pythonjsonlogger import jsonlogger

from maskerlogger.ahocorasick_regex_match import RegexMatcher

DEFAULT_SECRETS_CONFIG_PATH = os.path.join(
    os.path.dirname(__file__), "config/gitleaks.toml"
)
_APPLY_MASK = "apply_mask"
SKIP_MASK = {_APPLY_MASK: False}


__all__ = [
    "mask_string",
    "MaskerFormatter",
    "MaskerFormatterJson",
]


def _apply_asterisk_mask(msg: str, matches: List[re.Match[str]], redact: int) -> str:
    """Replace the sensitive data with asterisks in the given message."""
    for match in matches:
        match_groups = match.groups() if match.groups() else [match.group()]  # noqa
        for group in match_groups:
            redact_length = int((len(group) / 100) * redact)
            msg = msg.replace(group[:redact_length], "*" * redact_length, 1)

    return msg


def mask_string(
    msg: str,
    redact: int = 100,
    regex_config_path: str = DEFAULT_SECRETS_CONFIG_PATH,
) -> str:
    """Masks the sensitive data in the given string.

    Args:
        string (str): The string to mask.
        redact (int): Percentage of the sensitive data to
            redact.
        regex_config_path (str): Path to the configuration file for regex patterns.

    Returns:
        str: The masked string.
    """
    regex_matcher = RegexMatcher(regex_config_path)
    if found_matching_regexes := regex_matcher.match_regex_to_line(msg):
        msg = _apply_asterisk_mask(msg, found_matching_regexes, redact=redact)

    return msg


class AbstractMaskedLogger(ABC):
    def __init__(
        self,
        regex_config_path: str = DEFAULT_SECRETS_CONFIG_PATH,
        redact: int = 100,
    ):
        """Initializes the AbstractMaskedLogger.

        Args:
            regex_config_path (str): Path to the configuration file for regex patterns.
            redact (int): Percentage of the sensitive data to redact.
        """
        self.regex_config_path = regex_config_path
        self.redact = redact

    def _mask_sensitive_data(self, record: logging.LogRecord) -> None:
        """Applies masking to the sensitive data in the log message."""
        record.msg = mask_string(record.msg, self.redact, self.regex_config_path)


class MaskerFormatter(logging.Formatter, AbstractMaskedLogger):
    """A log formatter that masks sensitive data in text-based logs."""

    def __init__(
        self,
        fmt: Optional[str] = None,
        regex_config_path: str = DEFAULT_SECRETS_CONFIG_PATH,
        redact: int = 100,
    ):
        """Initializes the MaskerFormatter.

        Args:
            fmt (str): Format string for the logger.
            regex_config_path (str): Path to the configuration file for regex patterns.
            redact (int): Percentage of the sensitive data to redact.
        """
        logging.Formatter.__init__(self, fmt)
        AbstractMaskedLogger.__init__(self, regex_config_path, redact)

    def format(self, record: logging.LogRecord) -> str:
        """Formats the log record as text and applies masking."""
        if getattr(record, _APPLY_MASK, True):
            self._mask_sensitive_data(record)

        return super().format(record)


class MaskerFormatterJson(jsonlogger.JsonFormatter, AbstractMaskedLogger):
    """A JSON log formatter that masks sensitive data in json-based logs."""

    def __init__(
        self,
        fmt: Optional[str] = None,
        regex_config_path: str = DEFAULT_SECRETS_CONFIG_PATH,
        redact: int = 100,
    ):
        """Initializes the MaskerFormatterJson.

        Args:
            fmt (str): Format string for the logger.
            regex_config_path (str): Path to the configuration file for regex patterns.
            redact (int): Percentage of the sensitive data to redact.
        """
        jsonlogger.JsonFormatter.__init__(self, fmt)
        AbstractMaskedLogger.__init__(self, regex_config_path, redact)

    def format(self, record: logging.LogRecord) -> str:
        """Formats the log record as JSON and applies masking."""
        if getattr(record, _APPLY_MASK, True):
            self._mask_sensitive_data(record)

        return super().format(record)
