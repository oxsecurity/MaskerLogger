import logging
import os
import re
from abc import ABC

try:
    from pythonjsonlogger import json as jsonlogger
except ImportError:
    from pythonjsonlogger import jsonlogger

from maskerlogger.ahocorasick_regex_match import RegexMatcher
from maskerlogger.utils import TimeoutException

DEFAULT_SECRETS_CONFIG_PATH = os.path.join(os.path.dirname(__file__), "config/gitleaks.toml")
_APPLY_MASK = "apply_mask"
SKIP_MASK = {_APPLY_MASK: False}


class AbstractMaskedLogger(ABC):  # noqa B024
    """Abstract base class for loggers that mask sensitive data in log messages.

    This class provides the core functionality for detecting and masking sensitive
    information in log messages using regex patterns configured in a TOML file.
    """

    def __init__(
        self,
        regex_config_path: str = DEFAULT_SECRETS_CONFIG_PATH,
        redact: int = 100,
        timeout_seconds: int = 3,
    ) -> None:
        """Initialize the AbstractMaskedLogger.

        Args:
            regex_config_path: Path to the TOML configuration file containing regex patterns.
            redact: Percentage of sensitive data to redact (0-100). 100 means full masking.
            timeout_seconds: Timeout in seconds for regex matching operations to prevent hangs.

        Raises:
            FileNotFoundError: If the configuration file is not found.
            ValueError: If redact percentage is invalid or configuration is malformed.
        """
        self.regex_matcher = RegexMatcher(regex_config_path, timeout_seconds)
        self.redact = self._validate_redact(redact)

    @staticmethod
    def _validate_redact(redact: int | str) -> int:
        try:
            redact_int = int(redact)
        except (ValueError, TypeError) as e:
            raise ValueError(
                f"Redact value must be a number, got {type(redact).__name__}: {redact}"
            ) from e

        if not (0 <= redact_int <= 100):
            raise ValueError("Redact value must be between 0 and 100")

        return redact_int

    def _mask_secret(self, msg: str, matches: list[re.Match]) -> str:
        """Masks the sensitive data in the log message."""
        for match in matches:
            match_groups = list(match.groups()) if match.groups() else [match.group()]
            for group in match_groups:
                if not group:  # Skip empty groups
                    continue
                redact_length = int((len(group) / 100) * self.redact)
                if redact_length > 0:
                    # Replace only the beginning of the group with asterisks
                    masked_part = "*" * redact_length + group[redact_length:]
                    msg = msg.replace(group, masked_part, 1)

        return msg

    def _mask_sensitive_data(self, record: logging.LogRecord) -> None:
        """Applies masking to the sensitive data in the log message."""
        try:
            if found_matching_regex := self.regex_matcher.match_regex_to_line(record.msg):  # noqa
                record.msg = self._mask_secret(record.msg, found_matching_regex)
        except TimeoutException:
            pass


# Normal Masked Logger - Text-Based Log Formatter
class MaskerFormatter(logging.Formatter, AbstractMaskedLogger):
    def __init__(
        self,
        fmt: str,
        regex_config_path: str = DEFAULT_SECRETS_CONFIG_PATH,
        redact: int = 100,
        timeout_seconds: int = 3,
    ) -> None:
        """Initializes the MaskerFormatter.

        Args:
            fmt (str): Format string for the logger.
            regex_config_path (str): Path to the configuration file for regex patterns.
            redact (int): Percentage of the sensitive data to redact.
            timeout_seconds (int): Timeout in seconds for regex matching operations.
        """
        logging.Formatter.__init__(self, fmt)
        AbstractMaskedLogger.__init__(self, regex_config_path, redact, timeout_seconds)

    def format(self, record: logging.LogRecord) -> str:
        """Formats the log record as text and applies masking."""
        if getattr(record, _APPLY_MASK, True):
            self._mask_sensitive_data(record)

        return super().format(record)


# JSON Masked Logger - JSON-Based Log Formatter
class MaskerFormatterJson(jsonlogger.JsonFormatter, AbstractMaskedLogger):
    def __init__(
        self,
        fmt: str,
        regex_config_path: str = DEFAULT_SECRETS_CONFIG_PATH,
        redact: int = 100,
        timeout_seconds: int = 3,
    ) -> None:
        """Initializes the MaskerFormatterJson.

        Args:
            fmt (str): Format string for the logger.
            regex_config_path (str): Path to the configuration file for regex patterns.
            redact (int): Percentage of the sensitive data to redact.
            timeout_seconds (int): Timeout in seconds for regex matching operations.
        """
        jsonlogger.JsonFormatter.__init__(self, fmt)
        AbstractMaskedLogger.__init__(self, regex_config_path, redact, timeout_seconds)

    def format(self, record: logging.LogRecord) -> str:
        """Formats the log record as JSON and applies masking."""
        if getattr(record, _APPLY_MASK, True):
            self._mask_sensitive_data(record)

        return str(super().format(record))
