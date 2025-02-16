import logging
import os
import re
from abc import ABC
from typing import List

from pythonjsonlogger import jsonlogger

from maskerlogger.ahocorasick_regex_match import RegexMatcher

DEFAULT_SECRETS_CONFIG_PATH = os.path.join(
    os.path.dirname(__file__), "config/gitleaks.toml"
)
_APPLY_MASK = 'apply_mask'
SKIP_MASK = {_APPLY_MASK: False}


class AbstractMaskedLogger(ABC):
    def __init__(
            self,
            fmt: str,
            regex_config_path: str = DEFAULT_SECRETS_CONFIG_PATH,
            redact=100
    ):
        """Initializes the AbstractMaskedLogger.

        Args:
            fmt (str): Format string for the logger.
            regex_config_path (str): Path to the configuration file for regex patterns.
            redact (int): Percentage of the sensitive data to redact.
        """
        self.fmt = fmt
        self.regex_matcher = RegexMatcher(regex_config_path)
        self.redact = redact

    @staticmethod
    def _validate_redact(redact: int) -> int:
        if not (0 <= int(redact) <= 100):
            raise ValueError("Redact value must be between 0 and 100")

        return int(redact)

    def _mask_secret(self, msg: str, matches: List[re.Match]) -> str:
        """Masks the sensitive data in the log message."""
        for match in matches:
            match_groups = match.groups() if match.groups() else [match.group()]  # noqa
            for group in match_groups:
                redact_length = int((len(group) / 100) * self.redact)
                msg = msg.replace(
                    group[:redact_length], "*" * redact_length, 1)

        return msg

    def _mask_sensitive_data(self, record: logging.LogRecord) -> None:
        """Applies masking to the sensitive data in the log message."""
        if found_matching_regex := self.regex_matcher.match_regex_to_line(record.msg):  # noqa
            record.msg = self._mask_secret(record.msg, found_matching_regex)


# Normal Masked Logger - Text-Based Log Formatter
class MaskerFormatter(AbstractMaskedLogger):
    def __init__(
            self,
            fmt: str,
            regex_config_path: str = DEFAULT_SECRETS_CONFIG_PATH,
            redact=100
    ):
        """Initializes the MaskerFormatter.

        Args:
            fmt (str): Format string for the logger.
            regex_config_path (str): Path to the configuration file for regex patterns.
            redact (int): Percentage of the sensitive data to redact.
        """
        super().__init__(fmt, regex_config_path, redact)
        self.formatter = logging.Formatter(fmt)

    def format(self, record: logging.LogRecord) -> str:
        """Formats the log record as text and applies masking."""
        if getattr(record, _APPLY_MASK, True):
            self._mask_sensitive_data(record)

        return self.formatter.format(record)


# JSON Masked Logger - JSON-Based Log Formatter
class MaskerFormatterJson(MaskerFormatter):
    def __init__(
            self,
            fmt: str,
            regex_config_path: str = DEFAULT_SECRETS_CONFIG_PATH,
            redact=100
    ):
        """Initializes the MaskerFormatterJson.

        Args:
            fmt (str): Format string for the logger.
            regex_config_path (str): Path to the configuration file for regex patterns.
            redact (int): Percentage of the sensitive data to redact.
        """
        super().__init__(fmt, regex_config_path, redact)
        self.formatter = jsonlogger.JsonFormatter(fmt)
