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
            fix_masking_len: int = -1
    ):
        """Initializes the AbstractMaskedLogger.

        Args:
            fmt (str): Format string for the logger.
            regex_config_path (str): Path to the configuration file for regex patterns.
            fix_masking_len (int): Fixed length for masking sensitive data, -1 for dynamic masking.
        """
        self.fix_masking_len = fix_masking_len
        self.regex_matcher = RegexMatcher(regex_config_path)
        self.formatter = None  # To be defined by concrete implementations
        self.fmt = fmt

    def format(self, record: logging.LogRecord) -> str:
        """Formats the log record as text and applies masking."""
        if getattr(record, _APPLY_MASK, True):
            self._mask_sensitive_data(record)

        return self.formatter.format(record)

    def _mask_secret(self, msg: str, matches: List[re.Match]) -> str:
        """Masks the sensitive data in the log message."""
        for match in matches:
            match_groups = match.groups() if match.groups() else [match.group()]  # noqa
            for group in match_groups:
                replace_len = len(group) if self.fix_masking_len < 0 else self.fix_masking_len  # noqa
                msg = msg.replace(group, "*" * replace_len)

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
            fix_masking_len: int = -1
    ):
        """Initializes the MaskerFormatter.

        Args:
            fmt (str): Format string for the logger.
            regex_config_path (str): Path to the configuration file for regex patterns.
            fix_masking_len (int): Fixed length for masking sensitive data, -1 for dynamic masking.
        """
        super().__init__(fmt, regex_config_path, fix_masking_len)
        self.formatter = logging.Formatter(fmt)


# JSON Masked Logger - JSON-Based Log Formatter
class MaskerFormatterJson(MaskerFormatter):
    def __init__(
            self,
            fmt: str,
            regex_config_path: str = DEFAULT_SECRETS_CONFIG_PATH,
            fix_masking_len: int = -1
    ):
        """Initializes the MaskerFormatterJson.

        Args:
            fmt (str): Format string for the logger.
            regex_config_path (str): Path to the configuration file for regex patterns.
            fix_masking_len (int): Fixed length for masking sensitive data, -1 for dynamic masking.
        """
        super().__init__(fmt, regex_config_path, fix_masking_len)
        self.formatter = jsonlogger.JsonFormatter(fmt)
