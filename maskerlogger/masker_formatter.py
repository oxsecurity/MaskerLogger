import logging
import re
from typing import List
from maskerlogger.ahocorasick_regex_match import RegexMatcher
import os

DEFAULT_SECRETS_CONFIG_PATH = os.path.join(
    os.path.dirname(__file__), "config/gitleaks.toml")
_APPLY_MASK = 'apply_mask'
SKIP_MASK = {_APPLY_MASK: False}


class MaskerFormatter(logging.Formatter):
    def __init__(self, fmt=None, datefmt=None, style='%', validate=True,
                 defaults=None,
                 regex_config_path=DEFAULT_SECRETS_CONFIG_PATH,
                 redact=100):
        super().__init__(fmt, datefmt, style, validate=validate,
                         defaults=defaults)
        self.redact = self._validate_redact(redact)
        self.regex_matcher = RegexMatcher(regex_config_path)

    def _validate_redact(self, redact: int) -> int:
        if not (0 <= int(redact) <= 100):
            raise ValueError("Redact value must be between 0 and 100")
        return int(redact)

    def format(self, record: logging.LogRecord) -> str:
        if getattr(record, _APPLY_MASK, True):
            self._mask_sensitive_data(record)
        return super().format(record)

    def _mask_secret(self, msg: str, matches: List[re.Match]) -> str:
        for match in matches:
            match_groups = match.groups() if match.groups() else [match.group()]  # noqa
            for group in match_groups:
                redact_length = int((len(group) / 100) * self.redact)
                msg = msg.replace(
                    group[:redact_length], "*" * redact_length, 1)
            return msg

    def _mask_sensitive_data(self, record: logging.LogRecord) -> None:
        if found_matching_regex := self.regex_matcher.match_regex_to_line(record.msg):  # noqa
            record.msg = self._mask_secret(record.msg, found_matching_regex)
