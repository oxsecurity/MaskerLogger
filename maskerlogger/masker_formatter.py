import logging
import re
from typing import List
from maskerlogger.ahocorasick_regex_match import RegexMatcher

DEFAULT_SECRETS_CONFIG_PATH = "maskerlogger/config/gitleaks.toml"


class MaskerFormatter(logging.Formatter):
    def __init__(self, fmt=None, datefmt=None, style='%', validate=True,
                 defaults=None,
                 regex_config_path=DEFAULT_SECRETS_CONFIG_PATH):
        super().__init__(fmt, datefmt, style, validate=validate,
                         defaults=defaults)
        self.regex_matcher = RegexMatcher(regex_config_path)

    def format(self, record: logging.LogRecord) -> str:
        self._mask_sensitive_data(record)
        return super().format(record)

    def _mask_secret(self, msg: str, matches: List[re.Match]) -> str:
        for match in matches:
            for group in match.groups():
                msg = msg.replace(group, "*" * len(group))
            return msg

    def _mask_sensitive_data(self, record: logging.LogRecord) -> None:
        if found_matching_regex := self.regex_matcher.match_regex_to_line(record.msg):  # noqa
            record.msg = self._mask_secret(record.msg, found_matching_regex)
