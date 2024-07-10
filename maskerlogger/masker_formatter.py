import logging
import re
from typing import List
from ahocorasick_regex_match import RegexMatcher

DEFAULT_SECRETS_CONFIG_PATH = "maskerlogger/config/gitleaks.toml"
_APPLY_MASK = 'apply_mask'
SKIP_MASK = {_APPLY_MASK: False}


class MaskerFormatter(logging.Formatter):
    def __init__(self, fmt=None, datefmt=None, style='%', validate=True,
                 defaults=None,
                 regex_config_path=DEFAULT_SECRETS_CONFIG_PATH,
                 fix_masking_len=-1):
        super().__init__(fmt, datefmt, style, validate=validate,
                         defaults=defaults)
        self.fix_masking_len = fix_masking_len
        self.regex_matcher = RegexMatcher(regex_config_path)

    def format(self, record: logging.LogRecord) -> str:
        if getattr(record, _APPLY_MASK, True):
            self._mask_sensitive_data(record)
        return super().format(record)

    def _mask_secret(self, msg: str, matches: List[re.Match]) -> str:
        for match in matches:
            match_groups = match.groups() if match.groups() else [match.group()]  # noqa
            for group in match_groups:
                replace_len = len(group) if self.fix_masking_len < 0 else self.fix_masking_len # noqa
                msg = msg.replace(group, "*" * replace_len)
            return msg

    def _mask_sensitive_data(self, record: logging.LogRecord) -> None:
        if found_matching_regex := self.regex_matcher.match_regex_to_line(record.msg):  # noqa
            record.msg = self._mask_secret(record.msg, found_matching_regex)
