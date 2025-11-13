import re
from typing import Any

import ahocorasick
import tomli as toml

from maskerlogger.utils import timeout

RULES_KEY = "rules"
KEYWORDS_KEY = "keywords"
REGEX_KEY = "regex"


class RegexMatcher:
    """Efficient regex matcher using Aho-Corasick algorithm for keyword detection.

    This class loads regex patterns from a TOML configuration file and uses the
    Aho-Corasick algorithm to efficiently detect keywords before applying regex matching.
    This two-stage approach significantly improves performance for large pattern sets.
    """

    def __init__(self, config_path: str, timeout_seconds: int = 3) -> None:
        """Initialize the RegexMatcher.

        Args:
            config_path: Path to the TOML configuration file.
            timeout_seconds: Timeout for individual regex operations.

        Raises:
            FileNotFoundError: If config file doesn't exist.
            ValueError: If config is malformed or contains invalid regex patterns.
        """
        config = self._load_config(config_path)
        self.keyword_to_patterns = self._extract_keywords_and_patterns(config)
        self.automaton = self._initialize_automaton()
        self.timeout_seconds = timeout_seconds

    def _initialize_automaton(self) -> ahocorasick.Automaton:
        keyword_automaton = ahocorasick.Automaton()
        for keyword, regexs in self.keyword_to_patterns.items():
            keyword_automaton.add_word(keyword, (regexs))
        keyword_automaton.make_automaton()
        return keyword_automaton

    @staticmethod
    def _load_config(config_path: str) -> dict[str, Any]:
        try:
            with open(config_path, "rb") as f:
                return toml.load(f)  # type: ignore[no-any-return]
        except FileNotFoundError as e:
            raise FileNotFoundError(f"Configuration file not found: {config_path}") from e
        except Exception as e:
            raise ValueError(f"Failed to load configuration from {config_path}: {e}") from e

    def _extract_keywords_and_patterns(
        self, config: dict[str, Any]
    ) -> dict[str, list[re.Pattern[str]]]:
        if RULES_KEY not in config:
            raise ValueError(f"Configuration must contain a '{RULES_KEY}' key")

        keyword_to_patterns: dict[str, list[re.Pattern[str]]] = {}
        for rule in config[RULES_KEY]:
            for keyword in rule.get(KEYWORDS_KEY, []):
                if keyword not in keyword_to_patterns:
                    keyword_to_patterns[keyword] = []

                keyword_to_patterns[keyword].append(self._get_compiled_regex(rule[REGEX_KEY]))

        return keyword_to_patterns

    def safe_compile(self, pattern: str, flags: int = 0) -> re.Pattern[str]:
        """
        Safely compile Gitleaks (Go-style) regex for Python.
        Handles bad escapes like \\z.
        Preserves valid Python regex anchors like \\A, \\Z.
        Preserves regex escape sequences like \b, \\w, \\d, etc.
        """
        # Replace PCRE/Go-only tokens with Python equivalents
        pattern = pattern.replace(r"\z", r"\Z")

        return re.compile(pattern, flags)

    def _get_compiled_regex(self, regex: str) -> re.Pattern[str]:
        try:
            if "(?i)" in regex:
                regex = regex.replace("(?i)", "")
                return self.safe_compile(regex, re.IGNORECASE)
            return self.safe_compile(regex)
        except re.error as e:
            raise ValueError(f"Invalid regex pattern '{regex}': {e}") from e

    def _filter_by_keywords(self, line: str) -> set[re.Pattern[str]]:
        matched_regexes: set[re.Pattern[str]] = set()
        for _end_index, regex_values in self.automaton.iter(line):
            matched_regexes.update(regex_values)
        return matched_regexes

    @timeout(lambda self, *args, **kwargs: self.timeout_seconds)
    def _get_match_regex(
        self, line: str, matched_regex: list[re.Pattern[str]]
    ) -> list[re.Match[str]]:
        matches: list[re.Match[str]] = []
        for regex in matched_regex:
            matches.extend(regex.finditer(line))
        return matches

    def match_regex_to_line(self, line: str) -> list[re.Match[str]] | None:
        lower_case_line = line.lower()
        if matched_regxes := self._filter_by_keywords(lower_case_line):
            return self._get_match_regex(line, list(matched_regxes))
        return None
