import tomli as toml
import re
from typing import List
import ahocorasick
from maskerlogger.utils import timeout
from collections import defaultdict


MAX_MATCH_TIMEOUT = 1


class RegexMatcher:
    def __init__(self, config_path: str) -> None:
        config = self._load_config(config_path)
        self.keyword_to_patterns = self._extract_keywords_and_patterns(config)
        self.automaton = self._initialize_automaton()

    def _initialize_automaton(self) -> ahocorasick.Automaton:
        keyword_automaton = ahocorasick.Automaton()
        for keyword, regexs in self.keyword_to_patterns.items():
            keyword_automaton.add_word(keyword, (regexs))
        keyword_automaton.make_automaton()

        return keyword_automaton

    @staticmethod
    def _load_config(config_path: str) -> dict:
        with open(config_path, "rb") as f:
            return toml.load(f)

    def _extract_keywords_and_patterns(
        self, config: dict
    ) -> dict[str, List[re.Pattern]]:
        """Extracts keywords and their corresponding regex patterns from the configuration file."""
        keyword_to_patterns = defaultdict(list)

        for rule in config["rules"]:
            for keyword in rule.get("keywords", []):
                keyword_to_patterns[keyword].append(
                    self._get_compiled_regex(rule["regex"])
                )

        return dict(keyword_to_patterns)

    def _get_compiled_regex(self, regex: str) -> re.Pattern[str]:
        """Compiles the regex pattern and returns the compiled pattern."""
        if "(?i)" in regex:
            regex = regex.replace("(?i)", "")
            return re.compile(regex, re.IGNORECASE)
        return re.compile(regex)

    def _filter_by_keywords(self, line: str) -> list[re.Pattern[str]]:
        """Filters the regex patterns based on the keywords present in the line."""

        matched_regexes = set()
        for _, regex_values in self.automaton.iter(line):
            matched_regexes.update(regex_values)

        return list(matched_regexes)

    @timeout(MAX_MATCH_TIMEOUT)
    def _get_match_regex(
        self,
        line: str,
        matched_regex: List[re.Pattern[str]],
    ) -> List[re.Match]:
        """Gets the matches of the regex patterns in the given line."""
        return [match for regex in matched_regex for match in regex.finditer(line)]

    def match_regex_to_line(self, line: str) -> list[re.Match[str]]:
        """Matches the regex patterns to the given line."""
        lower_case_line = line.lower()

        if matched_regexes := self._filter_by_keywords(lower_case_line):
            return self._get_match_regex(line, matched_regexes)
        return []
