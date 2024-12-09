import tomli as toml
import re
from typing import List
import ahocorasick
from maskerlogger.utils import timeout


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
        with open(config_path, 'rb') as f:
            return toml.load(f)

    def _extract_keywords_and_patterns(self, config) -> dict:
        keyword_to_patterns = {}
        for rule in config['rules']:
            for keyword in rule.get('keywords', []):
                if keyword not in keyword_to_patterns:
                    keyword_to_patterns[keyword] = []

                keyword_to_patterns[keyword].append(self._get_compiled_regex(
                    rule['regex']))

        return keyword_to_patterns

    def _get_compiled_regex(self, regex: str) -> str:
        if '(?i)' in regex:
            regex = regex.replace('(?i)', '')
            return re.compile(regex, re.IGNORECASE)
        return re.compile(regex)

    def _filter_by_keywords(self, line):
        matched_regexes = set()
        for end_index, regex_values in self.automaton.iter(line):
            matched_regexes.update(regex_values)
        return matched_regexes

    @timeout(MAX_MATCH_TIMEOUT)
    def _get_match_regex(self, line: str,
                         matched_regex: List[re.Pattern]) -> List[re.Match]:
        matches = []
        for regex in matched_regex:
            if match := regex.search(line):
                matches.append(match)
        return matches

    def match_regex_to_line(self, line: str) -> re.Match:
        lower_case_line = line.lower()
        if matched_regxes := self._filter_by_keywords(lower_case_line):
            return self._get_match_regex(line, matched_regxes)
