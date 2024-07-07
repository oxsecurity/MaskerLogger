import tomllib
import re
from typing import List
import ahocorasick


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

    def _load_config(self, config_path: str) -> dict:
        with open(config_path, 'rb') as f:
            return tomllib.load(f)

    def _extract_keywords_and_patterns(self, config) -> dict:
        keyword_to_patterns = {}
        for rule in config['rules']:
            for keyword in rule.get('keywords', []):
                if keyword not in keyword_to_patterns:
                    keyword_to_patterns[keyword] = []
                keyword_to_patterns[keyword].append(rule['regex'])
        return keyword_to_patterns

    def _filter_by_keywords(self, line):
        matched_regexes = set()
        for end_index, regex_values in self.automaton.iter(line):
            matched_regexes.update(regex_values)
        return matched_regexes

    def _get_match_regex(self, line, matched_regex) -> List[re.Match]:
        matches = []
        for pattern in matched_regex:
            regex = re.compile(pattern)
            if match := regex.search(line):
                matches.append(match)
        return matches

    def match_regex_to_line(self, line) -> re.Match:
        if matched_regxes := self._filter_by_keywords(line):
            return self._get_match_regex(line, matched_regxes)
