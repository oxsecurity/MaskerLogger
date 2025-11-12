import os

import pytest
import tomli

from maskerlogger.ahocorasick_regex_match import RegexMatcher

GITLEAKS_CONFIG_PATH = os.path.join(
    os.path.dirname(__file__), "..", "maskerlogger", "config", "gitleaks.toml"
)


@pytest.fixture
def config_path() -> str:
    return GITLEAKS_CONFIG_PATH


@pytest.fixture
def regex_matcher(config_path: str) -> RegexMatcher:
    return RegexMatcher(config_path)


def test_config_file_exists(config_path: str) -> None:
    assert os.path.exists(config_path), f"Config file not found at {config_path}"
    assert os.path.isfile(config_path), f"Config path is not a file: {config_path}"


def test_config_file_loads_successfully(config_path: str) -> None:
    matcher = RegexMatcher(config_path)
    assert matcher is not None
    assert matcher.keyword_to_patterns is not None
    assert len(matcher.keyword_to_patterns) > 0


def test_config_contains_rules(regex_matcher: RegexMatcher) -> None:
    assert len(regex_matcher.keyword_to_patterns) > 0


def test_all_regex_patterns_compile(regex_matcher: RegexMatcher) -> None:
    for keyword, patterns in regex_matcher.keyword_to_patterns.items():
        assert len(patterns) > 0, f"Keyword '{keyword}' has no patterns"
        for pattern in patterns:
            assert pattern is not None, f"Pattern for keyword '{keyword}' is None"


def test_automaton_initializes_successfully(regex_matcher: RegexMatcher) -> None:
    assert regex_matcher.automaton is not None
    assert len(regex_matcher.automaton) > 0


@pytest.mark.parametrize(
    "test_case",
    [
        "ghp_123456789012345678901234567890123456",
        "token=ghp_abcdefghijklmnopqrstuvwxyz123456",
        "GITHUB_TOKEN=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ123456",
    ],
)
def test_github_pat_detection(regex_matcher: RegexMatcher, test_case: str) -> None:
    matches = regex_matcher.match_regex_to_line(test_case)
    assert matches is not None, f"Failed to detect GitHub PAT in: {test_case}"
    assert len(matches) > 0, f"No matches found for: {test_case}"


@pytest.mark.parametrize(
    "test_case",
    [
        "AKIAIOSFODNN7EXAMPLE",
        "aws_access_key_id=AKIAIOSFODNN7EXAMPLE",
        "ASIAIOSFODNN7EXAMPLE",
    ],
)
def test_aws_access_key_detection(regex_matcher: RegexMatcher, test_case: str) -> None:
    matches = regex_matcher.match_regex_to_line(test_case)
    assert matches is not None, f"Failed to detect AWS key in: {test_case}"
    assert len(matches) > 0, f"No matches found for: {test_case}"


@pytest.mark.parametrize(
    "test_case",
    [
        "xoxb-1234567890-1234567890123-abcdefghijklmnopqrstuvwx",
        "slack_token=xoxb-1234567890-1234567890123-abcdefghijklmnopqrstuvwx",
        "xoxp-1234567890123-1234567890123-1234567890123-abcdefghijklmnopqrstuvwxyz1234",
    ],
)
def test_slack_token_detection(regex_matcher: RegexMatcher, test_case: str) -> None:
    matches = regex_matcher.match_regex_to_line(test_case)
    assert matches is not None, f"Failed to detect Slack token in: {test_case}"
    assert len(matches) > 0, f"No matches found for: {test_case}"


@pytest.mark.parametrize(
    "test_case",
    [
        "sk_test_1234567890123456789012345678901234567890",
        "STRIPE_KEY=sk_live_abcdefghijklmnopqrstuvwxyz1234567890",
        "rk_test_1234567890123456789012345678901234567890",
    ],
)
def test_stripe_key_detection(regex_matcher: RegexMatcher, test_case: str) -> None:
    matches = regex_matcher.match_regex_to_line(test_case)
    assert matches is not None, f"Failed to detect Stripe key in: {test_case}"
    assert len(matches) > 0, f"No matches found for: {test_case}"


@pytest.mark.parametrize(
    "test_case",
    [
        "sk-12345678901234567890T3BlbkFJ12345678901234567890",
        "OPENAI_API_KEY=sk-12345678901234567890T3BlbkFJ12345678901234567890",
    ],
)
def test_openai_api_key_detection(regex_matcher: RegexMatcher, test_case: str) -> None:
    matches = regex_matcher.match_regex_to_line(test_case)
    assert matches is not None, f"Failed to detect OpenAI key in: {test_case}"
    assert len(matches) > 0, f"No matches found for: {test_case}"


@pytest.mark.parametrize(
    "test_case",
    [
        "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOP\n-----END RSA PRIVATE KEY-----",
        "-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu\nKUpRKfFLfRYC9AIKjbJTWit+CqvjWYzvQwECAwEAAQJAIJLixBy2qpFoS4DSmoEm\no3qGy0t6z09AIJtH+5OeRV1be+N4cDYJKffGzDa88vQENZiRm0GRq6a+HPGQMd2k\nTQIhAKMSvzIBnni7ot/OSie2TmJLY4SwTQAevXysE2RbFDYdAiEBCUEaRQnMnbp7\n9mxDXDf6AU0cN/RPBjb9qSHDcWZHGzUCIG2Es59z8ugGrDY+pxLQnwfotadxd+Uy\nv/Ow5T0q5gIJAiEAyS4RaI9YG8EWx/2w0T67ZUVAw8eOMB6BIUg0Xcu+3okCIBOs\n/5OiPgoTdSy7bcF9IGpSE8ZgGKzgYQVZeN97YE00\n-----END RSA PRIVATE KEY-----",  # noqa
    ],
)
def test_private_key_detection(regex_matcher: RegexMatcher, test_case: str) -> None:
    matches = regex_matcher.match_regex_to_line(test_case)
    assert matches is not None, f"Failed to detect private key in: {test_case}"
    assert len(matches) > 0, f"No matches found for: {test_case}"


@pytest.mark.parametrize(
    "test_case",
    [
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
        "token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
    ],
)
def test_jwt_token_detection(regex_matcher: RegexMatcher, test_case: str) -> None:
    matches = regex_matcher.match_regex_to_line(test_case)
    assert matches is not None, f"Failed to detect JWT in: {test_case}"
    assert len(matches) > 0, f"No matches found for: {test_case}"


@pytest.mark.parametrize(
    "test_case",
    [
        "api_key=123456789012345678901234567890",
        "API_TOKEN=abcdefghijklmnopqrstuvwxyz123456",
        "secret=test_secret_key_12345678901234567890",
    ],
)
def test_generic_api_key_detection(regex_matcher: RegexMatcher, test_case: str) -> None:
    matches = regex_matcher.match_regex_to_line(test_case)
    assert matches is not None, f"Failed to detect generic API key in: {test_case}"
    assert len(matches) > 0, f"No matches found for: {test_case}"


@pytest.mark.parametrize(
    "test_case",
    [
        "This is a regular log message",
        "User logged in successfully",
        "Processing request 12345",
        "Error occurred at line 42",
    ],
)
def test_non_sensitive_data_not_detected(regex_matcher: RegexMatcher, test_case: str) -> None:
    matches = regex_matcher.match_regex_to_line(test_case)
    assert matches is None, f"False positive detected in: {test_case}"


@pytest.mark.parametrize(
    "test_case",
    [
        "GITHUB_TOKEN=ghp_123456789012345678901234567890123456",
        "github_token=ghp_123456789012345678901234567890123456",
        "GitHub_Token=ghp_123456789012345678901234567890123456",
    ],
)
def test_keyword_case_insensitivity(regex_matcher: RegexMatcher, test_case: str) -> None:
    matches = regex_matcher.match_regex_to_line(test_case)
    assert matches is not None, f"Failed to detect token with case variation: {test_case}"
    assert len(matches) > 0


def test_multiple_secrets_in_one_line(regex_matcher: RegexMatcher) -> None:
    test_line = (
        "github_token=ghp_123456789012345678901234567890123456 and aws_key=AKIAIOSFODNN7EXAMPLE"
    )
    matches = regex_matcher.match_regex_to_line(test_line)
    assert matches is not None
    assert len(matches) > 0


def test_keyword_to_patterns_structure(regex_matcher: RegexMatcher) -> None:
    for keyword, patterns in regex_matcher.keyword_to_patterns.items():
        assert isinstance(keyword, str), f"Keyword must be string, got {type(keyword)}"
        assert len(keyword) > 0, "Keyword cannot be empty"
        assert isinstance(patterns, list), f"Patterns must be list, got {type(patterns)}"
        assert len(patterns) > 0, f"Keyword '{keyword}' must have at least one pattern"


def test_automaton_keyword_matching(regex_matcher: RegexMatcher) -> None:
    test_keywords = ["github", "aws", "slack", "stripe", "api", "token"]
    for keyword in test_keywords:
        if keyword.lower() in regex_matcher.keyword_to_patterns:
            test_line = f"test_{keyword}_value=some_secret_123"
            matches = regex_matcher.match_regex_to_line(test_line)
            assert matches is not None or keyword not in ["github", "aws", "slack", "stripe"]


def test_config_file_is_valid_toml(config_path: str) -> None:
    with open(config_path, "rb") as f:
        config = tomli.load(f)
        assert "rules" in config, "Config must contain 'rules' key"
        assert isinstance(config["rules"], list), "Rules must be a list"
        assert len(config["rules"]) > 0, "Config must contain at least one rule"


def test_all_rules_have_required_fields(config_path: str) -> None:
    with open(config_path, "rb") as f:
        config = tomli.load(f)
        for rule in config["rules"]:
            assert "id" in rule, f"Rule missing 'id' field: {rule}"
            assert "regex" in rule, f"Rule missing 'regex' field: {rule.get('id', 'unknown')}"
            assert isinstance(rule["regex"], str), (
                f"Rule regex must be string: {rule.get('id', 'unknown')}"
            )
            assert len(rule["regex"]) > 0, (
                f"Rule regex cannot be empty: {rule.get('id', 'unknown')}"
            )


def test_keywords_extraction_from_config(config_path: str) -> None:
    with open(config_path, "rb") as f:
        config = tomli.load(f)
        rules_with_keywords = [
            r for r in config["rules"] if "keywords" in r and len(r["keywords"]) > 0
        ]
        assert len(rules_with_keywords) > 0, "At least some rules should have keywords"


def test_regex_patterns_are_valid(regex_matcher: RegexMatcher) -> None:
    for keyword, patterns in regex_matcher.keyword_to_patterns.items():
        for pattern in patterns:
            try:
                test_string = "test_string_for_pattern_validation"
                pattern.search(test_string)
            except Exception as e:
                pytest.fail(f"Pattern for keyword '{keyword}' failed validation: {e}")


def test_timeout_configuration(regex_matcher: RegexMatcher) -> None:
    assert regex_matcher.timeout_seconds > 0
    assert isinstance(regex_matcher.timeout_seconds, int)


def test_specific_rule_ids_exist(config_path: str) -> None:
    with open(config_path, "rb") as f:
        config = tomli.load(f)
        rule_ids = [rule["id"] for rule in config["rules"]]
        expected_rules = [
            "github-pat",
            "aws-access-token",
            "slack-bot-token",
            "stripe-access-token",
            "openai-api-key",
            "private-key",
            "jwt",
            "generic-api-key",
        ]
        for expected_rule in expected_rules:
            assert expected_rule in rule_ids, f"Expected rule '{expected_rule}' not found in config"
