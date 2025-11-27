import json
import logging
from io import StringIO
from unittest.mock import patch

import pytest

from maskerlogger import MaskerFormatter, MaskerFormatterJson
from maskerlogger.utils import TimeoutException


@pytest.fixture
def logger_and_log_stream():
    """
    Pytest fixture to set up the logger and a StringIO stream for capturing log output.

    Returns:
        tuple: A logger instance and a StringIO object to capture the log output.
    """
    logger = logging.getLogger("test_logger")
    logger.setLevel(logging.DEBUG)
    logger.handlers.clear()
    log_stream = StringIO()

    # Create console handler and set formatter
    console_handler = logging.StreamHandler(log_stream)
    logger.addHandler(console_handler)

    return logger, log_stream


@pytest.fixture
def log_format():
    return "%(asctime)s %(name)s %(levelname)s %(message)s"


def test_masked_logger_text(logger_and_log_stream, log_format):
    """
    Test the functionality of MaskerFormatter, ensuring it formats logs in plain text
    and masks sensitive data correctly.

    Args:
        logger_and_log_stream (tuple): A tuple containing the logger and log stream.
    """
    logger, log_stream = logger_and_log_stream

    # Set the MaskerFormatter formatter
    formatter = MaskerFormatter(fmt=log_format)
    logger.handlers[0].setFormatter(formatter)

    # Log a sensitive message
    logger.info("User login with password=secretpassword")

    # Read and parse the log output
    log_output = log_stream.getvalue().strip()

    # Validate that the password is masked in the text log output
    assert "password=*****" in log_output
    assert "secretpassword" not in log_output


def test_masked_logger_json(logger_and_log_stream, log_format):
    """
    Test the functionality of MaskerFormatterJson, ensuring it formats logs in JSON format
    and masks sensitive data correctly.

    Args:
        logger_and_log_stream (tuple): A tuple containing the logger and log stream.
    """
    logger, log_stream = logger_and_log_stream

    # Set the MaskerFormatterJson formatter
    formatter = MaskerFormatterJson(fmt=log_format)
    logger.handlers[0].setFormatter(formatter)

    # Log a sensitive message
    logger.info("User login with password=secretpassword")

    # Read and parse the log output
    log_output = log_stream.getvalue().strip()
    log_json = json.loads(log_output)  # Parse the JSON log output

    # Validate that the password is masked in the JSON log output
    assert "password=*****" in log_json["message"]
    assert "secretpassword" not in log_json["message"]


def test_masked_logger_text_format_after_masking(logger_and_log_stream, log_format):
    """
    Test that MaskerFormatter outputs correctly formatted text logs after applying data masking.
    Ensures that sensitive data is masked and log format remains valid.

    Args:
        logger_and_log_stream (tuple): A tuple containing the logger and log stream.
    """
    logger, log_stream = logger_and_log_stream

    # Set the MaskerFormatter formatter
    formatter = MaskerFormatter(fmt=log_format)
    logger.handlers[0].setFormatter(formatter)

    # Log a sensitive message
    logger.info("Sensitive data: password=secretpassword and other info")

    # Read and parse the log output
    log_output = log_stream.getvalue().strip()

    # Validate that the password is masked and the log format is correct
    assert "password=*****" in log_output
    assert "secretpassword" not in log_output


def test_masked_logger_json_format_after_masking(logger_and_log_stream, log_format):
    """
    Test that MaskerFormatterJson outputs correctly formatted JSON logs after applying data masking.
    Ensures that sensitive data is masked and log format remains valid.

    Args:
        logger_and_log_stream (tuple): A tuple containing the logger and log stream.
    """
    logger, log_stream = logger_and_log_stream

    # Set the MaskerFormatterJson formatter
    formatter = MaskerFormatterJson(fmt=log_format)

    logger.handlers[0].setFormatter(formatter)

    # Log a sensitive message
    logger.info("Sensitive data: password=secretpassword and other info")

    # Read and parse the log output
    log_output = log_stream.getvalue().strip()
    log_json = json.loads(log_output)  # Parse the JSON log output

    # Validate that the password is masked and the JSON log format is correct
    assert "password=*****" in log_json["message"]
    assert "secretpassword" not in log_json["message"]


def test_masked_logger_non_sensitive_data(logger_and_log_stream, log_format):
    """
    Test that non-sensitive log messages are logged without modification,
    ensuring they are formatted correctly in both text and JSON formats.

    Args:
        logger_and_log_stream (tuple): A tuple containing the logger and log stream.
    """
    logger, log_stream = logger_and_log_stream

    # Set the MaskerFormatter formatter for testing non-sensitive data
    formatter = MaskerFormatter(fmt=log_format)
    logger.handlers[0].setFormatter(formatter)

    # Log a non-sensitive message
    non_sensitive_msg = "This is a regular log message."
    logger.info(non_sensitive_msg)

    # Read and parse the log output
    log_output = log_stream.getvalue().strip()

    # Ensure the non-sensitive message is logged without any masking
    assert non_sensitive_msg in log_output


def test_masked_logger_handles_timeout_gracefully(logger_and_log_stream, log_format):
    logger, log_stream = logger_and_log_stream
    formatter = MaskerFormatter(fmt=log_format)
    logger.handlers[0].setFormatter(formatter)

    with patch.object(
        formatter.regex_matcher,
        "match_regex_to_line",
        side_effect=TimeoutException("Regex matching timeout"),
    ):
        sensitive_msg = "User login with password=secretpassword"
        logger.info(sensitive_msg)

        log_output = log_stream.getvalue().strip()

        assert sensitive_msg in log_output
        assert log_output is not None


def test_redact_validation_valid_values():
    """Test that valid redact values (0-100) are accepted."""
    # Test boundary values
    MaskerFormatter(fmt="%(message)s", redact=0)
    MaskerFormatter(fmt="%(message)s", redact=50)
    MaskerFormatter(fmt="%(message)s", redact=100)

    # Test valid integer values
    MaskerFormatter(fmt="%(message)s", redact=25)
    MaskerFormatter(fmt="%(message)s", redact=75)


def test_redact_validation_invalid_values():
    """Test that invalid redact values raise ValueError."""
    # Test negative values
    with pytest.raises(ValueError, match="Redact value must be between 0 and 100"):
        MaskerFormatter(fmt="%(message)s", redact=-1)

    with pytest.raises(ValueError, match="Redact value must be between 0 and 100"):
        MaskerFormatter(fmt="%(message)s", redact=-50)

    # Test values greater than 100
    with pytest.raises(ValueError, match="Redact value must be between 0 and 100"):
        MaskerFormatter(fmt="%(message)s", redact=101)

    with pytest.raises(ValueError, match="Redact value must be between 0 and 100"):
        MaskerFormatter(fmt="%(message)s", redact=150)


def test_redact_validation_type_conversion():
    """Test that string numbers are properly converted to integers."""
    # Test string representations of valid values
    formatter = MaskerFormatter(fmt="%(message)s", redact="50")
    assert formatter.redact == 50
    assert isinstance(formatter.redact, int)

    formatter = MaskerFormatter(fmt="%(message)s", redact="0")
    assert formatter.redact == 0
    assert isinstance(formatter.redact, int)

    # Test invalid string values
    with pytest.raises(ValueError, match="Redact value must be between 0 and 100"):
        MaskerFormatter(fmt="%(message)s", redact="150")


def test_masked_logger_multiple_leaks_same_string(logger_and_log_stream, log_format):
    """
    Test that multiple occurrences of the same leak in a single string are all masked.
    This verifies the fix for catching more than 1 leak in the same string.

    Args:
        logger_and_log_stream (tuple): A tuple containing the logger and log stream.
    """
    logger, log_stream = logger_and_log_stream

    # Set the MaskerFormatter formatter
    formatter = MaskerFormatter(fmt=log_format)
    logger.handlers[0].setFormatter(formatter)

    # Log a message with multiple instances of the same secret (using 10+ char passwords)
    logger.info(
        "First password=secretpassword and second password=anothersecret and third password=secretpassword"
    )

    # Read and parse the log output
    log_output = log_stream.getvalue().strip()

    # Validate that all password instances are masked
    assert "password=" in log_output
    assert "secretpassword" not in log_output
    assert "anothersecret" not in log_output

    # Count the number of password= occurrences to ensure all are processed
    password_count = log_output.count("password=")
    assert password_count == 3, f"Expected 3 password fields, found {password_count}"


def test_masked_logger_multiple_different_leaks_same_string(logger_and_log_stream, log_format):
    """
    Test that multiple different types of leaks in a single string are all masked.

    Args:
        logger_and_log_stream (tuple): A tuple containing the logger and log stream.
    """
    logger, log_stream = logger_and_log_stream

    # Set the MaskerFormatter formatter
    formatter = MaskerFormatter(fmt=log_format)
    logger.handlers[0].setFormatter(formatter)

    # Log a message with multiple different sensitive patterns (using 10+ char secrets)
    logger.info(
        "User data: password=mysecretpassword and token=abc123tokenlong and password=anothersecret"
    )

    # Read and parse the log output
    log_output = log_stream.getvalue().strip()

    # Validate that both password instances and token are masked
    assert "password=" in log_output
    assert "token=" in log_output
    assert "mysecretpassword" not in log_output
    assert "anothersecret" not in log_output
    assert "abc123tokenlong" not in log_output


def test_masked_logger_overlapping_matches(logger_and_log_stream, log_format):
    """
    Test that overlapping matches from different regex patterns are handled correctly.
    This verifies that the character-array approach properly handles complex scenarios
    where multiple patterns might match overlapping text spans.

    Args:
        logger_and_log_stream (tuple): A tuple containing the logger and log stream.
    """
    logger, log_stream = logger_and_log_stream

    # Set the MaskerFormatter formatter
    formatter = MaskerFormatter(fmt=log_format)
    logger.handlers[0].setFormatter(formatter)

    # Log a message that might trigger overlapping regex patterns
    logger.info("Auth data: token=secrettoken123456 and password=overlappingsecretkey")

    # Read and parse the log output
    log_output = log_stream.getvalue().strip()

    # Validate that all sensitive data is masked, even with potential overlaps
    assert "secrettoken123456" not in log_output
    assert "overlappingsecretkey" not in log_output
    # Note: Different patterns capture differently - some include key=, others don't
    # The important thing is that the secret values are masked
    assert "password=" in log_output  # This pattern captures only the value


def test_masked_logger_empty_capture_groups(logger_and_log_stream, log_format):
    """
    Test that patterns with capture groups that are all None/empty still get masked.
    This verifies the fix for the edge case where regex patterns have optional groups
    that don't match, leaving all capture groups as None/empty.

    Args:
        logger_and_log_stream (tuple): A tuple containing the logger and log stream.
    """
    logger, log_stream = logger_and_log_stream

    # Set the MaskerFormatter formatter
    formatter = MaskerFormatter(fmt=log_format)
    logger.handlers[0].setFormatter(formatter)

    # Create a scenario that might result in None capture groups
    # This could happen with complex regex patterns that have optional groups
    logger.info("API key: AKIAIOSFODNN7EXAMPLE")  # AWS access key pattern

    # Read and parse the log output
    log_output = log_stream.getvalue().strip()

    # The key should be masked even if capture groups are None/empty
    assert "AKIAIOSFODNN7EXAMPLE" not in log_output
    # Some part of the message should be masked (asterisks should appear)
    assert "*" in log_output


def test_masked_logger_no_capture_groups_fallback(logger_and_log_stream, log_format):
    """
    Test that patterns with no capture groups fall back to masking the entire match (group 0).
    This covers the fallback code path when masked_something remains False.
    """
    logger, log_stream = logger_and_log_stream

    # Set the MaskerFormatter formatter
    formatter = MaskerFormatter(fmt=log_format)
    logger.handlers[0].setFormatter(formatter)

    # Use a pattern that we know doesn't have capture groups but matches secrets
    # The JWT pattern should match without capture groups in some cases
    logger.info(
        "JWT: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    )

    log_output = log_stream.getvalue().strip()

    # The entire JWT should be masked since there are no capture groups
    assert "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" not in log_output
    assert "*" in log_output


def test_masked_logger_all_capture_groups_none(logger_and_log_stream, log_format):
    """
    Test the fallback to group 0 when all capture groups are None.
    This specifically tests the case where match.groups() returns a tuple with None values.
    """
    import re
    from unittest.mock import Mock

    logger, log_stream = logger_and_log_stream

    formatter = MaskerFormatter(fmt=log_format)

    # Mock a match object that has capture groups but they're all None
    mock_match = Mock(spec=re.Match)
    mock_match.groups.return_value = (None, None)  # Two capture groups, both None
    mock_match.group.side_effect = lambda i=0: "sensitivedata12345" if i == 0 else None
    mock_match.start.side_effect = lambda i=0: 10 if i == 0 else -1
    mock_match.end.side_effect = lambda i=0: 27 if i == 0 else -1

    # Test the _mask_secret method directly with our mock match
    test_message = "Some text sensitivedata12345 more text"
    result = formatter._mask_secret(test_message, [mock_match])

    # Should fall back to masking the entire match since all capture groups are None
    assert "sensitivedata12345" not in result
    assert "*" in result


def test_masked_logger_all_capture_groups_empty(logger_and_log_stream, log_format):
    """
    Test the fallback to group 0 when all capture groups are empty strings.
    """
    import re
    from unittest.mock import Mock

    logger, log_stream = logger_and_log_stream

    formatter = MaskerFormatter(fmt=log_format)

    # Mock a match object that has capture groups, but they're all empty strings
    mock_match = Mock(spec=re.Match)
    mock_match.groups.return_value = ("", "")  # Two capture groups, both empty
    mock_match.group.side_effect = lambda i=0: "anothersecret123" if i == 0 else ""
    mock_match.start.side_effect = lambda i=0: 5 if i == 0 else -1
    mock_match.end.side_effect = lambda i=0: 21 if i == 0 else -1

    # Test the _mask_secret method directly
    test_message = "Data anothersecret123 end"
    result = formatter._mask_secret(test_message, [mock_match])

    # Should fall back to masking the entire match since all capture groups are empty
    assert "anothersecret123" not in result
    assert "*" in result


def test_masked_logger_fallback_with_different_redact_percentages():
    """
    Test the fallback masking with different redact percentages to ensure
    the redact_length calculation works correctly in the fallback code path.
    """
    import re
    from unittest.mock import Mock

    test_cases = [
        (0, "testsecret1234", "testsecret1234"),  # 0% should not mask anything
        (50, "testsecret1234", "*******cret1234"),  # 50% should mask half
        (100, "testsecret1234", "**************"),  # 100% should mask everything
    ]

    for redact_percent, secret, _ in test_cases:
        formatter = MaskerFormatter(fmt="%(message)s", redact=redact_percent)

        # Mock a match with no valid capture groups
        mock_match = Mock(spec=re.Match)
        mock_match.groups.return_value = (None,)
        mock_match.group.side_effect = lambda i=0, s=secret: s if i == 0 else None
        mock_match.start.side_effect = lambda i=0: 0 if i == 0 else -1
        mock_match.end.side_effect = lambda i=0, s=secret: len(s) if i == 0 else -1

        result = formatter._mask_secret(secret, [mock_match])

        if redact_percent == 0:
            # 0% redaction should leave the original text
            assert result == secret
        else:
            # Other percentages should mask appropriately
            expected_mask_length = int((len(secret) / 100) * redact_percent)
            expected_asterisks = "*" * expected_mask_length
            expected_remaining = secret[expected_mask_length:]
            expected_result = expected_asterisks + expected_remaining
            assert result == expected_result, (
                f"Redact {redact_percent}%: expected {expected_result}, got {result}"
            )


def test_masked_logger_mixed_capture_groups_fallback():
    """
    Test a scenario where some matches have valid capture groups and others need fallback.
    This ensures both code paths work together correctly.
    """
    import re
    from unittest.mock import Mock

    formatter = MaskerFormatter(fmt="%(message)s")

    # First match: has a valid capture group
    mock_match1 = Mock(spec=re.Match)
    mock_match1.groups.return_value = ("validgroup123",)
    mock_match1.group.side_effect = lambda i=0: "key=validgroup123" if i == 0 else "validgroup123"
    mock_match1.start.side_effect = lambda i=0: 0 if i == 0 else 4
    mock_match1.end.side_effect = lambda i=0: 17 if i == 0 else 17

    # Second match: has capture groups, but they're all None (needs fallback)
    mock_match2 = Mock(spec=re.Match)
    mock_match2.groups.return_value = (None, None)
    mock_match2.group.side_effect = lambda i=0: "fallbacksecret" if i == 0 else None
    mock_match2.start.side_effect = lambda i=0: 20 if i == 0 else -1
    mock_match2.end.side_effect = lambda i=0: 34 if i == 0 else -1

    test_message = "key=validgroup123 : fallbacksecret end"
    result = formatter._mask_secret(test_message, [mock_match1, mock_match2])

    # Both secrets should be masked
    assert "validgroup123" not in result
    assert "fallbacksecret" not in result
    assert "*" in result


def test_masked_logger_masks_secrets_in_traceback_text(logger_and_log_stream, log_format):
    """
    Test that MaskerFormatter masks secrets in exception tracebacks (exc_info) in text logs.
    """
    logger, log_stream = logger_and_log_stream
    formatter = MaskerFormatter(fmt=log_format)
    logger.handlers[0].setFormatter(formatter)

    secret = "supersecretpassword"
    try:
        raise ValueError(f"This is a test error with password={secret}")
    except Exception:
        logger.error("Exception occurred", exc_info=True)

    log_output = log_stream.getvalue()
    # The secret should be masked in the traceback
    assert "password=" in log_output
    assert secret not in log_output
    assert "*****" in log_output


def test_masked_logger_masks_secrets_in_traceback_json(logger_and_log_stream, log_format):
    """
    Test that MaskerFormatterJson masks secrets in exception tracebacks (exc_info) in JSON logs.
    """
    logger, log_stream = logger_and_log_stream
    formatter = MaskerFormatterJson(fmt=log_format)
    logger.handlers[0].setFormatter(formatter)

    secret = "supersecretpassword"
    try:
        raise ValueError(f"This is a test error with password={secret}")
    except Exception:
        logger.error("Exception occurred", exc_info=True)

    log_output = log_stream.getvalue()
    log_json = json.loads(log_output)
    # The secret should be masked in the traceback (exc_info field)
    assert "password=" in log_json.get("exc_info", "")
    assert secret not in log_json.get("exc_info", "")
    assert "*****" in log_json.get("exc_info", "")
