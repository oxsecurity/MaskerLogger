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
