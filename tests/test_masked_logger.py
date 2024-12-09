import logging
import pytest
import json
from io import StringIO
from maskerlogger import MaskerFormatter, MaskerFormatterJson


@pytest.fixture
def logger_and_log_stream():
    """
    Pytest fixture to set up the logger and a StringIO stream for capturing log output.

    Returns:
        tuple: A logger instance and a StringIO object to capture the log output.
    """
    logger = logging.getLogger('test_logger')
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
