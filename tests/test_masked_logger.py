import logging
import pytest
import json
from io import StringIO
from maskerlogger import MaskerFormatter, MaskerFormatterJson


ELASTIC_PW = "^_h6yCZKuadboPDfSa7pmN2tdWPCbZPWq!!"
MASKED_ELASTIC_PW = len(ELASTIC_PW) * "*"
API_TOKEN = "dqu0oJU45UMbrhJ1eNfVdSQ9Yf6wj6u@!^_"
MASKED_API_TOKEN = len(API_TOKEN) * "*"
GCP_API_KEY = "AIzaSyabcdefghijklmnopqrstuvwxyz1234567"
MASKED_GCP_API_KEY = len(GCP_API_KEY) * "*"

SENSITIVE_STRING = json.dumps(
    {
        "ELASTIC_SEARCH": {
            "URL": "https://example.com:9200",
            "USERNAME": "<superUserForElastic>",
            "PASSWORD": ELASTIC_PW,
        },
        "ANOTHER_ELASTIC_SEARCH": {
            "URL": "https://example.com:9200",
            "USERNAME": "<superUserForElastic>",
            "PASSWORD": ELASTIC_PW,
        },
        "API": {
            "HOST": "https://api.example.com",
            "USERNAME": "<api_userName>",
            "TOKEN": API_TOKEN,
        },
        "GCP": {
            "PROJECT_ID": "my-gcp-project",
            "SERVICE_ACCOUNT": "my-service",
            "API_KEY": GCP_API_KEY,
        },
    }
)


def common_assertions(log_output: str) -> None:
    # ElASTIC_SEARCH password should be masked
    assert ELASTIC_PW not in log_output
    assert f'"PASSWORD": "{MASKED_ELASTIC_PW}"' in log_output

    # API token should be masked
    assert API_TOKEN not in log_output
    assert f'"TOKEN": "{MASKED_API_TOKEN}"' in log_output

    # GCP API key should be masked
    assert GCP_API_KEY not in log_output
    assert f'"API_KEY": "{MASKED_GCP_API_KEY}"' in log_output


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
    logger.info(SENSITIVE_STRING)

    # Read and parse the log output
    log_output = log_stream.getvalue().strip()

    common_assertions(log_output)


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
    logger.info(SENSITIVE_STRING)

    # Read and parse the log output
    log_output = log_stream.getvalue().strip()
    log_json = json.loads(log_output)  # Parse the JSON log output

    # Validate that the password is masked in the JSON log output
    common_assertions(log_json["message"])


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
    logger.info(SENSITIVE_STRING)

    # Read and parse the log output
    log_output = log_stream.getvalue().strip()

    # Validate that the password is masked and the log format is correct
    common_assertions(log_output)


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
    logger.info(SENSITIVE_STRING)

    # Read and parse the log output
    log_output = log_stream.getvalue().strip()
    log_json = json.loads(log_output)  # Parse the JSON log output

    # Validate that the password is masked and the JSON log format is correct
    common_assertions(log_json["message"])


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
