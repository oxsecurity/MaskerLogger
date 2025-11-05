"""
This module demonstrates handling secrets in logs with ox_formatter.
"""

import logging
from masker_formatter import MaskerFormatter, SKIP_MASK


def main():
    """
    Main function to demonstrate logging with secrets.
    """
    logger = logging.getLogger("mylogger")
    logger.setLevel(logging.DEBUG)
    handler = logging.StreamHandler()
    handler.setFormatter(
        MaskerFormatter("%(asctime)s %(name)s %(levelname)s %(message)s", redact=50)
    )
    logger.addHandler(handler)

    logger.info(
        '"current_key": "AIzaSOHbouG6DDa6DOcRGEgOMayAXYXcw6la3c"', extra=SKIP_MASK
    )  # noqa
    logger.info('"AKIAI44QH8DHBEXAMPLE" and then more text.')
    logger.info("Datadog access token: 'abcdef1234567890abcdef1234567890'")
    logger.info('"password": "password123"')


if __name__ == "__main__":
    main()
