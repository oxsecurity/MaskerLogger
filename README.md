[![Tests](https://github.com/oxsecurity/maskerlogger/actions/workflows/run-tests.yml/badge.svg)](https://github.com/oxsecurity/maskerlogger/actions/workflows/run-tests.yml)
[![Lint](https://github.com/oxsecurity/maskerlogger/actions/workflows/lint.yml/badge.svg)](https://github.com/oxsecurity/maskerlogger/actions/workflows/lint.yml)
[![Quality](https://github.com/oxsecurity/maskerlogger/actions/workflows/quality.yml/badge.svg)](https://github.com/oxsecurity/maskerlogger/actions/workflows/quality.yml)
[![codecov](https://codecov.io/gh/oxsecurity/maskerlogger/branch/main/graph/badge.svg)](https://codecov.io/gh/oxsecurity/maskerlogger)
[![PyPI version](https://badge.fury.io/py/maskerlogger.svg)](https://badge.fury.io/py/maskerlogger)
[![Python](https://img.shields.io/pypi/pyversions/maskerlogger.svg)](https://pypi.org/project/maskerlogger/)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows-blue)](https://github.com/oxsecurity/maskerlogger)
[![License](https://img.shields.io/github/license/oxsecurity/maskerlogger)](https://github.com/oxsecurity/maskerlogger/blob/main/LICENSE)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](https://makeapullrequest.com)


![MaskerLoggerTitle](https://github.com/oxsecurity/MaskerLogger/assets/140309297/ae8ec8a7-9ec8-42f6-9640-6f9cd91e986e)

# Masker Logger

Keep Your logs safe!
This formatter ensures the security of your logs and prevents sensitive data leaks.
For example -
Using this Formatter will print this line:
`logger.info(f'Dont Give Your {secrets} away')`
like this:
`Dont Give Your ****** away`

## Getting started
This formatter utilizes the standard `logging.Formatter` module.
Before printing each record to any destination (file, stdout, etc.), it ensures sensitive data is masked with asterisks to prevent leaks.

### Requirements

| MaskerLogger Version | Python Version |
|---------------------|----------------|
| 1.0.0+              | 3.10 - 3.13    |
| < 1.0.0             | 3.9 - 3.13     |

### Install the library

```
pip install maskerlogger
```

### Basic Usage

 Like any formatter - just init your logger handler with the MaskerLogger formatter.
 ```
 from maskerlogger import MaskerFormatter
 logger = logging.getLogger('logger')
 logger.setLevel(logging.DEBUG)
 handler = logging.StreamHandler()
 handler.setFormatter(
     MaskerFormatter("%(asctime)s %(name)s %(levelname)s %(message)s"))
 logger.addHandler(handler)
 ```
#### skip masking
If, for some reason, you want to disable masking on a specific log line, use the `SKIP_MASK` mechanism.
```
from maskerlogger import MaskerFormatter, SKIP_MASK
...
...
logger.info('Line you want to skip', extra=SKIP_MASK)
```

#### redact
Here’s a rewritten version suitable for inclusion in a README.md file:

---

### Partial Masking of Secrets
If you prefer to mask only a portion of a secret (rather than its entire length), you can set the `redact` parameter in the formatter. The `redact` parameter specifies the percentage of the secret to be masked.

Here’s an example of how to use it:

```
handler.setFormatter(
    MaskerFormatter("%(asctime)s %(name)s %(levelname)s %(message)s",
                    redact=30))
```

In this example, 30% of the secret will be masked. Adjust the `redact` value as needed to suit your requirements.

## The Config File

Here's where the magic happens!
Our tool is built upon the powerful Gitleaks tool,
leveraging its default configuration to scan for sensitive data leaks in repositories.
You can find the default configuration [here](https://github.com/gitleaks/gitleaks/blob/master/config/gitleaks.toml)

#### Use custom config file

To create and use your own config file, set the path when initializing the formatter:
```
handler.setFormatter(
    MaskerFormatter("%(asctime)s %(name)s %(levelname)s %(message)s",
                    regex_config_path="your/config/gitleaks.toml"))
```

Good luck!


##### Brought to you by [OX Security](https://www.ox.security/)
