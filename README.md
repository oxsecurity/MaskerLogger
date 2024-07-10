![Flake Status](https://github.com/oxsecurity/maskerlogger/actions/workflows/flake.yml/badge.svg)
[![PyPI version](https://badge.fury.io/py/maskerlogger.svg)](https://badge.fury.io/py/maskerlogger)
[![GitHub release](https://img.shields.io/github/v/release/oxsecurity/maskerlogger?sort=semver)](https://github.com/oxsecurity/maskerlogger/releases)
[![License](https://img.shields.io/github/license/oxsecurity/maskerlogger)](https://github.com/oxsecurity/maskerlogger/blob/main/LICENSE)
[![GitHub stars](https://img.shields.io/github/stars/oxsecurity/maskerlogger?cacheSeconds=3600)](https://github.com/oxsecurity/maskerlogger/stargazers/)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=flat-square)](http://makeapullrequest.com)


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
from masker_formatter import MaskerFormatter, SKIP_MASK
...
...
logger.info('Line you want to skip', extra=SKIP_MASK)
```

#### fix len masking
If you want the masking to be in a fixed size (and not in the secret len),  
please set the `fix_masking_len`:  
```
handler.setFormatter(
    MaskerFormatter("%(asctime)s %(name)s %(levelname)s %(message)s",
                    fix_masking_len=30))
```

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

