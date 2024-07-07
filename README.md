![MaskerLoggerTitle](https://github.com/oxsecurity/MaskerLogger/assets/140309297/ae8ec8a7-9ec8-42f6-9640-6f9cd91e986e)

# Masker Logger

Keep Your logs safe!

This formatter ensures the security of your logs and prevents sensitive data leaks.
For example -   
Using this Formatter will print this line:   `looger.info(f'Dont Give Your {secrets} away')`  
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
## The Config File

Here's where the magic happens!  
Our tool is built upon the powerful Gitleaks tool,  
leveraging its default configuration to scan for sensitive data leaks in repositories.  
You can find the default configuration [here](https://github.com/gitleaks/gitleaks/blob/master/config/gitleaks.toml)

Good luck!


##### Brought to you by [OX Security](https://www.ox.security/)

