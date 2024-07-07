![MaskerLoggerTitle](https://github.com/oxsecurity/MaskerLogger/assets/140309297/ae8ec8a7-9ec8-42f6-9640-6f9cd91e986e)

# Masker Logger

The Best Logger Formatter to prevent leaks in you python logs!

## Getting started

This formatter is based on the common `logging.Formatter` module.  
For each record, before the log is printed (to any source - file/stdout/etc),  
The formatter will prevent you from leaking sensetive data.

### Install the library

```
pip install maskerlogger
```

### Basic Usage

 Like any formatter - just init your logger handler with the MaskerLogger formatter.  
 ```
 from ox_formatter import OxFormatter
 logger = logging.getLogger('logger')
 logger.setLevel(logging.DEBUG)
 handler = logging.StreamHandler()
 handler.setFormatter(
     MaskerFormatter("%(asctime)s %(name)s %(levelname)s %(message)s"))
 logger.addHandler(handler)
 ```
## The Config File
Here all the magic happen!
We based our tool on the great Gitleaks tool, and we are using their default config.  
Default config can be found [here](https://github.com/gitleaks/gitleaks/blob/master/config/gitleaks.toml)


Good luck!


##### Brought to you by [OX Security](https://www.ox.security/)

