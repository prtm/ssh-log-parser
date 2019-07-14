ssh-log-parser
=========

### ssh-log-parser is a script to parse ssh logs. It can parse date, users, uri, IPv4 addresses.

Help:

```bash
python auth_log_parser.py -h

usage: auth_log_parser.py [-h] [-d DATE] [--file FILE]

Parsing for “Failed password” and “reverse mapping” attempts distributed by IP
addresses

optional arguments:
  -h, --help            show this help message and exit
  -d DATE, --date DATE  Specific date data - format YYYY-MM-DD
  --file FILE           file path
```

### Parsing
* reverse mapping address info
* failed password for user, on specific date
