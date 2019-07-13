# stdlib
from datetime import datetime, date
import argparse
import re
import pprint


# validate date from argument
def valid_date(string):
    try:
        return datetime.strptime(string, "%Y-%m-%d").date()
    except ValueError:
        msg = f"Invalid date: '{string}'."
        raise argparse.ArgumentTypeError(msg)


# parse date from a line
def parse_date(line):
    string_date = re.search(r'^[a-zA-Z]{3}(\s+)[\d]{1,2}', line)
    return datetime.strptime(f"{date.today().year} {string_date.group(0)}", "%Y %b %d").date().strftime("%Y-%m-%d")


# parse user from a line
def parse_user(line):
    return re.search(r'for (\binvalid\suser\s)?(\w+)', line).group(2)


# parse getaddr from a line
def parse_addr(line):
    return re.search(r'for ([\w\.-]+)\s', line).group(1)


# parse ipv4 from a line containing failed password text
def parse_fails_ipv4(line):
    return re.search(r'(\bfrom\s)((\d{1,3}\.){3}\d{1,3})', line).group(2)


# parse ipv4 from a line containing reverse mapping text
def parse_reverse_mapping_ipv4(line):
    return re.search(r'\[((\d{1,3}\.){3}\d{1,3})\]', line).group(1)


def get_fails_or_addrs(args, is_reverse_mapping):
    results = {}
    pattern = "reverse mapping checking " if is_reverse_mapping else "Failed password for "
    with open('auth.log', 'r') as infile:
        for line in infile:
            # filter by pattern
            if pattern in line:
                # parse data date, user or uri, ip address
                on_date = parse_date(line)
                if args.date and on_date != str(args.date):
                    continue
                main_key = parse_addr(
                    line) if is_reverse_mapping else parse_user(line)
                from_ip = parse_reverse_mapping_ipv4(
                    line) if is_reverse_mapping else parse_fails_ipv4(line)

                # increase counter or add results
                if on_date in results:
                    results_on_date = results[on_date]
                    if main_key in results_on_date:
                        user_data = results_on_date[main_key]
                        if 'TOTAL' in user_data:
                            user_data['TOTAL'] += 1
                        else:
                            user_data['TOTAL'] = 1
                        if 'IPLIST' in user_data:
                            iplist = user_data['IPLIST']
                            if from_ip in iplist:
                                iplist[from_ip] += 1
                            else:
                                iplist[from_ip] = 1
                        else:
                            iplist = {
                                from_ip: 1
                            }
                        user_data['IPLIST'] = iplist
                    else:
                        user_data = {
                            'TOTAL': 1,
                            'IPLIST': {
                                from_ip: 1
                            }
                        }
                    results_on_date[main_key] = user_data
                    results[on_date] = results_on_date
                else:
                    results[on_date] = {
                        main_key: {
                            'TOTAL': 1,
                            'IPLIST': {
                                from_ip: 1
                            }
                        }
                    }
    return results


def main():
    pp = pprint.PrettyPrinter(indent=4)
    # parse argument
    parser = argparse.ArgumentParser(
        description='Parsing for “Failed password” and “reverse mapping” attempts distributed by IP addresses')
    parser.add_argument("-d",
                        "--date",
                        help="Specific date data - format YYYY-MM-DD",
                        required=False,
                        type=valid_date)

    args = parser.parse_args()

    # print results
    pp.pprint(get_fails_or_addrs(args, is_reverse_mapping=False))
    pp.pprint(get_fails_or_addrs(args, is_reverse_mapping=True))


if __name__ == "__main__":
    main()
