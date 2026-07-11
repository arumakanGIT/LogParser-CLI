import re
from collections import Counter
from sys import exit
import time
import argparse
from pathlib import Path

# Initial necessary variables
pattern = re.compile(
    r"^(?P<ip>\d+\.\d+\.\d+\.\d+)\s+-(?P<username>.*)-\s+\[(?P<timeanddate>(?P<date>\d{2}\/\w{3}\/\d{4}):"
    r"(?P<time>\d{2}:\d{2}:\d{2})\s(?P<GMT>(\+|\-)\d{4})])\s+\"((?P<method>\w+) (?P<Path>\/\S*) "
    r"(?P<Protocol>\S*))\"\s+(?P<Code>\d+)\s+(?P<Size>\d+)\s+\"(?P<Referrer>.*)\"\s+\"(?P<UserAgent>.*)\"$")
total_logs = 0
requests = 0
start_time = time.perf_counter()
delta_time = start_time
path_input_arg_error = False
unique_ips = set()
error4 = 0
errors = 0
error_rate = 0
endpoint_counter = Counter()

# handling args
parser = argparse.ArgumentParser(description="A tool for log analysis.")
parser.add_argument("path", nargs="+", help="Path to the log file")
parser.add_argument("--live", "-l", action="store_true", help="Enable live log monitoring")
parser.add_argument("--output", "-o", nargs="?", const="output.txt",
                    help="Save the logs to a file")
parser.add_argument("--per-file", action="store_true",
                    help="Show separate analytical reports for each individual log file ")
args = parser.parse_args()

# check path validation
for path in args.path:
    file_path = Path(path)
    if not file_path.exists():
        print(f"Error: The path '{path}' does not exist.")
        path_input_arg_error = True
    elif not file_path.is_file():
        print(f"Error: The path '{path}' is a directory or not a regular file.")
        path_input_arg_error = True
if path_input_arg_error:
    exit(1)


def live_monitoring():
    error_rate = (errors / requests) * 100
    # print(f"total logs checked: {total_logs}", end="\r")
    # print(f": {total_logs}", end="\r")


if args.live:
    print("Live monitoring:")

# main loop
for path in args.path:
    with open(path, 'r', encoding='utf-8') as file:
        path_total_logs = 0
        path_requests = 0
        path_errors = 0
        path_endpoint = Counter()
        path_unique_ips = set()
        for line in file:
            path_total_logs += 1
            path_requests += 1
            total_logs += 1
            log_match = pattern.search(line.strip())
            if args.live and time.perf_counter() - delta_time > 0.001:
                live_monitoring()
                delta_time = time.perf_counter()
            if log_match:
                endpoint_counter[log_match.group("Path")] += 1
                path_endpoint[log_match.group("Path")] += 1
                requests += 1
                unique_ips.add(log_match.group("ip"))
                path_unique_ips.add(log_match.group("ip"))
                code = int(log_match.group("Code"))
                if 400 <= code < 500:
                    error4 += 1
                elif 400 <= code < 600:
                    errors += 1
                    path_errors += 1

        print(f"================================\n"
        f"results for {path}:\n"
        f"accepted logs: {path_requests}/{path_total_logs}\n"
        f"error rate: {(path_errors / path_requests) * 100}%\n"
        f"unique IP = {len(path_unique_ips)}\n"
        f"most 10 URL:")
        i = 1
        for url, count in path_endpoint.most_common(10):
            print(f"{i}. \"{url}\" : {count}")
            i += 1
        print("================================")

print(f"""
================================
accepted logs: {requests}/{total_logs}
error rate: {(errors / requests) * 100}%
unique IP = {len(unique_ips)}
most 10 URL:""")
i = 0
for url, count in path_endpoint.most_common(10):
    print(f"{++i}. {url}: {count}")
print("================================")
print(f"executiontime = {time.perf_counter() - start_time:.6f}s")
