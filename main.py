import re
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
accepted_logs = 0
start_time = time.perf_counter()
path_input_arg_error = False

# handling args
parser = argparse.ArgumentParser(description="A tool for log analysis.")
parser.add_argument("path", nargs="+", help="Path to the log file")
parser.add_argument("--live", "-l", action="store_true", help="Enable live log monitoring")
parser.add_argument("--output", "-o", nargs="?", const="output.txt",
                    help="Save the logs to a file")
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

# main loop
for path in args.path:
    with open(path, 'r', encoding='utf-8') as file:
        for line in file:
            total_logs += 1
            log_match = pattern.search(line.strip())
            if log_match:
                accepted_logs += 1
            print(f"{total_logs}", end="\r")

print(f"""
================================
          \tFinished
          \taccepted logs: {accepted_logs}/{total_logs}
================================""")

print(f"executiontime = {time.perf_counter() - start_time:.6f}s")
