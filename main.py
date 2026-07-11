import re
from collections import Counter
import sys
from sys import exit
import time
import argparse
from pathlib import Path
import json
from rich.live import Live

pattern = re.compile(
    r"^(?P<ip>\d+\.\d+\.\d+\.\d+)\s+-(?P<username>.*)-\s+\[(?P<timeanddate>(?P<date>\d{2}\/\w{3}\/\d{4}):"
    r"(?P<time>\d{2}:\d{2}:\d{2})\s(?P<GMT>(\+|\-)\d{4})])\s+\"((?P<method>\w+) (?P<Path>\/\S*) "
    r"(?P<Protocol>\S*))\"\s+(?P<Code>\d+)\s+(?P<Size>\d+)\s+\"(?P<Referrer>.*)\"\s+\"(?P<UserAgent>.*)\"$")
total_logs = 0
total_requests = 0
start_time = time.perf_counter()
delta_time = start_time
path_input_arg_error = False
unique_ips = set()
total_error4 = 0
total_errors = 0
error_rate = 0
endpoint_counter = Counter()

parser = argparse.ArgumentParser(description="A tool for log analysis.")
parser.add_argument("path", nargs="+", help="Path to the log file")
parser.add_argument("--live", "-l", action="store_true", help="Enable live log monitoring")
parser.add_argument("--output", "-o", type=str, help="Save the logs to a JSON file path")
parser.add_argument("--per-file", action="store_true",
                    help="Show separate analytical reports for each individual log file ")
args = parser.parse_args()

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

if args.output:
    output_path = Path(args.output)
    if output_path.is_dir():
        print(f"Error: The output path '{args.output}' is a directory. Please provide a file name.")
        exit(1)
    if not output_path.parent.exists():
        print(f"Error: The directory '{output_path.parent}' does not exist.")
        exit(1)

per_file_first = False
if args.output and args.per - file:
    output_flags = ["-o", "--output"]
    per_file_flags = ["--per-file"]

    output_index = min([sys.argv.index(flag) for flag in output_flags if flag in sys.argv], default=float('inf'))
    per_file_index = min([sys.argv.index(flag) for flag in per_file_flags if flag in sys.argv], default=float('inf'))

    if per_file_index < output_index:
        per_file_first = True

global_endpoint_counter = Counter()
global_unique_ips = set()
global_time_distribution = Counter()


def generate_display(current_requests, current_logs, current_errors, current_ips, current_endpoints, current_time_dist,
                     filename=""):
    err_rate = ((current_errors / current_requests) * 100) if current_requests > 0 else 0.0
    file_info = f" [File: {filename}]" if filename else " [All Files Combined]"
    display_str = f"""================================
[Live Monitoring...{file_info}]
accepted logs: {current_requests}/{current_logs}
error rate: {err_rate:.4f}%
unique IP = {len(current_ips)}
most 10 URL:\n"""
    for j, (url_address, url_count) in enumerate(current_endpoints.most_common(10), 1):
        display_str += f"  {j:02d}. \"{url_address}\" : {url_count}\n"

    display_str += "\nHourly Traffic Distribution:\n"
    for timestamp, traffic in sorted(current_time_dist.items()):
        display_str += f"  {timestamp}:00 -> Traffic: {traffic}\n"

    display_str += "================================"
    return display_str


live_context = None

try:
    if args.live and not args.per - file:
        live_context = Live(generate_display(0, 0, 0, set(), Counter(), Counter()), refresh_per_second=4,
                            transient=True)
        live_context.start()

    last_update_time = time.perf_counter()

    for path in args.path:
        if args.live and args.per - file:
            live_context = Live(generate_display(0, 0, 0, set(), Counter(), Counter(), filename=path),
                                refresh_per_second=4,
                                transient=True)
            live_context.start()

        with open(path, 'r', encoding='utf-8') as file:
            path_total_logs = 0
            path_requests = 0
            path_errors = 0
            path_endpoint = Counter()
            path_unique_ips = set()
            path_time_distribution = Counter()

            for line in file:
                path_total_logs += 1
                log_match = pattern.search(line.strip())
                if log_match:
                    path_requests += 1
                    current_path = log_match.group("Path")
                    path_endpoint[current_path] += 1
                    path_unique_ips.add(log_match.group("ip"))

                    log_date = log_match.group("date")
                    log_hour = log_match.group("time").split(":")[0]
                    time_key = f"{log_date} {log_hour}"
                    path_time_distribution[time_key] += 1

                    code = int(log_match.group("Code"))
                    if 400 <= code < 600:
                        path_errors += 1

                if args.live:
                    current_time = time.perf_counter()
                    if current_time - last_update_time >= 1.0:
                        if args.per - file:
                            live_context.update(
                                generate_display(path_requests, path_total_logs, path_errors, path_unique_ips,
                                                 path_endpoint, path_time_distribution, filename=path))
                        else:
                            show_req = total_requests + path_requests
                            show_logs = total_logs + path_total_logs
                            show_err = total_errors + path_errors
                            show_ips = global_unique_ips.union(path_unique_ips)
                            show_endpoints = global_endpoint_counter + path_endpoint
                            show_time_dist = global_time_distribution + path_time_distribution
                            live_context.update(
                                generate_display(show_req, show_logs, show_err, show_ips, show_endpoints,
                                                 show_time_dist))
                        last_update_time = current_time

            total_logs += path_total_logs
            total_requests += path_requests
            total_errors += path_errors
            global_unique_ips.update(path_unique_ips)
            global_endpoint_counter.update(path_endpoint)
            global_time_distribution.update(path_time_distribution)

            if args.live and args.per - file:
                if live_context:
                    live_context.stop()
                    live_context = None

            path_err_rate = ((path_errors / path_requests) * 100) if path_requests else 0.0

            if args.per_file:
                print(f"================================\n"
                      f"Results for {path}:\n"
                      f"accepted logs: {path_requests}/{path_total_logs}\n"
                      f"error rate: {path_err_rate:.2f}%\n"
                      f"unique IP = {len(path_unique_ips)}\n"
                      f"most 10 URL:")
                for i, (url, count) in enumerate(path_endpoint.most_common(10), 1):
                    print(f"{i:02d}. \"{url}\" : {count}")
                print("\nHourly Traffic Distribution:")
                for timestamp, traffic in sorted(path_time_distribution.items()):
                    print(f"  {timestamp}:00 -> Traffic: {traffic}")
                print("================================")

            if args.output and args.per - file and per_file_first:
                input_file_path = Path(path)
                per_file_output_name = f"{input_file_path.stem}_output.json"
                per_file_output_path = input_file_path.parent / per_file_output_name

                file_json_data = {
                    "file_name": str(input_file_path),
                    "accepted_logs": path_requests,
                    "total_logs": path_total_logs,
                    "error_rate": round(path_err_rate, 4),
                    "unique_ips_count": len(path_unique_ips),
                    "top_10_urls": dict(path_endpoint.most_common(10)),
                    "hourly_traffic_distribution": {f"{k}:00": v for k, v in sorted(path_time_distribution.items())}
                }
                with open(per_file_output_path, 'w', encoding='utf-8') as json_file:
                    json.dump(file_json_data, json_file, indent=4, ensure_ascii=False)

finally:
    if live_context:
        live_context.stop()

final_error_rate = ((total_errors / total_requests) * 100) if total_requests > 0 else 0.0

print(f"""
================================
FINAL REPORT (ALL FILES)
accepted logs: {total_requests}/{total_logs}
error rate: {final_error_rate:.4f}%
unique IP = {len(global_unique_ips)}
most 10 URL:""")
for i, (url, count) in enumerate(global_endpoint_counter.most_common(10), 1):
    print(f"{i:02d}. \"{url}\" : {count}")
print("\nHourly Traffic Distribution:")
for timestamp, traffic in sorted(global_time_distribution.items()):
    print(f"  {timestamp}:00 -> Traffic: {traffic}")
print("================================")
print(f"executiontime = {time.perf_counter() - start_time:.6f}s")

if args.output:
    final_json_data = {
        "report_type": "final_report",
        "accepted_logs": total_requests,
        "total_logs": total_logs,
        "error_rate": round(final_error_rate, 4),
        "unique_ips_count": len(global_unique_ips),
        "top_10_urls": dict(global_endpoint_counter.most_common(10)),
        "hourly_traffic_distribution": {f"{k}:00": v for k, v in sorted(global_time_distribution.items())},
        "execution_time_seconds": round(time.perf_counter() - start_time, 6)
    }

    if args.per_file and not per_file_first:
        final_json_data["report_type"] = "final_report_only_due_to_priority"

    with open(args.output, 'w', encoding='utf-8') as json_file:
        json.dump(final_json_data, json_file, indent=4, ensure_ascii=False)