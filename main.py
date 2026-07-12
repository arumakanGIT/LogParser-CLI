import re
from collections import Counter
import sys
from sys import exit
import time
import argparse
from pathlib import Path
import json
import gzip
import heapq

pattern = re.compile(
    r"^(?P<ip>\d+\.\d+\.\d+\.\d+)\s+-(?P<username>.*)-\s+\[(?P<timeanddate>(?P<date>\d{2}\/\w{3}\/\d{4}):"
    r"(?P<time>\d{2}:\d{2}:\d{2})\s(?P<GMT>(\+|\-)\d{4})])\s+\"((?P<method>\w+) (?P<Path>\/\S*) "
    r"(?P<Protocol>\S*))\"\s+(?P<Code>\d+)\s+(?P<Size>\d+)\s+\"(?P<Referrer>.*)\"\s+\"(?P<UserAgent>.*)\"$")

months_map = {
    'Jan': '01', 'Feb': '02', 'Mar': '03', 'Apr': '04', 'May': '05', 'Jun': '06',
    'Jul': '07', 'Aug': '08', 'Sep': '09', 'Oct': '10', 'Nov': '11', 'Dec': '12'
}


def parse_to_sortable_string(dt_str):
    parts = dt_str.split('/')
    if len(parts) < 3:
        return ""
    day = parts[0]
    month = months_map.get(parts[1], "00")
    year_time = parts[2].split(':')
    if len(year_time) < 4:
        return ""
    year = year_time[0]
    hour = year_time[1]
    minute = year_time[2]
    second = year_time[3]
    return f"{year}{month}{day}{hour}{minute}{second}"


total_logs = 0
total_requests = 0
start_time = time.perf_counter()
path_input_arg_error = False

parser = argparse.ArgumentParser(description="A tool for log analysis.")
parser.add_argument("path", nargs="+", help="Path to the log file (supports .gz)")
parser.add_argument("--live", "-l", action="store_true", help="Enable live log monitoring")
parser.add_argument("--output", "-o", type=str, help="Save the logs to a JSON file path")
parser.add_argument("--per-file", action="store_true",
                    help="Show separate analytical reports for each individual log file")
parser.add_argument("--hourly", "-hr", action="store_true", help="Enable hourly traffic distribution analysis")
parser.add_argument("--time-range", nargs=2, metavar=('START', 'END'),
                    help="Time range filter e.g., '11/Jul/2026:10:00:00' '11/Jul/2026:12:00:00'")
parser.add_argument("--top", nargs=2, metavar=('N', 'FIELD'), help="Get top N logs. Fields: code, hours, ip, size")
args = parser.parse_args()

for path in args.path:
    file_path = Path(path)
    if not file_path.exists() or not file_path.is_file():
        print(f"Error: The path '{path}' is invalid.")
        path_input_arg_error = True
if path_input_arg_error:
    exit(1)

time_filter_active = False
start_ts = ""
end_ts = ""
if args.time_range:
    start_ts = parse_to_sortable_string(args.time_range[0])
    end_ts = parse_to_sortable_string(args.time_range[1])
    if start_ts and end_ts:
        time_filter_active = True
    else:
        print("Error: Invalid time range format.")
        exit(1)

top_n_active = False
top_n = 0
top_field = ""
if args.top:
    try:
        top_n = int(args.top[0])
        top_field = args.top[1].lower()
        if top_field not in ['code', 'hours', 'ip', 'size']:
            raise ValueError
        top_n_active = True
    except ValueError:
        print("Error: Invalid top parameters.")
        exit(1)

global_endpoint_counter = Counter()
global_unique_ips = set()
global_time_distribution = Counter()
total_errors = 0

suspicious_401 = Counter()
suspicious_404 = Counter()
spike_window_reqs = Counter()
spike_window_5xx = Counter()

top_sizes = []
top_aggregates = Counter()
top_samples = {}


def open_log_file(path_str):
    if str(path_str).endswith('.gz'):
        return gzip.open(path_str, 'rt', encoding='utf-8')
    return open(path_str, 'r', encoding='utf-8')


for path in args.path:
    with open_log_file(path) as file:
        path_total_logs = 0
        path_requests = 0
        path_errors = 0
        path_endpoint = Counter()
        path_unique_ips = set()
        path_time_distribution = Counter()

        for line in file:
            path_total_logs += 1
            line_str = line.strip()

            if time_filter_active:
                open_bracket_idx = line_str.find('[')
                close_bracket_idx = line_str.find(']')
                if open_bracket_idx == -1 or close_bracket_idx == -1:
                    continue
                time_part = line_str[open_bracket_idx + 1:close_bracket_idx].split(' ')[0]
                current_ts = parse_to_sortable_string(time_part)

                if current_ts > end_ts:
                    break
                if current_ts < start_ts:
                    continue

            log_match = pattern.search(line_str)
            if not log_match:
                continue

            path_requests += 1
            ip = log_match.group("ip")
            code = int(log_match.group("Code"))
            url_path = log_match.group("Path")
            log_date = log_match.group("date")
            log_time = log_match.group("time")

            if top_n_active:
                if top_field == 'size':
                    size_val = int(log_match.group("Size"))
                    if len(top_sizes) < top_n:
                        heapq.heappush(top_sizes, (size_val, line_str))
                    elif size_val > top_sizes[0][0]:
                        heapq.heappushpop(top_sizes, (size_val, line_str))
                else:
                    key = ""
                    if top_field == 'code':
                        key = str(code)
                    elif top_field == 'hours':
                        key = f"{log_date} {log_time.split(':')[0]}"
                    elif top_field == 'ip':
                        key = ip

                    top_aggregates[key] += 1
                    if key not in top_samples:
                        top_samples[key] = line_str
                continue

            path_endpoint[url_path] += 1
            path_unique_ips.add(ip)

            hour_key = f"{log_date} {log_time.split(':')[0]}"
            path_time_distribution[hour_key] += 1

            if 400 <= code < 600:
                path_errors += 1

            minute_window = f"{log_date} {log_time[:5]}"
            spike_window_reqs[minute_window] += 1
            if 500 <= code < 600:
                spike_window_5xx[minute_window] += 1

            if code == 401 and 'login' in url_path.lower():
                suspicious_401[ip] += 1
            elif code == 404:
                suspicious_404[ip] += 1

        total_logs += path_total_logs
        total_requests += path_requests
        total_errors += path_errors

        if not top_n_active:
            global_unique_ips.update(path_unique_ips)
            global_endpoint_counter.update(path_endpoint)
            global_time_distribution.update(path_time_distribution)

if top_n_active:
    print(f"\n=== TOP {top_n} {top_field.upper()} REPORT ===")
    if top_field == 'size':
        sorted_sizes = sorted(top_sizes, key=lambda x: x[0], reverse=True)
        for i, (size, raw_line) in enumerate(sorted_sizes, 1):
            print(f"\n{i}. Size: {size} bytes\nRaw Log: {raw_line}")
    else:
        top_n_heap = heapq.nlargest(top_n, top_aggregates.items(), key=lambda x: x[1])
        for i, (key, count) in enumerate(top_n_heap, 1):
            print(f"\n{i}. {top_field.capitalize()}: {key} | Occurrences: {count}\nSample Raw Log: {top_samples[key]}")
    print("\n" + "=" * 32)
    exit(0)

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

if args.hourly:
    print("\nHourly Traffic Distribution:")
    for timestamp, traffic in sorted(global_time_distribution.items()):
        print(f"  {timestamp}:00 -> Traffic: {traffic}")

    if global_time_distribution:
        peak_hour = max(global_time_distribution, key=global_time_distribution.get)
        valley_hour = min(global_time_distribution, key=global_time_distribution.get)
        print(f"\n[!] Peak Traffic:   {peak_hour}:00 ({global_time_distribution[peak_hour]} requests)")
        print(f"[!] Lowest Traffic: {valley_hour}:00 ({global_time_distribution[valley_hour]} requests)")

print("\n--- Security & Anomaly Report ---")
anomalies_found = False

for ip, count in suspicious_401.items():
    if count > 20:
        print(f"[ALERT] Suspicious IP: {ip} | {count} failed /login attempts (Possible Brute-force)")
        anomalies_found = True

for ip, count in suspicious_404.items():
    if count > 50:
        print(f"[ALERT] Suspicious IP: {ip} | {count} Not Found errors (Possible Directory Scanning)")
        anomalies_found = True

for window, req_count in spike_window_reqs.items():
    if req_count > 50:
        err_5xx = spike_window_5xx.get(window, 0)
        spike_rate = (err_5xx / req_count) * 100
        if spike_rate > 10.0:
            print(f"[ALERT] 5xx Error Spike: {window} | Rate: {spike_rate:.1f}% ({err_5xx}/{req_count} requests)")
            anomalies_found = True

if not anomalies_found:
    print("No significant anomalies or security threats detected.")

print("================================")
print(f"executiontime = {time.perf_counter() - start_time:.6f}s")