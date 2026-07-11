import re
import time
import argparse

# from config_manager import load_app_settings , save_app_settings

parser = argparse.ArgumentParser(description="A tool for log analysis.")
parser.add_argument("path", nargs="?", default="access.log", help="Path to the log file")
parser.add_argument("--live", action="store_true", help="Enable live log monitoring")

start_time = time.perf_counter()
path , live_log =
pattern = re.compile(
    r"^(?P<ip>\d+\.\d+\.\d+\.\d+)\s+-(?P<username>.*)-\s+\[(?P<timeanddate>(?P<date>\d{2}\/\w{3}\/\d{4}):"
    r"(?P<time>\d{2}:\d{2}:\d{2})\s(?P<GMT>(\+|\-)\d{4})])\s+\"((?P<method>\w+) (?P<Path>\/\S*) "
    r"(?P<Protocol>\S*))\"\s+(?P<Code>\d+)\s+(?P<Size>\d+)\s+\"(?P<Referrer>.*)\"\s+\"(?P<UserAgent>.*)\"$")

total_logs = 0
accepted_logs = 0

while menu_index != 0:
    print(f"""
    default path:{path}
    live analyzer = {live_log}
    """)
    command = input()

    if menu_index == 1:
        with open(path, 'r', encoding='utf-8') as file:
            for line in file:
                total_logs += 1
                log_match = pattern.search(line.strip())
                if log_match:
                    accepted_logs += 1
                print(f"{total_logs}", end="\r")
    elif menu_index == 2:

    elif menu_index == 3:


    print(f"""
    ================================
              \tFinished
              \taccepted logs: {accepted_logs}/{total_logs}
    ================================""")

    end_time = time.perf_counter()
    execution_time = end_time - start_time
    print(f"executiontime = {execution_time:.6f}s")

    a = input("Press enter to exit...")