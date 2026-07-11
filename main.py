import re
import time

live_log = True
path = 'access.log'
start_time = time.perf_counter()

pattern = re.compile(
    r"^(?P<ip>\d+\.\d+\.\d+\.\d+)\s+-(?P<username>.*)-\s+\[(?P<timeanddate>(?P<date>\d{2}\/\w{3}\/\d{4}):(?P<time>\d{2}:\d{2}:\d{2})\s(?P<GMT>(\+|\-)\d{4})])\s+\"((?P<method>\w+) (?P<Path>\/\S*) (?P<Protocol>\S*))\"\s+(?P<Code>\d+)\s+(?P<Size>\d+)\s+\"(?P<Referrer>.*)\"\s+\"(?P<UserAgent>.*)\"$")

total_logs = 0
accepted_logs = 0

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

end_time = time.perf_counter()
execution_time = end_time - start_time
print(f"executiontime = {execution_time:.6f}s")

a = input("Press enter to exit...")