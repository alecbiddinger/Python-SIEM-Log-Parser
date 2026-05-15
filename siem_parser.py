import re
from collections import defaultdict

LOG_FILE = "logs/auth.log"
ALERT_FILE = "alerts.txt"

FAILED_LOGIN_THRESHOLD = 3

failed_logins = defaultdict(int)
alerts = []

failed_pattern = r"Failed password .* from (\d+\.\d+\.\d+\.\d+)"
success_pattern = r"Accepted password.*for (\w+) from (\d+\.\d+\.\d+\.\d+)"

with open(LOG_FILE, "r") as file:
    for line in file:
        failed_match = re.search(failed_pattern, line)
        success_match = re.search(success_pattern, line)

        if failed_match:
            ip_address = failed_match.group(1)
            failed_logins[ip_address] += 1
            if failed_logins[ip_address] == FAILED_LOGIN_THRESHOLD:
                alerts.append(f"[ALERT] Possible brute force attack detected from IP: {ip_address}")

        if success_match:
            username = success_match.group(1)
            ip_address = success_match.group(2)
            if failed_logins[ip_address] >= FAILED_LOGIN_THRESHOLD:
                alerts.append(f"[ALERT] Successful login after multiple failures: user={username}, ip={ip_address}")

with open(ALERT_FILE, "w") as file:
    if alerts:
        for alert in alerts:
            file.write(alert + "\n")
    else:
        file.write("No suspicious activity detected.\n")

print("SIEM log analysis complete.")
print(f"Alerts written to {ALERT_FILE}")
