import os
import sys

# Remove the admin check lines from traffic_daemon.py for testing
with open('traffic_daemon.py', 'r') as f:
    lines = f.readlines()

new_lines = []
skip = False
for line in lines:
    if line.strip() == "if os.name == 'nt':":
        skip = True
    if skip and line.strip() == "sys.exit(0)":
        skip = False
        continue
    if not skip:
        new_lines.append(line)

with open('traffic_daemon_test.py', 'w') as f:
    f.writelines(new_lines)
