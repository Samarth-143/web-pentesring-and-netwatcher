import subprocess
import time

p = subprocess.Popen(["python", "traffic_daemon_test.py"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
time.sleep(2)
p.terminate()
out, err = p.communicate()
print("STDOUT:", out)
print("STDERR:", err)
