import csv
import time
import json
import argparse
import requests
from urllib.parse import urlencode
from bs4 import BeautifulSoup

TARGETS = {
    "baseline": "http://waf-lab.local:8081/DVWA",
    "modsec": "http://waf-lab.local/DVWA",
    "coraza": "http://waf-lab.local:8080/DVWA",
}

BLOCK_CODES = {403, 406, 501}
REDIRECT_CODES = {301, 302, 303, 307, 308}


def classify_status(status_code):
    if status_code in BLOCK_CODES:
        return "clean_block"
    if 200 <= status_code <= 299:
        return "allowed"
    if status_code in REDIRECT_CODES:
        return "redirected"
    if 400 <= status_code <= 499:
        return "client_error"
    if status_code >= 500:
        return "server_error"
    return "unknown"


def extract_token(html):
    soup = BeautifulSoup(html, "html.parser")
    token = soup.find("input", {"name": "user_token"})
    if token and token.has_attr("value"):
        return token["value"]
    return None


def login(session, base_url):
    login_page = session.get(f"{base_url}/login.php", timeout=10)
    token = extract_token(login_page.text)

    data = {
        "username": "admin",
        "password": "password",
        "Login": "Login",
    }

    if token:
        data["user_token"] = token

    response = session.post(
        f"{base_url}/login.php",
        data=data,
        allow_redirects=True,
        timeout=10,
    )

    logged_in = (
        "logout" in response.text.lower()
        or "dvwa security" in response.text.lower()
        or "welcome" in response.text.lower()
    )

    return logged_in, response.status_code


def set_security_low(session, base_url):
    security_page = session.get(f"{base_url}/security.php", timeout=10)
    token = extract_token(security_page.text)

    data = {
        "security": "low",
        "seclev_submit": "Submit",
    }

    if token:
        data["user_token"] = token

    response = session.post(
        f"{base_url}/security.php",
        data=data,
        allow_redirects=True,
        timeout=10,
    )

    return response.status_code


def detect_response_markers(response_text):
    text = response_text.lower()

    return {
        "contains_forbidden": int("forbidden" in text),
        "contains_sql_error": int(
            ("sql" in text and "error" in text)
            or "syntax" in text
            or "mysql" in text
            or "mariadb" in text
        ),
        "contains_dvwa_result": int(
            "first name" in text
            or "surname" in text
            or "id:" in text
        ),
        "contains_login": int("login" in text and "username" in text),
    }


def run_transport_test(session, env, base_url, row):
    endpoint = row["dvwa_endpoint"]
    param = row["param"]
    payload = row["payload"]
    transport = row["transport"]
    content_type = row["content_type"]
    method = row["method"].upper()

    base_endpoint_url = f"{base_url}{endpoint}"

    headers = {
        "User-Agent": f"WAF-SQLi-Transport-Test/{env}",
        "X-WAF-Test-Type": "manual_sqli_transport",
        "X-WAF-Attack-Type": row["attack_type"],
        "X-WAF-Attack-Subtype": row["attack_subtype"],
        "X-WAF-Transport": transport,
        "X-WAF-Evasion-Type": row["evasion_type"],
        "X-WAF-Test-ID": row["test_id"],
    }

    cookies = {}

    start = time.time()

    try:
        if transport == "get_param":
            query = {param: payload, "Submit": "Submit"}
            url = f"{base_endpoint_url}?{urlencode(query)}"
            response = session.get(
                url,
                headers=headers,
                allow_redirects=False,
                timeout=15,
            )

        elif transport == "post_form":
            url = base_endpoint_url
            data = {param: payload, "Submit": "Submit"}
            response = session.post(
                url,
                data=data,
                headers=headers,
                allow_redirects=False,
                timeout=15,
            )

        elif transport == "json_body":
            url = base_endpoint_url
            headers["Content-Type"] = "application/json"
            body = {param: payload, "Submit": "Submit"}
            response = session.post(
                url,
                data=json.dumps(body),
                headers=headers,
                allow_redirects=False,
                timeout=15,
            )

        elif transport == "header":
            query = {param: "1", "Submit": "Submit"}
            url = f"{base_endpoint_url}?{urlencode(query)}"
            headers["X-Manual-SQLi-Payload"] = payload
            response = session.get(
                url,
                headers=headers,
                allow_redirects=False,
                timeout=15,
            )

        elif transport == "cookie":
            query = {param: "1", "Submit": "Submit"}
            url = f"{base_endpoint_url}?{urlencode(query)}"
            cookies["manual_sqli_payload"] = payload
            response = session.get(
                url,
                headers=headers,
                cookies=cookies,
                allow_redirects=False,
                timeout=15,
            )

        else:
            raise ValueError(f"Unsupported transport: {transport}")

        elapsed_ms = round((time.time() - start) * 1000, 2)
        result = classify_status(response.status_code)
        markers = detect_response_markers(response.text)

        return {
            **row,
            "environment": env,
            "base_url": base_url,
            "full_url": url,
            "status_code": response.status_code,
            "result": result,
            "blocked_flag": 1 if result == "clean_block" else 0,
            "allowed_flag": 1 if result == "allowed" else 0,
            "redirect_flag": 1 if result == "redirected" else 0,
            "client_error_flag": 1 if result == "client_error" else 0,
            "server_error_flag": 1 if result == "server_error" else 0,
            "timeout_flag": 0,
            "response_time_ms": elapsed_ms,
            **markers,
            "response_snippet": response.text.replace("\n", " ").replace("\r", " ")[:300],
        }

    except requests.exceptions.Timeout:
        return {
            **row,
            "environment": env,
            "base_url": base_url,
            "full_url": base_endpoint_url,
            "status_code": 0,
            "result": "timeout",
            "blocked_flag": 0,
            "allowed_flag": 0,
            "redirect_flag": 0,
            "client_error_flag": 0,
            "server_error_flag": 0,
            "timeout_flag": 1,
            "response_time_ms": 0,
            "contains_forbidden": 0,
            "contains_sql_error": 0,
            "contains_dvwa_result": 0,
            "contains_login": 0,
            "response_snippet": "timeout",
        }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--env", required=True, choices=TARGETS.keys())
    parser.add_argument(
        "--payloads",
        default="manual_tests/payloads/manual_sqli_transport_tests.csv",
    )
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    base_url = TARGETS[args.env]
    session = requests.Session()

    logged_in, login_code = login(session, base_url)
    print(f"Login status for {args.env}: {login_code}, logged_in={logged_in}")

    sec_code = set_security_low(session, base_url)
    print(f"Set DVWA security low: HTTP {sec_code}")

    results = []

    with open(args.payloads, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)

        for row in reader:
            print(
                f"Testing {args.env}: "
                f"{row['test_id']} | "
                f"{row['transport']} | "
                f"{row['evasion_type']}"
            )
            results.append(run_transport_test(session, args.env, base_url, row))

    if not results:
        print("No results generated.")
        return

    with open(args.output, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(results[0].keys()))
        writer.writeheader()
        writer.writerows(results)

    print(f"Written: {args.output}")


if __name__ == "__main__":
    main()
